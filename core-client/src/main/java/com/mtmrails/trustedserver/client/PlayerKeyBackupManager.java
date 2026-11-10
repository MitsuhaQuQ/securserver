package com.mtmrails.trustedserver.client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/** 面向客户端界面的密钥备份文件读写、预检和显式冲突覆盖流程。 */
public final class PlayerKeyBackupManager {
    public enum Disposition {
        MISSING,
        IDENTICAL,
        CONFLICT
    }

    public record PreviewEntry(StoredKey key, Disposition disposition) {
        public PreviewEntry {
            Objects.requireNonNull(key, "key");
            Objects.requireNonNull(disposition, "disposition");
        }
    }

    public record ImportPreview(List<PreviewEntry> entries, boolean encrypted) {
        public ImportPreview {
            entries = List.copyOf(entries);
            if (entries.isEmpty()) throw new IllegalArgumentException("empty import preview");
        }

        public long conflicts() {
            return entries.stream().filter(e -> e.disposition() == Disposition.CONFLICT).count();
        }
    }

    public record ImportResult(int added, int identical, int replaced, int conflictsSkipped) {
    }

    private final PlayerKeyStore store;
    private final SecureRandom random;

    public PlayerKeyBackupManager(PlayerKeyStore store, SecureRandom random) {
        this.store = Objects.requireNonNull(store, "store");
        this.random = Objects.requireNonNull(random, "random");
    }

    public List<StoredKey> list() throws IOException {
        return store.list();
    }

    /** 原子写出所选密钥；空密码表示明文，由界面负责先显示警告。 */
    public void export(Path target, List<StoredKey> selected, Optional<String> password) throws IOException {
        Objects.requireNonNull(target, "target");
        byte[] content = PlayerKeyBackup.export(selected, password, random);
        Path absolute = target.toAbsolutePath();
        Path parent = absolute.getParent();
        Files.createDirectories(parent);
        Path temp = Files.createTempFile(parent, "trustedserver-backup", ".tmp");
        try {
            Files.write(temp, content);
            try {
                Files.move(temp, absolute, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, absolute, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Arrays.fill(content, (byte) 0);
            Files.deleteIfExists(temp);
        }
    }

    /** 只解析并比较，不修改本机密钥；冲突必须在之后的 apply 中明确选择是否覆盖。 */
    public ImportPreview preview(Path source, Optional<String> password) throws IOException, BackupException {
        byte[] file;
        try (InputStream input = Files.newInputStream(source)) {
            file = input.readNBytes(PlayerKeyBackup.MAX_FILE_SIZE + 1);
        }
        try {
            if (file.length > PlayerKeyBackup.MAX_FILE_SIZE) {
                throw new BackupException(BackupException.Kind.UNSUPPORTED_FORMAT,
                        "file is too large to be a key backup");
            }
            boolean encrypted = PlayerKeyBackup.isEncrypted(file);
            List<PreviewEntry> entries = new ArrayList<>();
            for (StoredKey incoming : PlayerKeyBackup.read(file, password)) {
                Optional<StoredKey> local = store.find(incoming.target());
                Disposition disposition = local.isEmpty() ? Disposition.MISSING
                        : Arrays.equals(local.orElseThrow().key().publicKey(), incoming.key().publicKey())
                                ? Disposition.IDENTICAL : Disposition.CONFLICT;
                entries.add(new PreviewEntry(incoming, disposition));
            }
            return new ImportPreview(entries, encrypted);
        } finally {
            Arrays.fill(file, (byte) 0);
        }
    }

    public ImportResult apply(ImportPreview preview, boolean overwriteConflicts) throws IOException {
        int added = 0;
        int identical = 0;
        int replaced = 0;
        int skipped = 0;
        for (PreviewEntry entry : preview.entries()) {
            boolean overwrite = overwriteConflicts && entry.disposition() == Disposition.CONFLICT;
            PlayerKeyStore.ImportStatus status = store.importKey(entry.key(), overwrite);
            switch (status) {
                case ADDED -> added++;
                case IDENTICAL -> identical++;
                case REPLACED -> replaced++;
                case CONFLICT -> skipped++;
            }
        }
        return new ImportResult(added, identical, replaced, skipped);
    }
}
