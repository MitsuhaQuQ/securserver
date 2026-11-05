package com.mtmrails.trustedserver.client;

import com.mtmrails.trustedserver.core.crypto.Ed25519;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * 客户端玩家密钥存储（PROTOCOL.md 第 3 节）：每个“服务端身份公钥 + 用户名”一个文件，
 * 位于 {@code config/trustedserver/keys/}。
 *
 * <p>文件名为定位信息的 SHA-256 摘要，避免用户名中的特殊字符影响文件系统。文件格式：
 * {@code "TSPK" | u8 版本 | 密钥记录 | SHA-256 校验和}。按决策不考虑物理接触，私钥明文保存，
 * 支持 POSIX 权限的系统上设为仅本人可读写。
 *
 * <p>损坏的密钥文件会抛出 {@link IOException}，绝不静默重新生成：那样会导致与服务端绑定不一致。
 */
public final class PlayerKeyStore {
    private static final byte[] MAGIC = {'T', 'S', 'P', 'K'};
    private static final int VERSION = 1;
    private static final int CHECKSUM_LENGTH = 32;
    private static final String SUFFIX = ".key";

    /** 导入单条密钥的结果。 */
    public enum ImportStatus {
        /** 本机原本没有，已写入。 */
        ADDED,
        /** 本机已有相同的密钥，无需改动。 */
        IDENTICAL,
        /** 本机已有不同的密钥，未改动；须由玩家明确确认后以覆盖方式重新导入。 */
        CONFLICT,
        /** 玩家确认后，已用导入的密钥覆盖本机原有的不同密钥。 */
        REPLACED
    }

    private final Path directory;

    public PlayerKeyStore(Path directory) {
        this.directory = Objects.requireNonNull(directory, "directory");
    }

    public synchronized Optional<StoredKey> find(KeyTarget target) throws IOException {
        Path file = fileFor(target);
        if (!Files.exists(file)) {
            return Optional.empty();
        }
        StoredKey stored = readFile(file);
        if (!stored.target().equals(target)) {
            throw new IOException("key file " + file.getFileName() + " belongs to " + stored.target());
        }
        return Optional.of(stored);
    }

    /** 取出该定位的密钥；没有则生成新的并保存。 */
    public synchronized Ed25519.KeyPairData getOrCreate(KeyTarget target, SecureRandom random) throws IOException {
        Optional<StoredKey> existing = find(target);
        if (existing.isPresent()) {
            return existing.get().key();
        }
        Ed25519.KeyPairData key = Ed25519.generate(random);
        write(new StoredKey(target, key));
        return key;
    }

    /** 列出本机全部密钥（导出界面使用），按服务端指纹和用户名排序。 */
    public synchronized List<StoredKey> list() throws IOException {
        List<StoredKey> out = new ArrayList<>();
        if (!Files.isDirectory(directory)) {
            return out;
        }
        try (DirectoryStream<Path> files = Files.newDirectoryStream(directory, "*" + SUFFIX)) {
            for (Path file : files) {
                StoredKey stored = readFile(file);
                if (!file.equals(fileFor(stored.target()))) {
                    throw new IOException("key file " + file.getFileName() + " is stored under the wrong name");
                }
                out.add(stored);
            }
        }
        out.sort((a, b) -> {
            int c = a.target().serverFingerprint().compareTo(b.target().serverFingerprint());
            return c != 0 ? c : a.target().username().compareTo(b.target().username());
        });
        return out;
    }

    /**
     * 导入一条密钥。本机已有不同密钥时，只有 {@code overwrite} 为真才会覆盖（须先经玩家明确确认）。
     */
    public synchronized ImportStatus importKey(StoredKey stored, boolean overwrite) throws IOException {
        Optional<StoredKey> existing = find(stored.target());
        if (existing.isEmpty()) {
            write(stored);
            return ImportStatus.ADDED;
        }
        if (Arrays.equals(existing.get().key().publicKey(), stored.key().publicKey())) {
            return ImportStatus.IDENTICAL;
        }
        if (!overwrite) {
            return ImportStatus.CONFLICT;
        }
        write(stored);
        return ImportStatus.REPLACED;
    }

    Path fileFor(KeyTarget target) {
        MessageDigest sha256;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        sha256.update("tsrv key file".getBytes(StandardCharsets.US_ASCII));
        sha256.update(target.serverIdPub());
        sha256.update(new WireWriter().string(target.username(), KeyTarget.MAX_USERNAME_BYTES).toByteArray());
        return directory.resolve(HexFormat.of().formatHex(sha256.digest()) + SUFFIX);
    }

    private void write(StoredKey stored) throws IOException {
        WireWriter out = new WireWriter().fixed(MAGIC).u8(VERSION);
        KeyRecordCodec.write(out, stored);
        byte[] body = out.toByteArray();
        byte[] content = Arrays.copyOf(body, body.length + CHECKSUM_LENGTH);
        System.arraycopy(sha256(body), 0, content, body.length, CHECKSUM_LENGTH);

        Files.createDirectories(directory);
        Path target = fileFor(stored.target());
        Path temp = Files.createTempFile(directory, "key", ".tmp");
        try {
            restrictPermissions(temp);
            Files.write(temp, content);
            try {
                Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
            Arrays.fill(content, (byte) 0);
        }
    }

    private static StoredKey readFile(Path file) throws IOException {
        byte[] content = Files.readAllBytes(file);
        try {
            if (content.length < MAGIC.length + 1 + CHECKSUM_LENGTH) {
                throw new IOException("key file " + file.getFileName() + " is truncated");
            }
            byte[] body = Arrays.copyOf(content, content.length - CHECKSUM_LENGTH);
            byte[] checksum = Arrays.copyOfRange(content, body.length, content.length);
            if (!MessageDigest.isEqual(checksum, sha256(body))) {
                throw new IOException("key file " + file.getFileName() + " is corrupted (checksum mismatch)");
            }
            WireReader in = new WireReader(body);
            if (!Arrays.equals(in.fixed(MAGIC.length), MAGIC) || in.u8() != VERSION) {
                throw new IOException("key file " + file.getFileName() + " has an unknown format");
            }
            StoredKey stored = KeyRecordCodec.read(in);
            in.expectEnd();
            return stored;
        } catch (MalformedMessageException e) {
            throw new IOException("key file " + file.getFileName() + " is malformed: " + e.getMessage(), e);
        } finally {
            Arrays.fill(content, (byte) 0);
        }
    }

    private static void restrictPermissions(Path file) throws IOException {
        try {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException e) {
            // 非 POSIX 文件系统（如 Windows）：沿用用户目录的默认权限
        }
    }

    static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
