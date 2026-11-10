package com.mtmrails.trustedserver.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.mtmrails.trustedserver.core.crypto.Ed25519;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PlayerKeyBackupManagerTest {
    @TempDir
    Path dir;

    @Test
    void previewDoesNotWriteAndConflictNeedsExplicitOverwrite() throws Exception {
        SecureRandom random = new SecureRandom();
        PlayerKeyStore sourceStore = new PlayerKeyStore(dir.resolve("source"));
        StoredKey source = new StoredKey(PlayerKeyStoreTest.target("Steve"), Ed25519.generate(random));
        sourceStore.importKey(source, false);
        PlayerKeyBackupManager sourceManager = new PlayerKeyBackupManager(sourceStore, random);
        Path backup = dir.resolve("keys.tskb");
        sourceManager.export(backup, sourceManager.list(), Optional.of("backup password"));

        PlayerKeyStore targetStore = new PlayerKeyStore(dir.resolve("target"));
        targetStore.getOrCreate(source.target(), random);
        PlayerKeyBackupManager targetManager = new PlayerKeyBackupManager(targetStore, random);
        PlayerKeyBackupManager.ImportPreview preview = targetManager.preview(backup, Optional.of("backup password"));
        assertEquals(1, preview.conflicts());
        assertFalse(preview.entries().isEmpty());

        assertEquals(new PlayerKeyBackupManager.ImportResult(0, 0, 0, 1), targetManager.apply(preview, false));
        assertEquals(new PlayerKeyBackupManager.ImportResult(0, 0, 1, 0), targetManager.apply(preview, true));
        PlayerKeyBackupManager.ImportPreview after = targetManager.preview(backup, Optional.of("backup password"));
        assertEquals(PlayerKeyBackupManager.Disposition.IDENTICAL, after.entries().get(0).disposition());
    }

    @Test
    void exportsOnlySelectedKeys() throws Exception {
        SecureRandom random = new SecureRandom();
        PlayerKeyStore store = new PlayerKeyStore(dir.resolve("keys"));
        store.getOrCreate(PlayerKeyStoreTest.target("Steve"), random);
        store.getOrCreate(PlayerKeyStoreTest.target("Alex"), random);
        PlayerKeyBackupManager manager = new PlayerKeyBackupManager(store, random);
        List<StoredKey> selected = manager.list().stream()
                .filter(k -> k.target().username().equals("Alex")).toList();
        Path backup = dir.resolve("selected.tskb");
        manager.export(backup, selected, Optional.empty());

        PlayerKeyBackupManager.ImportPreview preview = new PlayerKeyBackupManager(
                new PlayerKeyStore(dir.resolve("empty")), random).preview(backup, Optional.empty());
        assertEquals(List.of("Alex"), preview.entries().stream().map(e -> e.key().target().username()).toList());
    }
}
