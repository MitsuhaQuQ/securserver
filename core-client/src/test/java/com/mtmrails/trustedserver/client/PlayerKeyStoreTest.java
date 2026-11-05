package com.mtmrails.trustedserver.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mtmrails.trustedserver.core.crypto.Ed25519;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PlayerKeyStoreTest {
    private static final SecureRandom RANDOM = new SecureRandom();

    @TempDir
    Path dir;

    static KeyTarget target(String username) {
        byte[] server = new byte[32];
        server[0] = 7;
        return new KeyTarget(server, username);
    }

    @Test
    void createsOnceAndPersists() throws Exception {
        PlayerKeyStore store = new PlayerKeyStore(dir);
        assertTrue(store.find(target("Steve")).isEmpty());
        Ed25519.KeyPairData created = store.getOrCreate(target("Steve"), RANDOM);
        assertArrayEquals(created.publicKey(), store.getOrCreate(target("Steve"), RANDOM).publicKey());

        PlayerKeyStore reopened = new PlayerKeyStore(dir);
        Ed25519.KeyPairData loaded = reopened.find(target("Steve")).orElseThrow().key();
        assertArrayEquals(created.publicKey(), loaded.publicKey());
        assertArrayEquals(created.seed(), loaded.seed());
    }

    @Test
    void usernamesAreCaseSensitiveAndFileNamesAreSafe() throws Exception {
        PlayerKeyStore store = new PlayerKeyStore(dir);
        Ed25519.KeyPairData upper = store.getOrCreate(target("Steve"), RANDOM);
        Ed25519.KeyPairData lower = store.getOrCreate(target("steve"), RANDOM);
        Ed25519.KeyPairData odd = store.getOrCreate(target("../../etc/passwd 名字"), RANDOM);
        assertFalse(java.util.Arrays.equals(upper.publicKey(), lower.publicKey()));
        assertEquals(3, store.list().size());
        try (var files = Files.list(dir)) {
            assertTrue(files.allMatch(f -> f.getFileName().toString().matches("[0-9a-f]{64}\\.key")));
        }
        assertArrayEquals(odd.publicKey(), store.find(target("../../etc/passwd 名字")).orElseThrow().key().publicKey());
    }

    @Test
    void listIsSorted() throws Exception {
        PlayerKeyStore store = new PlayerKeyStore(dir);
        store.getOrCreate(target("b"), RANDOM);
        store.getOrCreate(target("a"), RANDOM);
        assertEquals(List.of("a", "b"), store.list().stream().map(k -> k.target().username()).toList());
        assertTrue(new PlayerKeyStore(dir.resolve("missing")).list().isEmpty());
    }

    @Test
    void importNeverSilentlyOverwrites() throws Exception {
        PlayerKeyStore store = new PlayerKeyStore(dir);
        StoredKey incoming = new StoredKey(target("Steve"), Ed25519.generate(RANDOM));
        assertEquals(PlayerKeyStore.ImportStatus.ADDED, store.importKey(incoming, false));
        assertEquals(PlayerKeyStore.ImportStatus.IDENTICAL, store.importKey(incoming, false));

        StoredKey different = new StoredKey(target("Steve"), Ed25519.generate(RANDOM));
        assertEquals(PlayerKeyStore.ImportStatus.CONFLICT, store.importKey(different, false));
        assertArrayEquals(incoming.key().publicKey(), store.find(target("Steve")).orElseThrow().key().publicKey());

        assertEquals(PlayerKeyStore.ImportStatus.REPLACED, store.importKey(different, true));
        assertArrayEquals(different.key().publicKey(), store.find(target("Steve")).orElseThrow().key().publicKey());
    }

    @Test
    void corruptedFileIsNeverRegenerated() throws Exception {
        PlayerKeyStore store = new PlayerKeyStore(dir);
        store.getOrCreate(target("Steve"), RANDOM);
        Path file = store.fileFor(target("Steve"));
        byte[] content = Files.readAllBytes(file);
        content[10] ^= 1;
        Files.write(file, content);
        assertThrows(IOException.class, () -> store.find(target("Steve")));
        assertThrows(IOException.class, () -> store.getOrCreate(target("Steve"), RANDOM));
        assertThrows(IOException.class, store::list);
    }

    @Test
    void truncatedFileIsRejected() throws Exception {
        PlayerKeyStore store = new PlayerKeyStore(dir);
        store.getOrCreate(target("Steve"), RANDOM);
        Path file = store.fileFor(target("Steve"));
        byte[] content = Files.readAllBytes(file);
        for (int length = 0; length < content.length; length++) {
            Files.write(file, java.util.Arrays.copyOf(content, length));
            assertThrows(IOException.class, () -> store.find(target("Steve")), "length " + length);
        }
    }

    @Test
    void fileUnderWrongNameIsRejected() throws Exception {
        PlayerKeyStore store = new PlayerKeyStore(dir);
        store.getOrCreate(target("Steve"), RANDOM);
        Files.move(store.fileFor(target("Steve")), store.fileFor(target("Alex")));
        assertThrows(IOException.class, () -> store.find(target("Alex")));
        assertThrows(IOException.class, store::list);
    }

    @Test
    void keyFilesAreOwnerOnlyOnPosix() throws Exception {
        PlayerKeyStore store = new PlayerKeyStore(dir);
        store.getOrCreate(target("Steve"), RANDOM);
        Path file = store.fileFor(target("Steve"));
        if (Files.getFileStore(file).supportsFileAttributeView("posix")) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
        }
        try (var files = Files.list(dir)) {
            assertEquals(1, files.count()); // 没有遗留临时文件
        }
    }

    @Test
    void targetValidation() {
        assertThrows(IllegalArgumentException.class, () -> new KeyTarget(new byte[31], "Steve"));
        assertThrows(IllegalArgumentException.class, () -> new KeyTarget(new byte[32], ""));
        assertThrows(IllegalArgumentException.class, () -> new KeyTarget(new byte[32], "x".repeat(257)));
    }
}
