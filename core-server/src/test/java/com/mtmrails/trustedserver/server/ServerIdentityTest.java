package com.mtmrails.trustedserver.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ServerIdentityTest {
    @TempDir
    Path dir;

    @Test
    void createdOnceThenLoaded() throws Exception {
        Path file = dir.resolve("config/trustedserver/server_identity.key");
        ServerIdentity.Loaded created = ServerIdentity.loadOrCreate(file, new SecureRandom());
        assertTrue(created.created());
        ServerIdentity.Loaded loaded = ServerIdentity.loadOrCreate(file, new SecureRandom());
        assertFalse(loaded.created());
        assertArrayEquals(created.key().publicKey(), loaded.key().publicKey());
        assertEquals(64, loaded.fingerprint().length());
        if (Files.getFileStore(file).supportsFileAttributeView("posix")) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
        }
    }

    @Test
    void corruptedFileIsNeverReplaced() throws Exception {
        Path file = dir.resolve("server_identity.key");
        ServerIdentity.loadOrCreate(file, new SecureRandom());
        byte[] content = Files.readAllBytes(file);
        for (int i = 0; i < content.length; i++) {
            byte[] corrupted = content.clone();
            corrupted[i] ^= 1;
            Files.write(file, corrupted);
            assertThrows(IOException.class, () -> ServerIdentity.loadOrCreate(file, new SecureRandom()), "byte " + i);
            assertArrayEquals(corrupted, Files.readAllBytes(file)); // 原样保留，未被覆盖
        }
        Files.write(file, new byte[0]);
        assertThrows(IOException.class, () -> ServerIdentity.loadOrCreate(file, new SecureRandom()));
    }
}
