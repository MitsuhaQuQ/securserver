package com.mtmrails.trustedserver.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PresharedKeyFileTest {
    @TempDir
    Path dir;

    @Test
    void createsAndReloadsSameKey() throws Exception {
        Path file = dir.resolve("config/trustedserver/psk.key");
        PresharedKeyFile.Loaded created = PresharedKeyFile.loadOrCreate(file, new SecureRandom());
        assertTrue(created.created());
        assertEquals(32, created.key().length);
        assertEquals(32, Base64.getDecoder().decode(Files.readString(file).trim()).length);

        PresharedKeyFile.Loaded loaded = PresharedKeyFile.loadOrCreate(file, new SecureRandom());
        assertFalse(loaded.created());
        assertArrayEquals(created.key(), loaded.key());
    }

    @Test
    void malformedExistingFileRefusesToStart() throws Exception {
        Path file = dir.resolve("psk.key");
        Files.writeString(file, "not-base64!\n");
        assertThrows(IOException.class, () -> PresharedKeyFile.loadOrCreate(file, new SecureRandom()));
        Files.writeString(file, Base64.getEncoder().encodeToString(new byte[31]) + "\n");
        assertThrows(IOException.class, () -> PresharedKeyFile.loadOrCreate(file, new SecureRandom()));
        Files.writeString(file, Base64.getEncoder().encodeToString(new byte[32]) + " extra\n");
        assertThrows(IOException.class, () -> PresharedKeyFile.loadOrCreate(file, new SecureRandom()));
    }

    @Test
    void returnedArraysAreDefensiveCopies() throws Exception {
        PresharedKeyFile.Loaded loaded = PresharedKeyFile.loadOrCreate(dir.resolve("psk.key"), new SecureRandom());
        byte first = loaded.key()[0];
        loaded.key()[0] ^= 1;
        assertEquals(first, loaded.key()[0]);
    }
}
