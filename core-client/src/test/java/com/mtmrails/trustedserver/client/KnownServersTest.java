package com.mtmrails.trustedserver.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KnownServersTest {
    @TempDir
    Path dir;

    private static byte[] key(int b) {
        byte[] k = new byte[32];
        k[0] = (byte) b;
        return k;
    }

    @Test
    void pinsPersistAndAreCaseInsensitive() throws Exception {
        Path file = dir.resolve("trustedserver/known_servers.txt");
        KnownServers known = new KnownServers(file);
        assertTrue(known.get("mc.example.com").isEmpty());
        known.put("MC.Example.com:25565", key(1));
        known.put("other.example", key(2));
        KnownServers reopened = new KnownServers(file);
        assertArrayEquals(key(1), reopened.get("mc.example.com:25565").orElseThrow());
        assertArrayEquals(key(2), reopened.get(" OTHER.example ").orElseThrow());
        reopened.put("other.example", key(3));
        assertArrayEquals(key(3), new KnownServers(file).get("other.example").orElseThrow());
    }

    @Test
    void corruptedFileIsNotSilentlyDiscarded() throws Exception {
        Path file = dir.resolve("known_servers.txt");
        Files.writeString(file, "mc.example.com nothex\n");
        KnownServers known = new KnownServers(file);
        assertThrows(IOException.class, () -> known.get("mc.example.com"));
        assertThrows(IOException.class, () -> known.put("x", key(1)));
    }

    @Test
    void invalidInputs() {
        KnownServers known = new KnownServers(dir.resolve("k.txt"));
        assertThrows(IllegalArgumentException.class, () -> known.put("a b", key(1)));
        assertThrows(IllegalArgumentException.class, () -> known.put("", key(1)));
        assertThrows(IllegalArgumentException.class, () -> known.put("a", new byte[31]));
    }
}
