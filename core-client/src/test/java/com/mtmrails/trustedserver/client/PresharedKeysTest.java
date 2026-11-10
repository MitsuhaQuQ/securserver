package com.mtmrails.trustedserver.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PresharedKeysTest {
    @TempDir
    Path dir;

    @Test
    void loadsKeysByNormalizedServerAddress() throws Exception {
        byte[] key = key("address mapping");
        Path file = dir.resolve("psk.txt");
        Files.writeString(file, "# comment\nMC.Example.COM:25565 "
                + Base64.getEncoder().encodeToString(key) + "\n");
        PresharedKeys keys = new PresharedKeys(file);
        assertArrayEquals(key, keys.get(" mc.example.com:25565 ").orElseThrow());
        assertTrue(keys.get("other.example").isEmpty());
    }

    @Test
    void createsEditableTemplate() throws Exception {
        Path file = dir.resolve("trustedserver/psk.txt");
        PresharedKeys keys = new PresharedKeys(file);
        keys.createTemplateIfMissing();
        assertTrue(Files.readString(file).contains("server-address"));
        keys.createTemplateIfMissing();
    }

    @Test
    void rejectsMalformedShortAndDuplicateEntries() throws Exception {
        Path file = dir.resolve("psk.txt");
        PresharedKeys keys = new PresharedKeys(file);
        Files.writeString(file, "server not-base64!\n");
        assertThrows(IOException.class, () -> keys.get("server"));

        Files.writeString(file, "server " + Base64.getEncoder().encodeToString(new byte[31]) + "\n");
        assertThrows(IOException.class, () -> new PresharedKeys(file).get("server"));

        String encoded = Base64.getEncoder().encodeToString(key("duplicate detection"));
        Files.writeString(file, "server " + encoded + "\nSERVER " + encoded + "\n");
        assertThrows(IOException.class, () -> new PresharedKeys(file).get("server"));
    }

    @Test
    void savesPromptedKeyAndPreservesOtherServers() throws Exception {
        Path file = dir.resolve("trustedserver/psk.txt");
        PresharedKeys keys = new PresharedKeys(file);
        keys.createTemplateIfMissing();
        byte[] first = key("first server");
        byte[] second = key("second server");
        keys.put("One.Example:25565", first);
        keys.put("two.example", second);

        PresharedKeys reloaded = new PresharedKeys(file);
        assertArrayEquals(first, reloaded.get("one.example:25565").orElseThrow());
        assertArrayEquals(second, reloaded.get("two.example").orElseThrow());
        assertArrayEquals(first, PresharedKeys.decode(Base64.getEncoder().encodeToString(first)));
        assertThrows(IOException.class, () -> PresharedKeys.decode("4"));
    }

    private static byte[] key(String label) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(label.getBytes(StandardCharsets.UTF_8));
    }
}
