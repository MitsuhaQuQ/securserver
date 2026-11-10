package com.mtmrails.trustedserver.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class OnlineTokensTest {
    @TempDir Path dir;

    @Test
    void storesByServerIdentityAddressAndOnlineUuid() throws Exception {
        Path file = dir.resolve("online_tokens.txt");
        byte[] identity = new byte[32]; identity[0] = 1;
        byte[] token = new byte[32]; token[0] = 2;
        UUID id = UUID.randomUUID();
        OnlineTokens tokens = new OnlineTokens(file);
        tokens.put("MC.Example:25565", identity, id, "Player", token);
        assertArrayEquals(token, new OnlineTokens(file)
                .get("mc.example:25565", identity, id, "player").orElseThrow());
        identity[0] = 9;
        assertTrue(tokens.get("mc.example:25565", identity, id, "Player").isEmpty());
    }

    @Test
    void malformedFileIsRejected() throws Exception {
        Path file = dir.resolve("online_tokens.txt");
        Files.writeString(file, "broken\n");
        assertThrows(IOException.class, () -> new OnlineTokens(file)
                .get("server", new byte[32], UUID.randomUUID(), "Player"));
    }
}
