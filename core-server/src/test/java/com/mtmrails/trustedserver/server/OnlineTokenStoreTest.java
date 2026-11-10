package com.mtmrails.trustedserver.server;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class OnlineTokenStoreTest {
    @TempDir Path dir;

    @Test
    void persistsMultipleDevicesAndCapsOldEntries() throws Exception {
        Path file = dir.resolve("online_tokens.txt");
        UUID id = UUID.randomUUID();
        OnlineTokenStore store = new OnlineTokenStore(file);
        for (int i = 0; i < OnlineTokenStore.MAX_TOKENS_PER_PLAYER + 2; i++) {
            byte[] token = new byte[32];
            token[0] = (byte) i;
            store.add(id, "Player", token);
            Thread.sleep(1);
        }
        OnlineTokenStore reloaded = new OnlineTokenStore(file);
        assertEquals(OnlineTokenStore.MAX_TOKENS_PER_PLAYER, reloaded.tokens(id).size());
        assertArrayEquals(store.tokens(id).get(0), reloaded.tokens(id).get(0));
    }

    @Test
    void malformedFileIsNotSilentlyDiscarded() throws Exception {
        Path file = dir.resolve("online_tokens.txt");
        Files.writeString(file, "broken\n");
        assertThrows(IOException.class, () -> new OnlineTokenStore(file).tokens(UUID.randomUUID()));
    }

    @Test
    void onlineNameClaimBlocksAnotherUuidUntilExplicitlyCleared() throws Exception {
        OnlineTokenStore store = new OnlineTokenStore(dir.resolve("claims.txt"));
        UUID first = UUID.randomUUID();
        store.add(first, "Player", new byte[32]);
        assertTrue(store.isReservedName("player"));
        assertThrows(IOException.class, () -> store.add(UUID.randomUUID(), "PLAYER", new byte[32]));
        assertTrue(store.clearClaim("player"));
        store.add(UUID.randomUUID(), "PLAYER", new byte[32]);
    }
}
