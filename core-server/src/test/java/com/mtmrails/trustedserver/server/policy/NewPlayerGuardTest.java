package com.mtmrails.trustedserver.server.policy;

import static com.mtmrails.trustedserver.server.policy.NewPlayerGuard.Verdict.ALLOW;
import static com.mtmrails.trustedserver.server.policy.NewPlayerGuard.Verdict.COOLDOWN;
import static com.mtmrails.trustedserver.server.policy.NewPlayerGuard.Verdict.START_COOLDOWN;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class NewPlayerGuardTest {
    private final NewPlayerGuard guard = new NewPlayerGuard(new NewPlayerGuard.Config(true, 30, 2, 10, 30));
    private final UUID player = UUID.randomUUID();

    @Test
    void blocksBurstAndRetainsCooldownAcrossCleanupAndReconnect() {
        assertEquals(ALLOW, guard.beforeBreak(player, 100, 0));
        assertEquals(ALLOW, guard.beforeBreak(player, 101, 1));
        assertEquals(START_COOLDOWN, guard.beforeBreak(player, 102, 2));
        guard.prune(10_000);
        assertEquals(COOLDOWN, guard.beforeBreak(player, 103, 29_999));
        assertEquals(ALLOW, guard.beforeBreak(UUID.randomUUID(), 103, 29_999));
        assertEquals(ALLOW, guard.beforeBreak(player, 103, 30_002));
    }

    @Test
    void expiresOldBreaksAndSkipsEstablishedPlayers() {
        assertEquals(ALLOW, guard.beforeBreak(player, 100, 0));
        assertEquals(ALLOW, guard.beforeBreak(player, 100, 1));
        assertEquals(ALLOW, guard.beforeBreak(player, 100, 10_000));
        for (int i = 0; i < 4; i++) {
            assertEquals(ALLOW, guard.beforeBreak(player, 36_000, 10_001));
        }
    }
}
