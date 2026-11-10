package com.mtmrails.trustedserver.server.status;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mtmrails.trustedserver.server.policy.TestClock;
import java.time.Duration;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.Test;

class StatusSanitizerTest {
    private final TestClock clock = new TestClock();

    private StatusSanitizer sanitizer(StatusConfig.PlayerCountMode mode, int fixed, int min, int max) {
        return new StatusSanitizer(new StatusConfig(StatusConfig.ProtectionMode.NORMAL, false, "decoy",
                mode, fixed, min, max, Duration.ofMinutes(5)), clock, new Random(1));
    }

    @Test
    void realCountIsShownByDefault() {
        StatusSanitizer s = new StatusSanitizer(StatusConfig.DEFAULT, clock, new Random());
        assertEquals(7, s.displayedOnline(7, 20));
    }

    @Test
    void fixedCountIsClampedToMax() {
        assertEquals(15, sanitizer(StatusConfig.PlayerCountMode.FIXED, 15, 0, 0).displayedOnline(3, 20));
        assertEquals(10, sanitizer(StatusConfig.PlayerCountMode.FIXED, 50, 0, 0).displayedOnline(3, 10));
    }

    @Test
    void randomCountIsStableUntilReroll() {
        StatusSanitizer s = sanitizer(StatusConfig.PlayerCountMode.RANDOM, 0, 5, 30);
        int first = s.displayedOnline(0, 100);
        for (int i = 0; i < 50; i++) {
            clock.advance(Duration.ofSeconds(5)); // 共 250 秒，未到 5 分钟
            assertEquals(first, s.displayedOnline(0, 100));
        }
        Set<Integer> seen = new HashSet<>();
        for (int i = 0; i < 200; i++) {
            clock.advance(Duration.ofMinutes(5));
            int value = s.displayedOnline(0, 100);
            assertTrue(value >= 5 && value <= 30, "value " + value);
            seen.add(value);
        }
        assertTrue(seen.size() > 10, "random values should vary across reroll periods");
        assertTrue(s.displayedOnline(0, 3) <= 3);
    }

    @Test
    void enhancedModeHidesRealCountAndCanDisablePing() {
        StatusConfig config = new StatusConfig(StatusConfig.ProtectionMode.ENHANCED, true, "decoy",
                StatusConfig.PlayerCountMode.REAL, 20, 5, 30, Duration.ofMinutes(5));
        StatusSanitizer sanitizer = new StatusSanitizer(config, clock, new Random());
        assertEquals(0, sanitizer.displayedOnline(12, 20));
        assertTrue(sanitizer.enhanced());
        assertTrue(sanitizer.pingDisabled());
        assertEquals("decoy", sanitizer.enhancedMotd());
    }
}
