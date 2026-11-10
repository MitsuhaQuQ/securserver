package com.mtmrails.trustedserver.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ProtocolVersionTest {
    @Test
    void picksHighestCommonVersion() {
        assertEquals(ProtocolVersion.CURRENT,
                ProtocolVersion.negotiate(new int[] {ProtocolVersion.CURRENT + 5, ProtocolVersion.CURRENT}));
    }

    @Test
    void returnsNoneWithoutCommonVersion() {
        assertEquals(ProtocolVersion.NONE, ProtocolVersion.negotiate(new int[] {ProtocolVersion.CURRENT + 1}));
        assertEquals(ProtocolVersion.NONE, ProtocolVersion.negotiate(new int[0]));
    }

    @Test
    void noneIsNeverSupported() {
        assertFalse(ProtocolVersion.isSupported(ProtocolVersion.NONE));
        assertTrue(ProtocolVersion.isSupported(ProtocolVersion.CURRENT));
    }

    @Test
    void supportedReturnsDefensiveCopy() {
        ProtocolVersion.supported()[0] = -1;
        assertTrue(ProtocolVersion.isSupported(ProtocolVersion.CURRENT));
    }

    @Test
    void recoveryActionsRequireVersionThree() {
        assertEquals(3, ProtocolVersion.CURRENT);
        assertFalse(ProtocolVersion.isSupported(2));
    }
}
