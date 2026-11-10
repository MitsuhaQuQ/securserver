package com.mtmrails.trustedserver.core.crypto;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class PresharedKeyPolicyTest {
    @Test
    void acceptsGeneratedRandomKey() throws Exception {
        byte[] key = MessageDigest.getInstance("SHA-256")
                .digest("deterministic high-complexity fixture".getBytes(StandardCharsets.UTF_8));
        assertDoesNotThrow(() -> PresharedKeyPolicy.requireStrong(key));
    }

    @Test
    void rejectsLowComplexityAndCommonPasswordMaterial() {
        assertThrows(IllegalArgumentException.class,
                () -> PresharedKeyPolicy.requireStrong(new byte[32]));

        byte[] repeated = "abcd".repeat(8).getBytes(StandardCharsets.US_ASCII);
        assertThrows(IllegalArgumentException.class,
                () -> PresharedKeyPolicy.requireStrong(repeated));

        byte[] sequence = new byte[32];
        for (int i = 0; i < sequence.length; i++) sequence[i] = (byte) i;
        assertThrows(IllegalArgumentException.class,
                () -> PresharedKeyPolicy.requireStrong(sequence));

        byte[] common = "P@ssw0rd-Minecraft-123456-XyZ!".getBytes(StandardCharsets.US_ASCII);
        assertThrows(IllegalArgumentException.class,
                () -> PresharedKeyPolicy.requireStrong(Arrays.copyOf(common, 32)));
    }
}
