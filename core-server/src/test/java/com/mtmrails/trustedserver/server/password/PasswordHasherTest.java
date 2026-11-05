package com.mtmrails.trustedserver.server.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Optional;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.junit.jupiter.api.Test;

class PasswordHasherTest {
    /** 测试用的小参数，保持测试速度。 */
    static final PasswordHasher.Params FAST = new PasswordHasher.Params(64, 1, 1);
    private final PasswordHasher hasher = new PasswordHasher(FAST, new SecureRandom());

    @Test
    void bouncyCastleMatchesRfc9106Argon2idVector() {
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(32).withIterations(3).withParallelism(4)
                .withSalt(fill(16, 0x02)).withSecret(fill(8, 0x03)).withAdditional(fill(12, 0x04))
                .build());
        byte[] tag = new byte[32];
        generator.generateBytes(fill(32, 0x01), tag);
        assertEquals("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
                HexFormat.of().formatHex(tag));
    }

    private static byte[] fill(int length, int value) {
        byte[] out = new byte[length];
        java.util.Arrays.fill(out, (byte) value);
        return out;
    }

    @Test
    void hashAndVerify() {
        String encoded = hasher.hash("correct horse 密码");
        assertTrue(encoded.matches("\\$argon2id\\$v=19\\$m=64,t=1,p=1\\$[A-Za-z0-9+/]{22}\\$[A-Za-z0-9+/]{43}"),
                encoded);
        assertTrue(hasher.verify("correct horse 密码", encoded));
        assertFalse(hasher.verify("correct horse", encoded));
        assertNotEquals(encoded, hasher.hash("correct horse 密码")); // 每次随机 salt
    }

    @Test
    void defaultParamsAreOwaspMinimum() {
        assertEquals(new PasswordHasher.Params(19 * 1024, 2, 1), PasswordHasher.Params.DEFAULT);
        String encoded = new PasswordHasher(PasswordHasher.Params.DEFAULT, new SecureRandom()).hash("pw");
        assertTrue(encoded.startsWith("$argon2id$v=19$m=19456,t=2,p=1$"));
    }

    @Test
    void verifyUsesParametersStoredInHash() {
        String old = hasher.hash("pw");
        PasswordHasher upgraded = new PasswordHasher(new PasswordHasher.Params(128, 2, 1), new SecureRandom());
        assertTrue(upgraded.verify("pw", old));
        assertTrue(upgraded.needsRehash(old));
        assertFalse(upgraded.needsRehash(upgraded.hash("pw")));
    }

    @Test
    void malformedOrHostileHashesAreRejected() {
        for (String bad : new String[] {"", "plain", "$argon2i$v=19$m=64,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$"
                + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "$argon2id$v=19$m=64,t=1$x$y",
                "$argon2id$v=19$m=64,t=1,p=1$!!$AAAA", "$argon2id$v=19$m=999999999,t=1,p=1$AAAAAAAAAAA$"
                        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}) {
            assertThrows(IllegalArgumentException.class, () -> hasher.verify("pw", bad), bad);
        }
    }

    @Test
    void policyLength() {
        PasswordPolicy policy = PasswordPolicy.DEFAULT;
        assertTrue(policy.checkLength("12345").isPresent());
        assertEquals(Optional.empty(), policy.checkLength("123456"));
        assertEquals(Optional.empty(), policy.checkLength("🔑🔑🔑🔑🔑🔑")); // 6 个码点
        assertTrue(policy.checkLength("a".repeat(129)).isPresent());
        assertThrows(IllegalArgumentException.class, () -> new PasswordPolicy(0, 10));
        assertThrows(IllegalArgumentException.class, () -> new PasswordPolicy(6, 129));
    }
}
