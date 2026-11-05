package com.mtmrails.trustedserver.core.crypto;

import static com.mtmrails.trustedserver.core.crypto.Hex.h;
import static com.mtmrails.trustedserver.core.crypto.Hex.s;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

/** 标准测试向量：RFC 5869、RFC 7748、RFC 8032、GCM 规范测试用例。 */
class PrimitiveVectorsTest {
    // ---- HKDF-SHA256, RFC 5869 附录 A ----

    @Test
    void hkdfRfc5869Case1() {
        byte[] prk = Hkdf.extract(h("000102030405060708090a0b0c"), h("0b".repeat(22)));
        assertEquals("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", s(prk));
        assertEquals("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                s(Hkdf.expand(prk, h("f0f1f2f3f4f5f6f7f8f9"), 42)));
    }

    @Test
    void hkdfRfc5869Case3EmptySaltAndInfo() {
        byte[] prk = Hkdf.extract(new byte[0], h("0b".repeat(22)));
        assertEquals("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", s(prk));
        assertEquals("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
                s(Hkdf.expand(prk, new byte[0], 42)));
    }

    @Test
    void hkdfRejectsBadLengths() {
        byte[] prk = new byte[32];
        assertThrows(IllegalArgumentException.class, () -> Hkdf.expand(prk, new byte[0], 0));
        assertThrows(IllegalArgumentException.class, () -> Hkdf.expand(prk, new byte[0], 255 * 32 + 1));
        assertThrows(IllegalArgumentException.class, () -> Hkdf.expand(new byte[31], new byte[0], 32));
        assertEquals(255 * 32, Hkdf.expand(prk, new byte[0], 255 * 32).length);
    }

    // ---- X25519, RFC 7748 ----

    @Test
    void x25519Rfc7748Section52() throws Exception {
        assertEquals("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
                s(X25519.agree(h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                        h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"))));
        // 这个 u 的最高位为 1，必须按 RFC 7748 清除（结果已用 OpenSSL 交叉核对）
        assertEquals("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
                s(X25519.agree(h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
                        h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"))));
    }

    @Test
    void x25519Rfc7748Section61DiffieHellman() throws Exception {
        byte[] alicePriv = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] bobPriv = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        byte[] alicePub = X25519.publicKeyOf(alicePriv);
        byte[] bobPub = X25519.publicKeyOf(bobPriv);
        assertEquals("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", s(alicePub));
        assertEquals("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", s(bobPub));
        String shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        assertEquals(shared, s(X25519.agree(alicePriv, bobPub)));
        assertEquals(shared, s(X25519.agree(bobPriv, alicePub)));
    }

    @Test
    void x25519TreatsNonCanonicalUAsReducedModP() throws Exception {
        byte[] scalar = h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        BigInteger p = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
        byte[] canonical = X25519.encodePublic(BigInteger.valueOf(9));
        byte[] nonCanonical = Bytes.toLittleEndian(p.add(BigInteger.valueOf(9)), 32);
        assertArrayEquals(X25519.agree(scalar, canonical), X25519.agree(scalar, nonCanonical));
    }

    @Test
    void x25519RejectsSmallOrderPoints() {
        byte[] scalar = h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        assertThrows(CryptoException.class, () -> X25519.agree(scalar, new byte[32])); // u = 0
        byte[] one = new byte[32];
        one[0] = 1;
        assertThrows(CryptoException.class, () -> X25519.agree(scalar, one)); // u = 1
        assertThrows(IllegalArgumentException.class, () -> X25519.agree(scalar, new byte[31]));
    }

    @Test
    void x25519EphemeralKeysAgree() throws Exception {
        SecureRandom random = new SecureRandom();
        X25519.Ephemeral a = X25519.generate(random);
        X25519.Ephemeral b = X25519.generate(random);
        assertEquals(32, a.publicKey().length);
        assertArrayEquals(a.agree(b.publicKey()), b.agree(a.publicKey()));
        assertFalse(Arrays.equals(a.publicKey(), b.publicKey()));
    }

    // ---- Ed25519, RFC 8032 第 7.1 节 ----

    private static void checkEd25519(String seed, String pub, String message, String signature) throws Exception {
        Ed25519.KeyPairData pair = Ed25519.fromSeed(h(seed), h(pub));
        assertEquals(signature, s(pair.sign(h(message))));
        assertTrue(Ed25519.verify(h(pub), h(message), h(signature)));
    }

    @Test
    void ed25519Rfc8032Test1() throws Exception {
        checkEd25519("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                        + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    }

    @Test
    void ed25519Rfc8032Test2() throws Exception {
        checkEd25519("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                        + "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
    }

    @Test
    void ed25519Rfc8032Test3() throws Exception {
        checkEd25519("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                        + "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
    }

    private static final String T1_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    private static final String T1_SIG = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

    @Test
    void ed25519RejectsMalleatedSignatureWithLargeS() {
        byte[] sig = h(T1_SIG);
        BigInteger l = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
        BigInteger s = Bytes.fromLittleEndian(Arrays.copyOfRange(sig, 32, 64)).add(l);
        System.arraycopy(Bytes.toLittleEndian(s, 32), 0, sig, 32, 32);
        assertFalse(Ed25519.verify(h(T1_PUB), new byte[0], sig));
    }

    @Test
    void ed25519RejectsNonCanonicalPublicKey() {
        // y = p（清除最高位后 ≥ p）
        BigInteger p = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
        assertFalse(Ed25519.verify(Bytes.toLittleEndian(p, 32), new byte[0], h(T1_SIG)));
        assertFalse(Ed25519.verify(h("ff".repeat(32)), new byte[0], h(T1_SIG)));
    }

    @Test
    void ed25519RejectsTamperingAndBadLengths() {
        byte[] sig = h(T1_SIG);
        sig[0] ^= 1;
        assertFalse(Ed25519.verify(h(T1_PUB), new byte[0], sig));
        assertFalse(Ed25519.verify(h(T1_PUB), new byte[] {1}, h(T1_SIG)));
        assertFalse(Ed25519.verify(h(T1_PUB), new byte[0], Arrays.copyOf(h(T1_SIG), 63)));
        assertFalse(Ed25519.verify(Arrays.copyOf(h(T1_PUB), 31), new byte[0], h(T1_SIG)));
        assertFalse(Ed25519.verify(null, new byte[0], h(T1_SIG)));
    }

    @Test
    void ed25519FromSeedRejectsMismatchedPublicKey() {
        assertThrows(CryptoException.class, () -> Ed25519.fromSeed(
                h("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"), h(T1_PUB)));
    }

    @Test
    void ed25519GeneratedKeysRoundTripThroughSeed() throws Exception {
        Ed25519.KeyPairData pair = Ed25519.generate(new SecureRandom());
        Ed25519.KeyPairData restored = Ed25519.fromSeed(pair.seed(), pair.publicKey());
        byte[] message = {1, 2, 3};
        assertTrue(Ed25519.verify(pair.publicKey(), message, restored.sign(message)));
        assertArrayEquals(pair.sign(message), restored.sign(message));
    }

    // ---- AES-256-GCM，GCM 规范（McGrew & Viega）测试用例 13、14 ----

    @Test
    void aesGcmTestCase13EmptyPlaintext() throws Exception {
        byte[] out = Aes256Gcm.encrypt(new byte[32], new byte[12], new byte[0], new byte[0]);
        assertEquals("530f8afbc74536b9a963b4f1c4cb738b", s(out));
        assertEquals(0, Aes256Gcm.decrypt(new byte[32], new byte[12], new byte[0], out).length);
    }

    @Test
    void aesGcmTestCase14() throws Exception {
        byte[] out = Aes256Gcm.encrypt(new byte[32], new byte[12], new byte[0], new byte[16]);
        assertEquals("cea7403d4d606b6e074ec5d3baf39d18" + "d0d1c8a799996bf0265b98b5d48ab919", s(out));
    }

    @Test
    void aesGcmRejectsTamperedTagOrAad() throws Exception {
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        byte[] out = Aes256Gcm.encrypt(key, nonce, new byte[] {1}, new byte[16]);
        byte[] badTag = out.clone();
        badTag[badTag.length - 1] ^= 1;
        assertThrows(CryptoException.class, () -> Aes256Gcm.decrypt(key, nonce, new byte[] {1}, badTag));
        assertThrows(CryptoException.class, () -> Aes256Gcm.decrypt(key, nonce, new byte[] {2}, out));
        assertThrows(CryptoException.class, () -> Aes256Gcm.decrypt(key, nonce, new byte[0], new byte[15]));
        assertNotEquals(s(out), s(Aes256Gcm.encrypt(key, nonce, new byte[] {2}, new byte[16])));
    }
}
