package com.mtmrails.trustedserver.core.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

/**
 * 普通 Ed25519（RFC 8032，非 ph/ctx）。公钥为 32 字节压缩点，签名为 64 字节 {@code R || S}，均不带 DER 包装。
 * 椭圆曲线运算全部交给 JDK，这里只做原始编码与边界检查。
 */
public final class Ed25519 {
    public static final int PUBLIC_KEY_LENGTH = 32;
    public static final int SEED_LENGTH = 32;
    public static final int SIGNATURE_LENGTH = 64;

    private static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    /** 群阶 L = 2^252 + 27742317777372353535851937790883648493。 */
    private static final BigInteger L = BigInteger.ONE.shiftLeft(252)
            .add(new BigInteger("27742317777372353535851937790883648493"));
    private static final byte[] PAIR_CHECK_MESSAGE = Bytes.ascii("tsrv ed25519 key pair check");

    private Ed25519() {
    }

    /** 长期身份密钥对。 */
    public static final class KeyPairData {
        private final PrivateKey privateKey;
        private final byte[] seed;
        private final byte[] publicKey;

        private KeyPairData(PrivateKey privateKey, byte[] seed, byte[] publicKey) {
            this.privateKey = privateKey;
            this.seed = seed;
            this.publicKey = publicKey;
        }

        public byte[] publicKey() {
            return publicKey.clone();
        }

        /** 32 字节私钥种子，仅供本地持久化和备份使用，不得写入日志。 */
        public byte[] seed() {
            return seed.clone();
        }

        public byte[] sign(byte[] message) {
            try {
                Signature signer = Signature.getInstance("Ed25519");
                signer.initSign(privateKey);
                signer.update(message);
                return signer.sign();
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("Ed25519 signing failed", e);
            }
        }
    }

    public static KeyPairData generate(SecureRandom random) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("Ed25519");
            generator.initialize(NamedParameterSpec.ED25519, random);
            KeyPair pair = generator.generateKeyPair();
            byte[] seed = ((EdECPrivateKey) pair.getPrivate()).getBytes()
                    .orElseThrow(() -> new IllegalStateException("Ed25519 private key bytes unavailable"));
            return new KeyPairData(pair.getPrivate(), seed, encodePublic(((EdECPublicKey) pair.getPublic()).getPoint()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 unavailable", e);
        }
    }

    /**
     * 从持久化的种子和公钥恢复密钥对，并通过一次签名 / 验签确认二者匹配。
     *
     * @throws CryptoException 公钥编码非法，或与种子不匹配
     */
    public static KeyPairData fromSeed(byte[] seed, byte[] publicKey) throws CryptoException {
        Bytes.requireLength(seed, SEED_LENGTH, "seed");
        Bytes.requireLength(publicKey, PUBLIC_KEY_LENGTH, "publicKey");
        PrivateKey privateKey;
        try {
            privateKey = KeyFactory.getInstance("Ed25519")
                    .generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed.clone()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 unavailable", e);
        }
        KeyPairData pair = new KeyPairData(privateKey, seed.clone(), publicKey.clone());
        if (!verify(publicKey, PAIR_CHECK_MESSAGE, pair.sign(PAIR_CHECK_MESSAGE))) {
            throw new CryptoException("Ed25519 seed does not match public key");
        }
        return pair;
    }

    /** 验签。公钥或签名编码非法、S 越界、签名无效时一律返回 {@code false}。 */
    public static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        if (publicKey == null || publicKey.length != PUBLIC_KEY_LENGTH
                || signature == null || signature.length != SIGNATURE_LENGTH) {
            return false;
        }
        BigInteger s = Bytes.fromLittleEndian(Arrays.copyOfRange(signature, 32, 64));
        if (s.compareTo(L) >= 0) {
            return false;
        }
        try {
            PublicKey key = decodePublic(publicKey);
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update(message);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    /** RFC 8032 5.1.3：y 为清除最高位后的小端整数且必须小于 p，最高位为 x 的奇偶。 */
    static PublicKey decodePublic(byte[] encoded) throws GeneralSecurityException {
        byte[] masked = encoded.clone();
        boolean xOdd = (masked[PUBLIC_KEY_LENGTH - 1] & 0x80) != 0;
        masked[PUBLIC_KEY_LENGTH - 1] &= 0x7F;
        BigInteger y = Bytes.fromLittleEndian(masked);
        if (y.compareTo(P) >= 0) {
            throw new IllegalArgumentException("non-canonical Ed25519 point encoding");
        }
        return KeyFactory.getInstance("Ed25519")
                .generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, new EdECPoint(xOdd, y)));
    }

    static byte[] encodePublic(EdECPoint point) {
        byte[] out = Bytes.toLittleEndian(point.getY(), PUBLIC_KEY_LENGTH);
        if (point.isXOdd()) {
            out[PUBLIC_KEY_LENGTH - 1] |= (byte) 0x80;
        }
        return out;
    }
}
