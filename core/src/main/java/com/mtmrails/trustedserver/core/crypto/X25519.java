package com.mtmrails.trustedserver.core.crypto;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;
import java.security.spec.XECPrivateKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.Arrays;
import javax.crypto.KeyAgreement;

/**
 * X25519 临时密钥交换（RFC 7748），公钥在线上为 32 字节小端 u 坐标。
 */
public final class X25519 {
    public static final int KEY_LENGTH = 32;
    private static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));

    private X25519() {
    }

    /** 一次连接的临时密钥对；私钥不出本类之外的序列化形式。 */
    public static final class Ephemeral {
        private final PrivateKey privateKey;
        private final byte[] publicKey;

        private Ephemeral(PrivateKey privateKey, byte[] publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public byte[] publicKey() {
            return publicKey.clone();
        }

        /** 与对方公钥做 DH，返回 32 字节共享秘密。 */
        public byte[] agree(byte[] peerPublicKey) throws CryptoException {
            return X25519.agree(privateKey, peerPublicKey);
        }
    }

    public static Ephemeral generate(SecureRandom random) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("XDH");
            generator.initialize(NamedParameterSpec.X25519, random);
            KeyPair pair = generator.generateKeyPair();
            return new Ephemeral(pair.getPrivate(), encodePublic(((XECPublicKey) pair.getPublic()).getU()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519 unavailable", e);
        }
    }

    /** 由原始 32 字节标量计算 DH（测试向量用）。 */
    static byte[] agree(byte[] scalar, byte[] peerPublicKey) throws CryptoException {
        Bytes.requireLength(scalar, KEY_LENGTH, "scalar");
        try {
            PrivateKey privateKey = KeyFactory.getInstance("XDH")
                    .generatePrivate(new XECPrivateKeySpec(NamedParameterSpec.X25519, scalar.clone()));
            return agree(privateKey, peerPublicKey);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("X25519 unavailable", e);
        }
    }

    /** 由原始标量计算公钥（测试向量用）：与基点 u = 9 做 DH。 */
    static byte[] publicKeyOf(byte[] scalar) throws CryptoException {
        byte[] basePoint = new byte[KEY_LENGTH];
        basePoint[0] = 9;
        return agree(scalar, basePoint);
    }

    private static byte[] agree(PrivateKey privateKey, byte[] peerPublicKey) throws CryptoException {
        Bytes.requireLength(peerPublicKey, KEY_LENGTH, "peerPublicKey");
        byte[] secret;
        try {
            PublicKey peer = KeyFactory.getInstance("XDH")
                    .generatePublic(new XECPublicKeySpec(NamedParameterSpec.X25519, decodeU(peerPublicKey)));
            KeyAgreement agreement = KeyAgreement.getInstance("XDH");
            agreement.init(privateKey);
            agreement.doPhase(peer, true);
            secret = agreement.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("X25519 key agreement rejected", e);
        }
        if (secret.length != KEY_LENGTH || Bytes.isAllZero(secret)) {
            Arrays.fill(secret, (byte) 0);
            throw new CryptoException("X25519 produced an all-zero shared secret");
        }
        return secret;
    }

    /** RFC 7748 decodeUCoordinate：清除最高位，非规范值按模 p 约简。 */
    static BigInteger decodeU(byte[] encoded) {
        byte[] masked = encoded.clone();
        masked[KEY_LENGTH - 1] &= 0x7F;
        return Bytes.fromLittleEndian(masked).mod(P);
    }

    static byte[] encodePublic(BigInteger u) {
        return Bytes.toLittleEndian(u.mod(P), KEY_LENGTH);
    }
}
