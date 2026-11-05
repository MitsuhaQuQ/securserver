package com.mtmrails.trustedserver.core.crypto;

import java.util.Arrays;
import java.util.Objects;

/**
 * 一条 AEAD 计数流：一把密钥、一个线上方向、只做加密或只做解密（PROTOCOL.md 4.3.2、4.3.3）。
 *
 * <ul>
 *   <li>nonce = 方向标签 || u64be(序号)，序号从 0 开始，只在本地构造，不上线
 *   <li>成功处理一条记录后序号加 1；任何失败都会永久关闭本流并清零密钥
 *   <li>每把密钥最多 2^24 条记录、累计 2^36 字节明文，即将超过时在处理前关闭
 * </ul>
 *
 * <p>非线程安全：同一条流必须串行使用。
 */
public final class AeadStream {
    public enum Role {
        SEAL,
        OPEN
    }

    public static final long MAX_RECORDS = 1L << 24;
    public static final long MAX_PLAINTEXT_BYTES = 1L << 36;

    private final byte[] key;
    private final Direction direction;
    private final Role role;
    private final long maxRecords;
    private final long maxPlaintextBytes;
    private long sequence;
    private long plaintextBytes;
    private boolean closed;

    public AeadStream(byte[] key, Direction direction, Role role) {
        this(key, direction, role, MAX_RECORDS, MAX_PLAINTEXT_BYTES);
    }

    /** 测试用：可调低使用上限。 */
    AeadStream(byte[] key, Direction direction, Role role, long maxRecords, long maxPlaintextBytes) {
        this.key = Bytes.requireLength(key, Aes256Gcm.KEY_LENGTH, "key").clone();
        this.direction = Objects.requireNonNull(direction, "direction");
        this.role = Objects.requireNonNull(role, "role");
        this.maxRecords = maxRecords;
        this.maxPlaintextBytes = maxPlaintextBytes;
    }

    public byte[] seal(byte[] aad, byte[] plaintext) throws CryptoException {
        requireRole(Role.SEAL);
        checkUsable(plaintext.length);
        byte[] out;
        try {
            out = Aes256Gcm.encrypt(key, nonce(), aad, plaintext);
        } catch (CryptoException | RuntimeException e) {
            close();
            throw e;
        }
        consume(plaintext.length);
        return out;
    }

    public byte[] open(byte[] aad, byte[] ciphertext) throws CryptoException {
        requireRole(Role.OPEN);
        if (closed) {
            throw new CryptoException("stream is closed");
        }
        if (ciphertext.length < Aes256Gcm.TAG_LENGTH) {
            close();
            throw new CryptoException("ciphertext shorter than tag");
        }
        int plaintextLength = ciphertext.length - Aes256Gcm.TAG_LENGTH;
        checkUsable(plaintextLength);
        byte[] out;
        try {
            out = Aes256Gcm.decrypt(key, nonce(), aad, ciphertext);
        } catch (CryptoException | RuntimeException e) {
            close();
            throw e;
        }
        consume(plaintextLength);
        return out;
    }

    /** 下一条记录将使用的序号。 */
    public long sequence() {
        return sequence;
    }

    public boolean isOpen() {
        return !closed;
    }

    /** 永久关闭并清零密钥。 */
    public void close() {
        closed = true;
        Arrays.fill(key, (byte) 0);
    }

    private void requireRole(Role expected) {
        if (role != expected) {
            throw new IllegalStateException("stream role is " + role + ", not " + expected);
        }
    }

    private void checkUsable(int plaintextLength) throws CryptoException {
        if (closed) {
            throw new CryptoException("stream is closed");
        }
        if (sequence >= maxRecords || plaintextBytes + plaintextLength > maxPlaintextBytes) {
            close();
            throw new CryptoException("key usage limit reached");
        }
    }

    private void consume(int plaintextLength) {
        sequence++;
        plaintextBytes += plaintextLength;
    }

    private byte[] nonce() {
        byte[] nonce = Arrays.copyOf(direction.tag(), Aes256Gcm.NONCE_LENGTH);
        for (int i = 0; i < 8; i++) {
            nonce[4 + i] = (byte) (sequence >>> (56 - 8 * i));
        }
        return nonce;
    }
}
