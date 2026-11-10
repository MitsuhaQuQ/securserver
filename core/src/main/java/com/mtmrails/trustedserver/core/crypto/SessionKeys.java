package com.mtmrails.trustedserver.core.crypto;

import com.mtmrails.trustedserver.core.message.Channel;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.Map;

/**
 * 一次连接的六把会话密钥（PROTOCOL.md 4.3）：
 * {@code k = HKDF-Expand(HKDF-Extract(server_nonce || client_nonce, shared), "tsrv v3 <用途> <方向>" || transcript_0, 32)}。
 */
public final class SessionKeys {
    public enum Purpose {
        AUTH("auth"),
        TUNNEL("tunnel"),
        PASSWORD("password");

        private final String label;

        Purpose(String label) {
            this.label = label;
        }
    }

    static final String LABEL_PREFIX = "tsrv v3 ";

    private final Map<Purpose, Map<Direction, byte[]>> keys = new EnumMap<>(Purpose.class);
    private boolean destroyed;

    private SessionKeys() {
    }

    /**
     * 派生会话密钥。本方法接管 {@code sharedSecret}：它和中间 PRK 都会在派生后清零。
     */
    public static SessionKeys derive(byte[] sharedSecret, byte[] serverNonce, byte[] clientNonce, byte[] transcript) {
        Bytes.requireLength(sharedSecret, X25519.KEY_LENGTH, "sharedSecret");
        Bytes.requireLength(serverNonce, 32, "serverNonce");
        Bytes.requireLength(clientNonce, 32, "clientNonce");
        Bytes.requireLength(transcript, Transcript.LENGTH, "transcript");
        byte[] prk;
        try {
            prk = Hkdf.extract(Bytes.concat(serverNonce, clientNonce), sharedSecret);
        } finally {
            Arrays.fill(sharedSecret, (byte) 0);
        }
        try {
            SessionKeys result = new SessionKeys();
            for (Purpose purpose : Purpose.values()) {
                Map<Direction, byte[]> byDirection = new EnumMap<>(Direction.class);
                for (Direction direction : Direction.values()) {
                    byte[] info = Bytes.concat(Bytes.ascii(label(purpose, direction)), transcript);
                    byDirection.put(direction, Hkdf.expand(prk, info, Aes256Gcm.KEY_LENGTH));
                }
                result.keys.put(purpose, byDirection);
            }
            return result;
        } finally {
            Arrays.fill(prk, (byte) 0);
        }
    }

    static String label(Purpose purpose, Direction direction) {
        return LABEL_PREFIX + purpose.label + " " + direction.label();
    }

    /** 返回密钥副本（隧道编解码器及测试使用）。 */
    public byte[] key(Purpose purpose, Direction direction) {
        if (destroyed) {
            throw new IllegalStateException("session keys destroyed");
        }
        return keys.get(purpose).get(direction).clone();
    }

    /** 本端在认证频道上的加密收发。 */
    public SecureMessageChannel authChannel(Side side) {
        return channel(Channel.AUTH, Purpose.AUTH, side);
    }

    /** 本端在密码频道上的加密收发；登录与游戏阶段共用同一实例。 */
    public SecureMessageChannel passwordChannel(Side side) {
        return channel(Channel.PASSWORD, Purpose.PASSWORD, side);
    }

    private SecureMessageChannel channel(Channel channel, Purpose purpose, Side side) {
        byte[] outboundKey = key(purpose, side.outbound());
        byte[] inboundKey = key(purpose, side.inbound());
        try {
            return new SecureMessageChannel(channel,
                    new AeadStream(outboundKey, side.outbound(), AeadStream.Role.SEAL),
                    new AeadStream(inboundKey, side.inbound(), AeadStream.Role.OPEN));
        } finally {
            Arrays.fill(outboundKey, (byte) 0);
            Arrays.fill(inboundKey, (byte) 0);
        }
    }

    /** 清零全部密钥；之后不能再取用。 */
    public void destroy() {
        destroyed = true;
        keys.values().forEach(m -> m.values().forEach(k -> Arrays.fill(k, (byte) 0)));
    }
}
