package com.mtmrails.trustedserver.core.crypto;

import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

/**
 * 认证成功后移交给游戏阶段的加密状态（PROTOCOL.md 4.3.3、第 5、6 节）：
 * <ul>
 *   <li>密码通道：登录阶段使用的同一个实例，序号连续
 *   <li>隧道计数流：仅在开启隧道时存在，第一帧使用序号 0
 * </ul>
 * 认证通道和其余会话密钥不会移交。用完后调用 {@link #close()}。
 */
public final class SessionHandover {
    private final SecureMessageChannel passwordChannel;
    private final AeadStream tunnelSealer;
    private final AeadStream tunnelOpener;

    private SessionHandover(SecureMessageChannel passwordChannel, AeadStream tunnelSealer, AeadStream tunnelOpener) {
        this.passwordChannel = passwordChannel;
        this.tunnelSealer = tunnelSealer;
        this.tunnelOpener = tunnelOpener;
    }

    /** 从会话密钥和已在用的密码通道构造移交对象；不开隧道时不创建隧道流。 */
    public static SessionHandover create(SessionKeys keys, Side side, SecureMessageChannel passwordChannel,
            boolean tunnel) {
        Objects.requireNonNull(passwordChannel, "passwordChannel");
        if (!tunnel) {
            return new SessionHandover(passwordChannel, null, null);
        }
        byte[] outboundKey = keys.key(SessionKeys.Purpose.TUNNEL, side.outbound());
        byte[] inboundKey = keys.key(SessionKeys.Purpose.TUNNEL, side.inbound());
        try {
            return new SessionHandover(passwordChannel,
                    new AeadStream(outboundKey, side.outbound(), AeadStream.Role.SEAL),
                    new AeadStream(inboundKey, side.inbound(), AeadStream.Role.OPEN));
        } finally {
            Arrays.fill(outboundKey, (byte) 0);
            Arrays.fill(inboundKey, (byte) 0);
        }
    }

    public SecureMessageChannel passwordChannel() {
        return passwordChannel;
    }

    public boolean tunnel() {
        return tunnelSealer != null;
    }

    /** 本端发出的隧道帧所用的计数流。 */
    public Optional<AeadStream> tunnelSealer() {
        return Optional.ofNullable(tunnelSealer);
    }

    /** 收到的隧道帧所用的计数流。 */
    public Optional<AeadStream> tunnelOpener() {
        return Optional.ofNullable(tunnelOpener);
    }

    public void close() {
        passwordChannel.close();
        if (tunnelSealer != null) {
            tunnelSealer.close();
            tunnelOpener.close();
        }
    }
}
