package com.mtmrails.trustedserver.client;

import com.mtmrails.trustedserver.core.crypto.Ed25519;
import com.mtmrails.trustedserver.core.wire.WireWriter;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

/**
 * 玩家密钥的定位：服务端身份公钥 + 原始用户名（保留大小写）。
 */
public record KeyTarget(byte[] serverIdPub, String username) {
    /** 用户名 UTF-8 编码后的最大字节数。 */
    public static final int MAX_USERNAME_BYTES = 256;

    public KeyTarget {
        if (serverIdPub == null || serverIdPub.length != Ed25519.PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("serverIdPub must be " + Ed25519.PUBLIC_KEY_LENGTH + " bytes");
        }
        serverIdPub = serverIdPub.clone();
        Objects.requireNonNull(username, "username");
        if (username.isEmpty() || WireWriter.utf8(username).length > MAX_USERNAME_BYTES) {
            throw new IllegalArgumentException("username must be 1.." + MAX_USERNAME_BYTES + " UTF-8 bytes");
        }
    }

    @Override
    public byte[] serverIdPub() {
        return serverIdPub.clone();
    }

    /** 服务端身份公钥的十六进制指纹，供界面显示。 */
    public String serverFingerprint() {
        return HexFormat.of().formatHex(serverIdPub);
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof KeyTarget other && Arrays.equals(serverIdPub, other.serverIdPub)
                && username.equals(other.username);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(serverIdPub) + username.hashCode();
    }

    @Override
    public String toString() {
        return "KeyTarget[server=" + serverFingerprint() + ", username=" + username + "]";
    }
}
