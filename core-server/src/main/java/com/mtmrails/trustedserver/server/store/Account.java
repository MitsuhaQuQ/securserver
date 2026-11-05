package com.mtmrails.trustedserver.server.store;

import java.util.Objects;

/**
 * players 表的一行。{@code playerPub} 为 {@code null} 表示设备绑定已被管理员清空；
 * 时间均为毫秒时间戳。
 */
public record Account(String id, String lastName, byte[] playerPub, String passwordHash, String recoveryHash,
        boolean restricted, long createdAt, Long lastLoginAt, String lastIp) {
    public Account {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(lastName, "lastName");
        playerPub = playerPub == null ? null : playerPub.clone();
    }

    @Override
    public byte[] playerPub() {
        return playerPub == null ? null : playerPub.clone();
    }

    @Override
    public String toString() {
        // 不输出哈希
        return "Account[id=" + id + ", lastName=" + lastName + ", keyBound=" + (playerPub != null)
                + ", hasPassword=" + (passwordHash != null) + ", hasRecovery=" + (recoveryHash != null)
                + ", restricted=" + restricted + "]";
    }
}
