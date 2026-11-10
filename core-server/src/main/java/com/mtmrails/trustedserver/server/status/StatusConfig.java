package com.mtmrails.trustedserver.server.status;

import java.time.Duration;
import java.util.Objects;

/**
 * 服务器列表人数显示（AGENTS.md 第 6、19 条）。
 *
 * @param fixedCount FIXED 模式显示的人数
 * @param randomMin RANDOM 模式的下限（含）
 * @param randomMax RANDOM 模式的上限（含）
 * @param reroll RANDOM 模式重新抽取的间隔
 */
public record StatusConfig(ProtectionMode protection, boolean disablePing, String enhancedMotd,
        PlayerCountMode mode, int fixedCount, int randomMin, int randomMax, Duration reroll) {
    public enum ProtectionMode {
        NORMAL,
        ENHANCED
    }

    public enum PlayerCountMode {
        /** 显示真实人数。 */
        REAL,
        /** 显示固定人数。 */
        FIXED,
        /** 在范围内随机。 */
        RANDOM
    }

    public static final StatusConfig DEFAULT = new StatusConfig(ProtectionMode.NORMAL, false, "A Minecraft Server",
            PlayerCountMode.REAL, 20, 5, 30, Duration.ofMinutes(5));

    public StatusConfig {
        Objects.requireNonNull(protection, "protection");
        Objects.requireNonNull(enhancedMotd, "enhancedMotd");
        Objects.requireNonNull(mode, "mode");
        Objects.requireNonNull(reroll, "reroll");
        if (fixedCount < 0 || randomMin < 0 || randomMin > randomMax) {
            throw new IllegalArgumentException("invalid player count settings");
        }
        if (reroll.isNegative() || reroll.isZero()) {
            throw new IllegalArgumentException("reroll interval must be positive");
        }
        if (enhancedMotd.isBlank()) {
            throw new IllegalArgumentException("enhanced MOTD must not be blank");
        }
    }
}
