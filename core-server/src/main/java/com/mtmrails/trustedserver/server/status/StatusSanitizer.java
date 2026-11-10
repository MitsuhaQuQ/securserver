package com.mtmrails.trustedserver.server.status;

import java.time.Clock;
import java.util.Objects;
import java.util.Random;

/**
 * 服务器列表 Ping 响应脱敏（PROTOCOL.md 第 8 节）：玩家样本列表一律清空（由适配层执行），在线人数按配置输出。
 * 随机模式按固定间隔重新抽取，避免每次刷新都跳动而显得可疑。线程安全。
 */
public final class StatusSanitizer {
    private final StatusConfig config;
    private final Clock clock;
    private final Random random;
    private int currentRandom = -1;
    private long nextReroll;

    public StatusSanitizer(StatusConfig config, Clock clock, Random random) {
        this.config = Objects.requireNonNull(config, "config");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.random = Objects.requireNonNull(random, "random");
    }

    /** 对外显示的在线人数，不超过最大人数。 */
    public int displayedOnline(int realOnline, int maxPlayers) {
        if (config.protection() == StatusConfig.ProtectionMode.ENHANCED
                && config.mode() == StatusConfig.PlayerCountMode.REAL) {
            return 0;
        }
        int value = switch (config.mode()) {
            case REAL -> realOnline;
            case FIXED -> config.fixedCount();
            case RANDOM -> randomCount();
        };
        return Math.max(0, Math.min(value, maxPlayers));
    }

    public boolean enhanced() {
        return config.protection() == StatusConfig.ProtectionMode.ENHANCED;
    }

    public boolean pingDisabled() {
        return enhanced() && config.disablePing();
    }

    public String enhancedMotd() {
        return config.enhancedMotd();
    }

    private synchronized int randomCount() {
        long now = clock.millis();
        if (currentRandom < 0 || now >= nextReroll) {
            currentRandom = config.randomMin() + random.nextInt(config.randomMax() - config.randomMin() + 1);
            nextReroll = now + config.reroll().toMillis();
        }
        return currentRandom;
    }
}
