package com.mtmrails.trustedserver.server.policy;

import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/** 服务端线程上的新人破坏频率检测。使用单调时间，短时重连保留状态。 */
public final class NewPlayerGuard {
    public record Config(boolean enabled, int newcomerMinutes, int maxBreaks, int windowSeconds,
            int cooldownSeconds) {
        public static final Config DEFAULT = new Config(false, 30, 40, 10, 30);
    }

    public enum Verdict { ALLOW, START_COOLDOWN, COOLDOWN }

    private static final class Activity {
        final ArrayDeque<Long> breaks = new ArrayDeque<>();
        Long blockedSince;
    }

    private final Config config;
    private final Map<UUID, Activity> activity = new HashMap<>();
    private final long windowMillis;
    private final long cooldownMillis;

    public NewPlayerGuard(Config config) {
        this.config = config;
        windowMillis = config.windowSeconds() * 1000L;
        cooldownMillis = config.cooldownSeconds() * 1000L;
    }

    public Verdict beforeBreak(UUID player, int playTicks, long nowMillis) {
        Activity recent = activity.get(player);
        if (recent != null && recent.blockedSince != null) {
            if (nowMillis - recent.blockedSince < cooldownMillis) {
                return Verdict.COOLDOWN;
            }
            recent.blockedSince = null;
        }
        if (playTicks >= config.newcomerMinutes() * 1200L) {
            activity.remove(player);
            return Verdict.ALLOW;
        }
        if (recent == null) {
            recent = new Activity();
            activity.put(player, recent);
        }
        expireBreaks(recent, nowMillis);
        if (recent.breaks.size() >= config.maxBreaks()) {
            recent.breaks.clear();
            recent.blockedSince = nowMillis;
            return Verdict.START_COOLDOWN;
        }
        recent.breaks.addLast(nowMillis);
        return Verdict.ALLOW;
    }

    public void prune(long nowMillis) {
        activity.values().removeIf(recent -> {
            expireBreaks(recent, nowMillis);
            return recent.breaks.isEmpty()
                    && (recent.blockedSince == null || nowMillis - recent.blockedSince >= cooldownMillis);
        });
    }

    private void expireBreaks(Activity recent, long nowMillis) {
        while (!recent.breaks.isEmpty() && nowMillis - recent.breaks.getFirst() >= windowMillis) {
            recent.breaks.removeFirst();
        }
    }
}
