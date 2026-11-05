package com.mtmrails.trustedserver.server.policy;

/** 令牌桶参数：每分钟补充 {@code perMinute} 个，最多存 {@code burst} 个。 */
public record RateLimit(int perMinute, int burst) {
    public RateLimit {
        if (perMinute < 1 || burst < 1) {
            throw new IllegalArgumentException("rate limit values must be positive");
        }
    }
}
