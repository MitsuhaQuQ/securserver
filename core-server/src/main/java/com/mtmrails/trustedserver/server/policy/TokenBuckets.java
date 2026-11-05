package com.mtmrails.trustedserver.server.policy;

import java.time.Clock;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * 按键分组的令牌桶，仅存在内存中。线程安全。
 *
 * <p>为防止大量不同地址撑爆内存，条目超过上限时清理已经补满（等价于从未使用）的桶。
 */
final class TokenBuckets {
    static final int MAX_ENTRIES = 100_000;

    private static final class Bucket {
        double tokens;
        long updatedAt;
    }

    private final RateLimit limit;
    private final Clock clock;
    private final Map<String, Bucket> buckets = new HashMap<>();

    TokenBuckets(RateLimit limit, Clock clock) {
        this.limit = limit;
        this.clock = clock;
    }

    /** 有令牌则消耗一个并返回 {@code true}。 */
    synchronized boolean tryAcquire(String key) {
        Bucket bucket = refill(key);
        if (bucket.tokens >= 1) {
            bucket.tokens -= 1;
            return true;
        }
        return false;
    }

    /** 只检查是否还有令牌，不消耗。 */
    synchronized boolean hasToken(String key) {
        return refill(key).tokens >= 1;
    }

    /** 消耗一个令牌（不足一个时扣到零）。 */
    synchronized void consume(String key) {
        Bucket bucket = refill(key);
        bucket.tokens = Math.max(0, bucket.tokens - 1);
    }

    synchronized int size() {
        return buckets.size();
    }

    private Bucket refill(String key) {
        long now = clock.millis();
        Bucket bucket = buckets.get(key);
        if (bucket == null) {
            if (buckets.size() >= MAX_ENTRIES) {
                evictFull(now);
            }
            bucket = new Bucket();
            bucket.tokens = limit.burst();
            bucket.updatedAt = now;
            buckets.put(key, bucket);
            return bucket;
        }
        long elapsed = Math.max(0, now - bucket.updatedAt);
        bucket.tokens = Math.min(limit.burst(), bucket.tokens + elapsed * limit.perMinute() / 60_000.0);
        bucket.updatedAt = now;
        return bucket;
    }

    private void evictFull(long now) {
        Iterator<Bucket> it = buckets.values().iterator();
        while (it.hasNext()) {
            Bucket bucket = it.next();
            double tokens = bucket.tokens + Math.max(0, now - bucket.updatedAt) * limit.perMinute() / 60_000.0;
            if (tokens >= limit.burst()) {
                it.remove();
            }
        }
    }
}
