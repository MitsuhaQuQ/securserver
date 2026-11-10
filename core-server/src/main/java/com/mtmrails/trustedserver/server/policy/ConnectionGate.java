package com.mtmrails.trustedserver.server.policy;

import java.net.InetAddress;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * 握手之前的 IP 维度拦截（PROTOCOL.md 第 7 节）。状态只保存在内存中，重启即清空。线程安全。
 *
 * <p>为照顾共享 IPv4 出口，登录分两层额度：每次登录消耗宽松的总量额度；只有最终未通过可信握手的连接
 * 才在结束时消耗严格的“未验证”额度。账号维度的锁定与封禁检查由上层另行调用。
 */
public final class ConnectionGate {
    /** 登录前的判定。 */
    public enum Verdict {
        ALLOW,
        /** 超出频率限制。 */
        RATE_LIMITED,
        /** 地址处于 IP 维度的密码错误锁定期。 */
        IP_LOCKED,
        SERVER_BUSY
    }

    private final NetworkPolicyConfig config;
    private final Clock clock;
    private final TokenBuckets ping;
    private final TokenBuckets login;
    private final TokenBuckets unverified;
    private final Map<String, Deque<Long>> failures = new HashMap<>();
    private final Map<String, Long> lockedUntil = new HashMap<>();
    private int pendingLogins;

    public ConnectionGate(NetworkPolicyConfig config, Clock clock) {
        this.config = Objects.requireNonNull(config, "config");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.ping = new TokenBuckets(config.ping(), clock);
        this.login = new TokenBuckets(config.login(), clock);
        this.unverified = new TokenBuckets(config.unverified(), clock);
    }

    /** 服务器列表 Ping 是否放行；不放行时上层直接断开、不回应。 */
    public boolean allowPing(InetAddress address) {
        return isTrusted(address) || ping.tryAcquire(NetworkKey.of(address));
    }

    /** 收到登录 Hello 时调用。返回 ALLOW 时已消耗一个总量额度。 */
    public synchronized Verdict beginLogin(InetAddress address) {
        if (pendingLogins >= config.maxPendingLogins()) {
            return Verdict.SERVER_BUSY;
        }
        if (isTrusted(address)) {
            pendingLogins++;
            return Verdict.ALLOW;
        }
        String key = NetworkKey.of(address);
        if (isLocked(key)) {
            return Verdict.IP_LOCKED;
        }
        if (!unverified.hasToken(key) || !login.tryAcquire(key)) {
            return Verdict.RATE_LIMITED;
        }
        pendingLogins++;
        return Verdict.ALLOW;
    }

    /**
     * 登录连接结束时调用。{@code trustedHandshake} 为对方是否完成了可信握手（放行，或在可信握手之后被拒绝）；
     * 为假时消耗一个“未验证”额度。
     */
    public synchronized void endLogin(InetAddress address, boolean trustedHandshake) {
        if (pendingLogins > 0) {
            pendingLogins--;
        }
        if (!trustedHandshake && !isTrusted(address)) {
            unverified.consume(NetworkKey.of(address));
        }
    }

    /** beginLogin 未分配全局槽位便拒绝的尝试；只计入未验证额度。 */
    public synchronized void rejectLogin(InetAddress address) {
        if (!isTrusted(address)) {
            unverified.consume(NetworkKey.of(address));
        }
    }

    /** 记录一次密码错误（任意账号），达到阈值时锁定该地址。 */
    public void passwordFailed(InetAddress address) {
        if (!config.ipLockoutEnabled() || isTrusted(address)) {
            return;
        }
        IpLockout rule = NetworkKey.isIpv4(address) ? config.ipv4Lockout() : config.ipv6Lockout();
        String key = NetworkKey.of(address);
        long now = clock.millis();
        synchronized (this) {
            Deque<Long> times = failures.computeIfAbsent(key, k -> new ArrayDeque<>());
            prune(times, now - rule.window().toMillis());
            times.addLast(now);
            if (times.size() >= rule.failures()) {
                lockedUntil.put(key, now + rule.lockFor().toMillis());
                times.clear();
            }
            if (failures.size() > TokenBuckets.MAX_ENTRIES) {
                failures.values().removeIf(d -> {
                    prune(d, now - rule.window().toMillis());
                    return d.isEmpty();
                });
            }
        }
    }

    public boolean isLocked(InetAddress address) {
        return !isTrusted(address) && isLocked(NetworkKey.of(address));
    }

    private synchronized boolean isLocked(String key) {
        Long until = lockedUntil.get(key);
        if (until == null) {
            return false;
        }
        if (until <= clock.millis()) {
            lockedUntil.remove(key);
            return false;
        }
        return true;
    }

    private boolean isTrusted(InetAddress address) {
        for (Cidr network : config.trustedNetworks()) {
            if (network.contains(address)) {
                return true;
            }
        }
        return false;
    }

    private static void prune(Deque<Long> times, long cutoff) {
        while (!times.isEmpty() && times.peekFirst() <= cutoff) {
            times.removeFirst();
        }
    }
}
