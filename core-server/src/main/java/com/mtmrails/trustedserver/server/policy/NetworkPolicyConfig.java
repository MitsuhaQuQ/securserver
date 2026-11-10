package com.mtmrails.trustedserver.server.policy;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * 网络层防护参数（AGENTS.md 第 19 条）。默认值对共享 IPv4 出口（运营商级 NAT、校园网）友好。
 *
 * @param unverified 未通过可信握手的连接额外消耗的额度
 * @param trustedNetworks 不受任何 IP 维度限流与锁定的网段
 */
public record NetworkPolicyConfig(RateLimit ping, RateLimit login, RateLimit unverified,
        int maxPendingLogins, int gateTimeoutSeconds, boolean ipLockoutEnabled,
        IpLockout ipv4Lockout, IpLockout ipv6Lockout, List<Cidr> trustedNetworks) {
    public static final NetworkPolicyConfig DEFAULT = new NetworkPolicyConfig(
            new RateLimit(60, 20), new RateLimit(30, 15), new RateLimit(10, 10), 256, 10, true,
            new IpLockout(50, Duration.ofMinutes(15), Duration.ofMinutes(5)),
            new IpLockout(20, Duration.ofMinutes(15), Duration.ofMinutes(15)),
            List.of());

    public NetworkPolicyConfig {
        Objects.requireNonNull(ping, "ping");
        Objects.requireNonNull(login, "login");
        Objects.requireNonNull(unverified, "unverified");
        Objects.requireNonNull(ipv4Lockout, "ipv4Lockout");
        Objects.requireNonNull(ipv6Lockout, "ipv6Lockout");
        trustedNetworks = List.copyOf(trustedNetworks);
        if (maxPendingLogins < 1 || gateTimeoutSeconds < 2) {
            throw new IllegalArgumentException("network pending login limits must be positive");
        }
    }
}
