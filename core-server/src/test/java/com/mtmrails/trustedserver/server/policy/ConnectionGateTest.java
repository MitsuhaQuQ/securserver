package com.mtmrails.trustedserver.server.policy;

import static com.mtmrails.trustedserver.server.policy.NetworkKeyTest.ip;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

class ConnectionGateTest {
    private final TestClock clock = new TestClock();
    private final InetAddress natExit = ip("203.0.113.7");

    private ConnectionGate gate(NetworkPolicyConfig config) {
        return new ConnectionGate(config, clock);
    }

    private ConnectionGate gate() {
        return gate(NetworkPolicyConfig.DEFAULT);
    }

    @Test
    void pingBurstThenRefill() {
        ConnectionGate gate = gate();
        for (int i = 0; i < 20; i++) {
            assertTrue(gate.allowPing(natExit), "ping " + i);
        }
        assertFalse(gate.allowPing(natExit));
        clock.advance(Duration.ofSeconds(1)); // 每分钟 60 个 = 每秒 1 个
        assertTrue(gate.allowPing(natExit));
        assertFalse(gate.allowPing(natExit));
        assertTrue(gate.allowPing(ip("203.0.113.8"))); // 其他地址不受影响
    }

    @Test
    void manyLegitPlayersBehindOneNatAreNotBlocked() {
        ConnectionGate gate = gate();
        // 同一出口后，一分钟内 30 位装了 mod 的玩家依次登录并完成可信握手
        for (int i = 0; i < 30; i++) {
            assertEquals(ConnectionGate.Verdict.ALLOW, gate.beginLogin(natExit), "player " + i);
            gate.endLogin(natExit, true);
            clock.advance(Duration.ofSeconds(2));
        }
    }

    @Test
    void botsWithoutModExhaustTheStrictBudget() {
        ConnectionGate gate = gate();
        for (int i = 0; i < 10; i++) {
            assertEquals(ConnectionGate.Verdict.ALLOW, gate.beginLogin(natExit));
            gate.endLogin(natExit, false);
        }
        assertEquals(ConnectionGate.Verdict.RATE_LIMITED, gate.beginLogin(natExit));
        // 未验证额度按每分钟 10 个恢复
        clock.advance(Duration.ofSeconds(6));
        assertEquals(ConnectionGate.Verdict.ALLOW, gate.beginLogin(natExit));
    }

    @Test
    void loginFloodHitsTotalBudget() {
        ConnectionGate gate = gate();
        for (int i = 0; i < 15; i++) {
            assertEquals(ConnectionGate.Verdict.ALLOW, gate.beginLogin(natExit));
            gate.endLogin(natExit, true);
        }
        assertEquals(ConnectionGate.Verdict.RATE_LIMITED, gate.beginLogin(natExit));
    }

    @Test
    void ipv4LockoutIsLenientForSharedExits() {
        ConnectionGate gate = gate();
        for (int i = 0; i < 49; i++) {
            gate.passwordFailed(natExit);
        }
        assertFalse(gate.isLocked(natExit));
        gate.passwordFailed(natExit);
        assertTrue(gate.isLocked(natExit));
        assertEquals(ConnectionGate.Verdict.IP_LOCKED, gate.beginLogin(natExit));
        clock.advance(Duration.ofMinutes(5).plusSeconds(1));
        assertFalse(gate.isLocked(natExit));
    }

    @Test
    void failuresOutsideTheWindowDoNotAccumulate() {
        ConnectionGate gate = gate();
        for (int i = 0; i < 100; i++) {
            gate.passwordFailed(natExit);
            clock.advance(Duration.ofSeconds(20)); // 15 分钟内最多 45 次
        }
        assertFalse(gate.isLocked(natExit));
    }

    @Test
    void ipv6LockoutCoversTheWholeSlash64() {
        ConnectionGate gate = gate();
        for (int i = 1; i <= 20; i++) {
            gate.passwordFailed(ip("2001:db8:1:2::" + Integer.toHexString(i)));
        }
        assertTrue(gate.isLocked(ip("2001:db8:1:2::abcd")));
        assertFalse(gate.isLocked(ip("2001:db8:1:3::1")));
        clock.advance(Duration.ofMinutes(15).plusSeconds(1));
        assertFalse(gate.isLocked(ip("2001:db8:1:2::abcd")));
    }

    @Test
    void ipLockoutCanBeDisabled() {
        NetworkPolicyConfig d = NetworkPolicyConfig.DEFAULT;
        ConnectionGate gate = gate(new NetworkPolicyConfig(d.ping(), d.login(), d.unverified(),
                d.maxPendingLogins(), d.gateTimeoutSeconds(), false,
                d.ipv4Lockout(), d.ipv6Lockout(), List.of()));
        for (int i = 0; i < 200; i++) {
            gate.passwordFailed(natExit);
        }
        assertFalse(gate.isLocked(natExit));
    }

    @Test
    void trustedNetworksBypassAllIpLimits() {
        NetworkPolicyConfig d = NetworkPolicyConfig.DEFAULT;
        ConnectionGate gate = gate(new NetworkPolicyConfig(d.ping(), d.login(), d.unverified(),
                d.maxPendingLogins(), d.gateTimeoutSeconds(), true,
                d.ipv4Lockout(), d.ipv6Lockout(), List.of(Cidr.parse("203.0.113.0/24"))));
        for (int i = 0; i < 500; i++) {
            assertTrue(gate.allowPing(natExit));
            assertEquals(ConnectionGate.Verdict.ALLOW, gate.beginLogin(natExit));
            gate.endLogin(natExit, false);
            gate.passwordFailed(natExit);
        }
        assertFalse(gate.isLocked(natExit));
        // 网段之外照常限制
        InetAddress outside = ip("198.51.100.1");
        for (int i = 0; i < 20; i++) {
            gate.allowPing(outside);
        }
        assertFalse(gate.allowPing(outside));
    }

    @Test
    void globalPendingLimitCoversDistributedAddressesAndReleasesSlots() {
        NetworkPolicyConfig d = NetworkPolicyConfig.DEFAULT;
        ConnectionGate gate = gate(new NetworkPolicyConfig(d.ping(), d.login(), d.unverified(), 2,
                d.gateTimeoutSeconds(), d.ipLockoutEnabled(), d.ipv4Lockout(), d.ipv6Lockout(), List.of()));
        InetAddress first = ip("198.51.100.1");
        InetAddress second = ip("198.51.100.2");
        InetAddress third = ip("198.51.100.3");
        assertEquals(ConnectionGate.Verdict.ALLOW, gate.beginLogin(first));
        assertEquals(ConnectionGate.Verdict.ALLOW, gate.beginLogin(second));
        assertEquals(ConnectionGate.Verdict.SERVER_BUSY, gate.beginLogin(third));
        gate.rejectLogin(third);
        assertEquals(ConnectionGate.Verdict.SERVER_BUSY, gate.beginLogin(ip("198.51.100.4")));
        gate.endLogin(first, false);
        assertEquals(ConnectionGate.Verdict.ALLOW, gate.beginLogin(third));
    }

    @Test
    void opGuard() {
        assertTrue(OpGuard.suspendOp(true, false, false));
        assertTrue(OpGuard.suspendOp(true, true, true));
        assertFalse(OpGuard.suspendOp(true, false, true));
        assertFalse(OpGuard.suspendOp(false, true, false));
    }
}
