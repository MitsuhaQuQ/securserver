package com.mtmrails.trustedserver.server.policy;

import java.time.Duration;
import java.util.Objects;

/** IP 维度的密码错误锁定参数：{@code window} 内累计 {@code failures} 次，锁定 {@code lockFor}。 */
public record IpLockout(int failures, Duration window, Duration lockFor) {
    public IpLockout {
        Objects.requireNonNull(window, "window");
        Objects.requireNonNull(lockFor, "lockFor");
        if (failures < 1 || window.isNegative() || window.isZero() || lockFor.isNegative() || lockFor.isZero()) {
            throw new IllegalArgumentException("lockout values must be positive");
        }
    }
}
