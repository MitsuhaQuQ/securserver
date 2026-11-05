package com.mtmrails.trustedserver.server.account;

import com.mtmrails.trustedserver.server.password.PasswordHasher;
import com.mtmrails.trustedserver.server.password.PasswordPolicy;
import java.time.Duration;
import java.util.Objects;

/**
 * 账号服务配置（默认值见 AGENTS.md 第 18 条）。
 *
 * @param hashThreads 同时进行 Argon2id 计算的线程数
 * @param hashQueue 哈希任务排队上限，排满时拒绝
 * @param cumulativeFailureLimit 同一账号跨连接累计密码错误达到该次数即锁定
 * @param lockoutDuration 锁定时长
 * @param auditRetention 审计日志保留期
 */
public record AccountServiceConfig(PasswordHasher.Params hashParams, PasswordPolicy policy, int hashThreads,
        int hashQueue, int cumulativeFailureLimit, Duration lockoutDuration, Duration auditRetention) {
    public static final AccountServiceConfig DEFAULT = new AccountServiceConfig(PasswordHasher.Params.DEFAULT,
            PasswordPolicy.DEFAULT, 4, 64, 10, Duration.ofMinutes(15), Duration.ofDays(90));

    public AccountServiceConfig {
        Objects.requireNonNull(hashParams, "hashParams");
        Objects.requireNonNull(policy, "policy");
        if (hashThreads < 1 || hashQueue < 1 || cumulativeFailureLimit < 1) {
            throw new IllegalArgumentException("thread, queue and failure limits must be positive");
        }
        if (lockoutDuration.isNegative() || lockoutDuration.isZero() || auditRetention.isNegative()
                || auditRetention.isZero()) {
            throw new IllegalArgumentException("durations must be positive");
        }
    }
}
