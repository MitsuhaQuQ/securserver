package com.mtmrails.trustedserver.server.account;

import com.mtmrails.trustedserver.core.message.PasswordRequest;
import com.mtmrails.trustedserver.core.message.PasswordResult;
import com.mtmrails.trustedserver.core.session.AccountGateway;
import com.mtmrails.trustedserver.core.session.AccountView;
import com.mtmrails.trustedserver.core.session.PasswordChange;
import com.mtmrails.trustedserver.core.session.RecoveryOrigin;
import com.mtmrails.trustedserver.core.session.RecoveryResult;
import com.mtmrails.trustedserver.server.password.PasswordHasher;
import com.mtmrails.trustedserver.server.store.Account;
import com.mtmrails.trustedserver.server.store.AuditEvent;
import com.mtmrails.trustedserver.server.store.SqliteStore;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * 服务端账号服务：实现状态机的 {@link AccountGateway}，并提供游戏内设密码、管理员命令和登录记录。
 *
 * <p>线程：Argon2id 在固定大小的哈希线程池上执行（排满时以 {@link RejectedExecutionException} 失败，
 * 状态机据此按“服务器繁忙”拒绝）；所有数据库操作在单一数据库线程上串行执行。方法均不阻塞调用线程。
 *
 * <p>锁定：账号处于锁定期时，密码校验直接判为错误，不做哈希计算。单个连接的尝试次数用尽，或跨连接累计错误达到
 * 上限，即锁定；{@link #recordLogin} 时清零累计。IP 维度的锁定与锁定期内的连接拦截由策略层实现。
 */
public final class AccountService implements AccountGateway, AutoCloseable {
    private final SqliteStore store;
    private final PasswordHasher hasher;
    private final AccountServiceConfig config;
    private final Clock clock;
    private final ExecutorService dbExecutor;
    private final ThreadPoolExecutor hashExecutor;

    private AccountService(SqliteStore store, AccountServiceConfig config, Clock clock, SecureRandom random) {
        this.store = store;
        this.config = config;
        this.clock = clock;
        this.hasher = new PasswordHasher(config.hashParams(), random);
        this.dbExecutor = Executors.newSingleThreadExecutor(daemon("trustedserver-db"));
        this.hashExecutor = new ThreadPoolExecutor(config.hashThreads(), config.hashThreads(), 0, TimeUnit.SECONDS,
                new ArrayBlockingQueue<>(config.hashQueue()), daemon("trustedserver-hash"),
                new ThreadPoolExecutor.AbortPolicy());
    }

    /** 打开（必要时创建并迁移）数据库。 */
    public static AccountService open(Path database, AccountServiceConfig config, Clock clock, SecureRandom random) {
        return new AccountService(SqliteStore.open(database), config, clock, random);
    }

    private static java.util.concurrent.ThreadFactory daemon(String prefix) {
        AtomicInteger counter = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable, prefix + "-" + counter.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }

    // ================= AccountGateway =================

    @Override
    public CompletableFuture<Optional<AccountView>> find(String accountId) {
        return db(() -> store.find(accountId).map(a -> new AccountView(a.playerPub(), a.restricted(),
                a.passwordHash() != null, a.recoveryHash() != null)));
    }

    @Override
    public CompletableFuture<Boolean> bindNew(String accountId, String username, byte[] playerPub) {
        return db(() -> {
            boolean inserted = store.insertNew(accountId, username, playerPub, now());
            if (inserted) {
                store.audit(now(), accountId, AuditEvent.BIND, null, null);
            }
            return inserted;
        });
    }

    @Override
    public CompletableFuture<Boolean> verifyLoginPassword(String accountId, String password) {
        return verify(accountId, password, Account::passwordHash, true);
    }

    @Override
    public CompletableFuture<Boolean> verifyRecoveryPassword(String accountId, String password) {
        return verify(accountId, password, Account::recoveryHash, false);
    }

    private CompletableFuture<Boolean> verify(String accountId, String password, Function<Account, String> hashOf,
            boolean login) {
        return db(() -> isLockedNow(accountId) ? Optional.<String>empty()
                : store.find(accountId).map(hashOf))
                .thenCompose(hash -> hash.isEmpty()
                        ? CompletableFuture.completedFuture(false)
                        : hash(() -> hasher.verify(password, hash.get())).thenCompose(ok -> {
                            if (ok && hasher.needsRehash(hash.get())) {
                                return rehash(accountId, password, login).thenApply(v -> true);
                            }
                            return CompletableFuture.completedFuture(ok);
                        }));
    }

    /** 参数调整后，校验成功时用当前参数重新哈希；只替换哈希，不改变受限状态。 */
    private CompletableFuture<Void> rehash(String accountId, String password, boolean login) {
        return hash(() -> hasher.hash(password)).thenCompose(newHash -> db(() -> {
            if (login) {
                store.find(accountId).ifPresent(a -> {
                    boolean restricted = a.restricted();
                    store.setPasswordHash(accountId, newHash);
                    store.setRestricted(accountId, restricted);
                });
            } else {
                store.setRecoveryHash(accountId, newHash);
            }
            return null;
        }));
    }

    @Override
    public CompletableFuture<Boolean> setLoginPassword(String accountId, String password) {
        return setPassword(accountId, password, true).thenApply(result -> result.status() == PasswordResult.Status.OK);
    }

    @Override
    public CompletableFuture<Void> rebindOnline(String accountId, byte[] playerPub) {
        return db(() -> {
            if (!store.setPlayerPub(accountId, playerPub)) {
                throw new IllegalStateException("account " + accountId + " disappeared during rebind");
            }
            store.audit(now(), accountId, AuditEvent.ONLINE_REBIND, null, null);
            return null;
        });
    }

    @Override
    public CompletableFuture<Boolean> rebindRecoveredKey(String accountId, byte[] expectedOldPub, byte[] newPub) {
        return db(() -> store.recoverAccount(accountId, expectedOldPub, newPub,
                SqliteStore.PasswordMutation.KEEP, null, now(), AuditEvent.RECOVERY_REBIND));
    }

    @Override
    public CompletableFuture<Boolean> claimUnboundKey(String accountId, byte[] playerPub) {
        return db(() -> {
            boolean claimed = store.claimUnboundKey(accountId, playerPub);
            if (claimed) {
                store.audit(now(), accountId, AuditEvent.BIND_AFTER_RESET, null, null);
            }
            return claimed;
        });
    }

    @Override
    public CompletableFuture<RecoveryResult> recoverAccount(String accountId, byte[] expectedOldPub, byte[] newPub,
            PasswordChange change, String newPassword, RecoveryOrigin origin) {
        if (origin == RecoveryOrigin.ONLINE_SESSION_AND_KEY
                && !java.util.Arrays.equals(expectedOldPub, newPub)) {
            return CompletableFuture.completedFuture(RecoveryResult.ACCOUNT_CONFLICT);
        }
        if (change == PasswordChange.CLEAR) {
            if (!newPassword.isEmpty()) {
                return CompletableFuture.completedFuture(RecoveryResult.PASSWORD_REJECTED);
            }
            return commitRecovery(accountId, expectedOldPub, newPub, change, null, origin);
        }
        Optional<String> lengthProblem = config.policy().checkLength(newPassword);
        if (lengthProblem.isPresent()) {
            return CompletableFuture.completedFuture(RecoveryResult.PASSWORD_REJECTED);
        }
        return db(() -> store.find(accountId).map(Account::recoveryHash)).thenCompose(recoveryHash -> {
            CompletableFuture<Boolean> sameAsRecovery = recoveryHash.isEmpty()
                    ? CompletableFuture.completedFuture(false)
                    : hash(() -> hasher.verify(newPassword, recoveryHash.get()));
            return sameAsRecovery.thenCompose(same -> {
                if (same) {
                    return CompletableFuture.completedFuture(RecoveryResult.PASSWORD_REJECTED);
                }
                return hash(() -> hasher.hash(newPassword)).thenCompose(newHash ->
                        commitRecovery(accountId, expectedOldPub, newPub, change, newHash, origin));
            });
        });
    }

    private CompletableFuture<RecoveryResult> commitRecovery(String accountId, byte[] expectedOldPub, byte[] newPub,
            PasswordChange change, String newHash, RecoveryOrigin origin) {
        return db(() -> {
            AuditEvent event = origin == RecoveryOrigin.ONLINE_SESSION_AND_KEY
                    ? AuditEvent.ONLINE_PASSWORD_RESET : AuditEvent.RECOVERY_PASSWORD_RESET;
            SqliteStore.PasswordMutation mutation = change == PasswordChange.SET
                    ? SqliteStore.PasswordMutation.SET : SqliteStore.PasswordMutation.CLEAR;
            return store.recoverAccount(accountId, expectedOldPub, newPub, mutation, newHash, now(), event)
                    ? RecoveryResult.OK : RecoveryResult.ACCOUNT_CONFLICT;
        });
    }

    @Override
    public CompletableFuture<Void> passwordFailed(String accountId, PasswordRequest.Kind kind, boolean exhausted) {
        return db(() -> {
            store.audit(now(), accountId, AuditEvent.LOGIN_FAIL, null, kind.name());
            int failures = store.addFailure(subject(accountId));
            if (exhausted || failures >= config.cumulativeFailureLimit()) {
                store.lockUntil(subject(accountId), now() + config.lockoutDuration().toMillis());
                store.audit(now(), accountId, AuditEvent.LOCKOUT, null,
                        exhausted ? "attempts exhausted" : "cumulative failures " + failures);
            }
            return null;
        });
    }

    // ================= 登录与锁定 =================

    /** 认证放行后由上层调用：更新最近登录信息，清零累计错误。 */
    public CompletableFuture<Void> recordLogin(String accountId, String username, String ip) {
        return db(() -> {
            store.recordLogin(accountId, username, ip, now());
            store.clearLockout(subject(accountId));
            store.audit(now(), accountId, AuditEvent.LOGIN_OK, ip, null);
            return null;
        });
    }

    /** 账号是否处于锁定期（策略层在握手前检查）。 */
    public CompletableFuture<Boolean> isLocked(String accountId) {
        return db(() -> isLockedNow(accountId));
    }

    private boolean isLockedNow(String accountId) {
        return store.lockedUntil(subject(accountId)).map(until -> until > now()).orElse(false);
    }

    private static String subject(String accountId) {
        return "name:" + accountId;
    }

    // ================= 游戏内 /passwd、/recoverypasswd =================

    /** 游戏内设定登录密码（解除受限）。哈希线程池排满时返回 RATE_LIMITED。 */
    public CompletableFuture<PasswordResult> setLoginPasswordInGame(String accountId, String password) {
        return orBusy(setPassword(accountId, password, true));
    }

    /** 游戏内设定找回密码。 */
    public CompletableFuture<PasswordResult> setRecoveryPasswordInGame(String accountId, String password) {
        return orBusy(setPassword(accountId, password, false));
    }

    private CompletableFuture<PasswordResult> setPassword(String accountId, String password, boolean login) {
        Optional<String> lengthProblem = config.policy().checkLength(password);
        if (lengthProblem.isPresent()) {
            return CompletableFuture.completedFuture(
                    new PasswordResult(PasswordResult.Status.REJECTED, lengthProblem.get()));
        }
        return db(() -> store.find(accountId)).thenCompose(account -> {
            if (account.isEmpty()) {
                return CompletableFuture.completedFuture(new PasswordResult(PasswordResult.Status.ERROR, "账号不存在"));
            }
            String otherHash = login ? account.get().recoveryHash() : account.get().passwordHash();
            CompletableFuture<Boolean> sameAsOther = otherHash == null
                    ? CompletableFuture.completedFuture(false)
                    : hash(() -> hasher.verify(password, otherHash));
            return sameAsOther.thenCompose(same -> {
                if (same) {
                    return CompletableFuture.completedFuture(
                            new PasswordResult(PasswordResult.Status.REJECTED, "登录密码与找回密码不能相同"));
                }
                return hash(() -> hasher.hash(password)).thenCompose(newHash -> db(() -> {
                    boolean updated = login ? store.setPasswordHash(accountId, newHash)
                            : store.setRecoveryHash(accountId, newHash);
                    if (!updated) {
                        return new PasswordResult(PasswordResult.Status.ERROR, "账号不存在");
                    }
                    store.audit(now(), accountId, login ? AuditEvent.SET_PASSWORD : AuditEvent.SET_RECOVERY,
                            null, null);
                    return new PasswordResult(PasswordResult.Status.OK, login ? "登录密码已设定" : "找回密码已设定");
                }));
            });
        });
    }

    private static CompletableFuture<PasswordResult> orBusy(CompletableFuture<PasswordResult> future) {
        return future.exceptionally(t -> {
            Throwable cause = t instanceof CompletionException && t.getCause() != null ? t.getCause() : t;
            if (cause instanceof RejectedExecutionException) {
                return new PasswordResult(PasswordResult.Status.RATE_LIMITED, "服务器繁忙，请稍后再试");
            }
            return new PasswordResult(PasswordResult.Status.ERROR, "服务器内部错误");
        });
    }

    // ================= 控制台管理员命令 =================

    /** {@code reset key}：清空设备绑定，保留密码与受限状态。 */
    public CompletableFuture<AdminResult> resetKey(String accountId) {
        return admin(accountId, AuditEvent.RESET_KEY, () -> store.clearKey(accountId));
    }

    /** {@code reset password}：清除登录密码并恢复受限。 */
    public CompletableFuture<AdminResult> resetPassword(String accountId) {
        return admin(accountId, AuditEvent.RESET_PASSWORD, () -> store.clearPassword(accountId));
    }

    /** {@code reset recovery}：清除找回密码。 */
    public CompletableFuture<AdminResult> resetRecovery(String accountId) {
        return admin(accountId, AuditEvent.RESET_RECOVERY, () -> store.clearRecovery(accountId));
    }

    /** {@code reset all}：删除整个账号，下次按新用户处理。 */
    public CompletableFuture<AdminResult> resetAll(String accountId) {
        return admin(accountId, AuditEvent.RESET_ALL, () -> {
            boolean deleted = store.delete(accountId);
            store.clearLockout(subject(accountId));
            return deleted;
        });
    }

    /** {@code trust}：解除受限。 */
    public CompletableFuture<AdminResult> trust(String accountId) {
        return admin(accountId, AuditEvent.TRUST, () -> store.setRestricted(accountId, false));
    }

    private CompletableFuture<AdminResult> admin(String accountId, AuditEvent event, Supplier<Boolean> action) {
        return db(() -> {
            if (!action.get()) {
                return AdminResult.NO_SUCH_ACCOUNT;
            }
            store.audit(now(), accountId, event, null, "console");
            return AdminResult.DONE;
        });
    }

    // ================= 维护 =================

    /** 删除超过保留期的审计记录，返回删除条数。由上层定期调用（例如启动时和每天一次）。 */
    public CompletableFuture<Integer> purgeOldAudit() {
        return db(() -> store.purgeAuditBefore(now() - config.auditRetention().toMillis()));
    }

    /** 仅供测试与诊断：在数据库线程上读取存储。 */
    <T> CompletableFuture<T> inspect(Function<SqliteStore, T> reader) {
        return db(() -> reader.apply(store));
    }

    @Override
    public void close() {
        hashExecutor.shutdown();
        dbExecutor.submit(store::close);
        dbExecutor.shutdown();
        try {
            hashExecutor.awaitTermination(10, TimeUnit.SECONDS);
            dbExecutor.awaitTermination(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private long now() {
        return clock.millis();
    }

    private <T> CompletableFuture<T> db(Supplier<T> body) {
        return CompletableFuture.supplyAsync(body, dbExecutor);
    }

    private <T> CompletableFuture<T> hash(Supplier<T> body) {
        return CompletableFuture.supplyAsync(body, hashExecutor);
    }
}
