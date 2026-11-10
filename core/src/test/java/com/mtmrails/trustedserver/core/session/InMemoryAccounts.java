package com.mtmrails.trustedserver.core.session;

import com.mtmrails.trustedserver.core.message.PasswordRequest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;

/**
 * 测试用账号存储：明文比较密码（真实实现用 Argon2id），可选用另一线程完成 future 以模拟线程池。
 */
final class InMemoryAccounts implements AccountGateway {
    static final class Account {
        byte[] playerPub;
        boolean restricted = true;
        String loginPassword;
        String recoveryPassword;

        Account(byte[] playerPub) {
            this.playerPub = playerPub == null ? null : playerPub.clone();
        }

        AccountView view() {
            return new AccountView(playerPub, restricted, loginPassword != null, recoveryPassword != null);
        }
    }

    record Failure(String accountId, PasswordRequest.Kind kind, boolean exhausted) {
    }

    final Map<String, Account> accounts = new ConcurrentHashMap<>();
    final List<Failure> failures = new ArrayList<>();
    final List<String> rebinds = new ArrayList<>();
    final List<RebindReason> rebindReasons = new ArrayList<>();
    private final Executor executor;
    boolean failNextCall;
    /** 模拟并发连接抢先绑定：bindNew 一律返回 false。 */
    boolean loseBindRace;
    boolean loseRecoveryRace;
    /** 模拟服务端密码规则：短于该长度的登录密码被拒绝。 */
    int minPasswordLength;

    InMemoryAccounts(Executor executor) {
        this.executor = executor;
    }

    InMemoryAccounts() {
        this(Runnable::run);
    }

    Account put(String accountId, byte[] playerPub, boolean restricted, String loginPassword, String recoveryPassword) {
        Account account = new Account(playerPub);
        account.restricted = restricted;
        account.loginPassword = loginPassword;
        account.recoveryPassword = recoveryPassword;
        accounts.put(accountId, account);
        return account;
    }

    private <T> CompletableFuture<T> async(java.util.function.Supplier<T> body) {
        if (failNextCall) {
            failNextCall = false;
            return CompletableFuture.failedFuture(new IllegalStateException("storage failure"));
        }
        return CompletableFuture.supplyAsync(body, executor);
    }

    @Override
    public CompletableFuture<Optional<AccountView>> find(String accountId) {
        return async(() -> Optional.ofNullable(accounts.get(accountId)).map(Account::view));
    }

    @Override
    public CompletableFuture<Boolean> bindNew(String accountId, String username, byte[] playerPub) {
        return async(() -> !loseBindRace && accounts.putIfAbsent(accountId, new Account(playerPub)) == null);
    }

    @Override
    public CompletableFuture<Boolean> verifyLoginPassword(String accountId, String password) {
        return async(() -> password.equals(accounts.get(accountId).loginPassword));
    }

    @Override
    public CompletableFuture<Boolean> verifyRecoveryPassword(String accountId, String password) {
        return async(() -> password.equals(accounts.get(accountId).recoveryPassword));
    }

    @Override
    public CompletableFuture<Boolean> setLoginPassword(String accountId, String password) {
        return async(() -> {
            if (password.length() < minPasswordLength) {
                return false;
            }
            Account account = accounts.get(accountId);
            account.loginPassword = password;
            account.restricted = false;
            return true;
        });
    }

    @Override
    public CompletableFuture<Boolean> claimUnboundKey(String accountId, byte[] playerPub) {
        return async(() -> {
            Account account = accounts.get(accountId);
            synchronized (account) {
                if (loseBindRace || account.playerPub != null) {
                    return false;
                }
                account.playerPub = playerPub.clone();
                return true;
            }
        });
    }

    @Override
    public CompletableFuture<Void> rebindOnline(String accountId, byte[] playerPub) {
        return async(() -> {
            accounts.get(accountId).playerPub = playerPub.clone();
            synchronized (rebinds) {
                rebinds.add(accountId);
                rebindReasons.add(RebindReason.ONLINE_MODE_IDENTITY);
            }
            return null;
        });
    }

    @Override
    public CompletableFuture<Boolean> rebindRecoveredKey(String accountId, byte[] expectedOldPub, byte[] newPub) {
        return async(() -> {
            Account account = accounts.get(accountId);
            synchronized (account) {
                if (loseRecoveryRace || !java.util.Arrays.equals(account.playerPub, expectedOldPub)) {
                    return false;
                }
                account.playerPub = newPub.clone();
                synchronized (rebinds) {
                    rebinds.add(accountId);
                    rebindReasons.add(RebindReason.RECOVERY);
                }
                return true;
            }
        });
    }

    @Override
    public CompletableFuture<RecoveryResult> recoverAccount(String accountId, byte[] expectedOldPub, byte[] newPub,
            PasswordChange change, String newPassword, RecoveryOrigin origin) {
        return async(() -> {
            Account account = accounts.get(accountId);
            synchronized (account) {
                if (loseRecoveryRace || !java.util.Arrays.equals(account.playerPub, expectedOldPub)) {
                    return RecoveryResult.ACCOUNT_CONFLICT;
                }
                if (change == PasswordChange.SET
                        && (newPassword.length() < minPasswordLength
                                || newPassword.equals(account.recoveryPassword))) {
                    return RecoveryResult.PASSWORD_REJECTED;
                }
                account.playerPub = newPub.clone();
                if (change == PasswordChange.SET) {
                    account.loginPassword = newPassword;
                    account.restricted = false;
                } else {
                    account.loginPassword = null;
                    account.restricted = true;
                }
                synchronized (rebinds) {
                    if (!java.util.Arrays.equals(expectedOldPub, newPub)) {
                        rebinds.add(accountId);
                        rebindReasons.add(RebindReason.RECOVERY);
                    }
                }
                return RecoveryResult.OK;
            }
        });
    }

    @Override
    public CompletableFuture<Void> passwordFailed(String accountId, PasswordRequest.Kind kind, boolean exhausted) {
        return async(() -> {
            synchronized (failures) {
                failures.add(new Failure(accountId, kind, exhausted));
            }
            return null;
        });
    }
}
