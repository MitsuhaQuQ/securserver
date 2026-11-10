package com.mtmrails.trustedserver.core.session;

import com.mtmrails.trustedserver.core.message.PasswordRequest;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * 服务端状态机访问账号的接口，由 core-server 的 AccountService 实现。
 *
 * <p>所有方法可能涉及 Argon2id 或数据库，必须在专用线程池上执行并返回 future，不得阻塞调用线程。
 * future 异常完成时，状态机按 {@link RejectReason#INTERNAL_ERROR} 拒绝；
 * 原因为 {@link java.util.concurrent.RejectedExecutionException}（线程池排满）时按 {@link RejectReason#SERVER_BUSY} 拒绝。
 */
public interface AccountGateway {
    /** 按账号 ID（正版为 UUID，离线为小写用户名）查找。 */
    CompletableFuture<Optional<AccountView>> find(String accountId);

    /**
     * 原子地为新账号绑定公钥，初始为受限、无密码。
     *
     * @return 账号已存在（被并发连接抢先）时为 {@code false}
     */
    CompletableFuture<Boolean> bindNew(String accountId, String username, byte[] playerPub);

    CompletableFuture<Boolean> verifyLoginPassword(String accountId, String password);

    CompletableFuture<Boolean> verifyRecoveryPassword(String accountId, String password);

    /**
     * 设定登录密码，并解除受限（PROTOCOL.md 6.1）。
     *
     * @return 密码不符合服务端规则时为 {@code false}，账号不变
     */
    CompletableFuture<Boolean> setLoginPassword(String accountId, String password);

    /** 把已通过正版 session 验证的账号改绑到新设备。 */
    CompletableFuture<Void> rebindOnline(String accountId, byte[] playerPub);

    /** 找回后保留原登录密码，仅当旧公钥仍匹配时改绑并记录审计。 */
    CompletableFuture<Boolean> rebindRecoveredKey(String accountId, byte[] expectedOldPub, byte[] newPub);

    /**
     * 管理员清空绑定后的重新绑定：仅当账号当前没有绑定公钥时原子地写入。
     *
     * @return 已被并发连接抢先绑定时为 {@code false}
     */
    CompletableFuture<Boolean> claimUnboundKey(String accountId, byte[] playerPub);

    /**
     * 使用一次性恢复授权原子地更新设备绑定和登录密码。
     * {@code expectedOldPub} 必须仍是数据库中的绑定，否则返回冲突。
     * CLEAR 时 {@code newPassword} 必须为空；SET 时由实现执行密码规则、与找回密码不同及 Argon2id 哈希。
     */
    CompletableFuture<RecoveryResult> recoverAccount(String accountId, byte[] expectedOldPub, byte[] newPub,
            PasswordChange change, String newPassword, RecoveryOrigin origin);

    /**
     * 记录一次密码错误。{@code exhausted} 为真表示本连接的尝试次数已用尽，实现应据此锁定。
     */
    CompletableFuture<Void> passwordFailed(String accountId, PasswordRequest.Kind kind, boolean exhausted);
}
