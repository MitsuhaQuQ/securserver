package com.mtmrails.trustedserver.core.session;

import com.mtmrails.trustedserver.core.message.PasswordRequest;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * 服务端状态机访问账号的接口，由 core-server 的 AccountService 实现。
 *
 * <p>所有方法可能涉及 Argon2id 或数据库，必须在专用线程池上执行并返回 future，不得阻塞调用线程。
 * future 异常完成时，状态机按 {@link RejectReason#INTERNAL_ERROR} 拒绝。
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

    /** 设定登录密码，并解除受限（PROTOCOL.md 6.1）。 */
    CompletableFuture<Void> setLoginPassword(String accountId, String password);

    /** 把账号改绑到新公钥（找回流程，或正版模式下的新设备）。 */
    CompletableFuture<Void> rebind(String accountId, byte[] playerPub, RebindReason reason);

    /**
     * 记录一次密码错误。{@code exhausted} 为真表示本连接的尝试次数已用尽，实现应据此锁定。
     */
    CompletableFuture<Void> passwordFailed(String accountId, PasswordRequest.Kind kind, boolean exhausted);
}
