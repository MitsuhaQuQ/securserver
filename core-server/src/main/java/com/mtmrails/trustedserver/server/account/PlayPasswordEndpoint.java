package com.mtmrails.trustedserver.server.account;

import com.mtmrails.trustedserver.core.crypto.CryptoException;
import com.mtmrails.trustedserver.core.crypto.SecureMessageChannel;
import com.mtmrails.trustedserver.core.message.Message;
import com.mtmrails.trustedserver.core.message.PasswordResult;
import com.mtmrails.trustedserver.core.message.SetPassword;
import com.mtmrails.trustedserver.core.message.SetRecoveryPassword;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * 游戏阶段密码通道的服务端一侧（PROTOCOL.md 第 6 节）：每个在线玩家一个实例，持有从登录阶段移交来的密码通道。
 *
 * <ul>
 *   <li>只接受 SetPassword / SetRecoveryPassword；其他类型、解密失败或格式错误都踢出玩家，不再尝试解密（4.3.3）
 *   <li>同一玩家同时只处理一个请求，且每分钟最多 {@link #MAX_REQUESTS_PER_MINUTE} 次；超出返回 RATE_LIMITED
 *   <li>加密和发送在同一把锁内完成，保证发出顺序与序号一致；上层的 {@link Listener#send} 须按调用顺序写出
 * </ul>
 */
public final class PlayPasswordEndpoint {
    public static final int MAX_REQUESTS_PER_MINUTE = 5;

    /** 由适配层实现。回调可能在账号服务的线程上调用。 */
    public interface Listener {
        /** 发出一条已加密的密码通道 payload（游戏阶段自定义数据包）。 */
        void send(byte[] payload);

        /** 密码已设定。{@code login} 为真时账号已解除受限，适配层应解除游戏内限制并恢复 OP。 */
        void passwordSet(boolean login);

        /** 通道已失去同步或收到非法消息：以统一拒绝文本踢出玩家。 */
        void kick();
    }

    private final String accountId;
    private final SecureMessageChannel channel;
    private final AccountService accounts;
    private final Listener listener;
    private final Clock clock;
    private final boolean loginEnabled;
    private final boolean recoveryEnabled;
    private final Deque<Long> recent = new ArrayDeque<>();
    private boolean inFlight;
    private boolean closed;

    public PlayPasswordEndpoint(String accountId, SecureMessageChannel channel, AccountService accounts,
            Listener listener, Clock clock) {
        this(accountId, channel, accounts, listener, clock, true, true);
    }

    public PlayPasswordEndpoint(String accountId, SecureMessageChannel channel, AccountService accounts,
            Listener listener, Clock clock, boolean loginEnabled, boolean recoveryEnabled) {
        this.accountId = Objects.requireNonNull(accountId, "accountId");
        this.channel = Objects.requireNonNull(channel, "channel");
        this.accounts = Objects.requireNonNull(accounts, "accounts");
        this.listener = Objects.requireNonNull(listener, "listener");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.loginEnabled = loginEnabled;
        this.recoveryEnabled = recoveryEnabled;
    }

    /** 收到客户端发来的密码通道 payload。 */
    public void onPayload(byte[] payload) {
        Message message;
        synchronized (this) {
            if (closed) {
                return;
            }
            try {
                message = channel.open(payload);
            } catch (CryptoException | MalformedMessageException e) {
                kick();
                return;
            }
            if (!(message instanceof SetPassword) && !(message instanceof SetRecoveryPassword)) {
                kick();
                return;
            }
            if ((message instanceof SetPassword && !loginEnabled)
                    || (message instanceof SetRecoveryPassword && !recoveryEnabled)) {
                reply(new PasswordResult(PasswordResult.Status.REJECTED, "此密码验证层未启用"));
                return;
            }
            if (inFlight || !withinRate()) {
                reply(new PasswordResult(PasswordResult.Status.RATE_LIMITED, "操作过于频繁，请稍后再试"));
                return;
            }
            inFlight = true;
        }
        boolean login = message instanceof SetPassword;
        CompletableFuture<PasswordResult> result = login
                ? accounts.setLoginPasswordInGame(accountId, ((SetPassword) message).password())
                : accounts.setRecoveryPasswordInGame(accountId, ((SetRecoveryPassword) message).password());
        result.whenComplete((r, t) -> {
            PasswordResult outcome = r != null ? r : new PasswordResult(PasswordResult.Status.ERROR, "服务器内部错误");
            synchronized (this) {
                inFlight = false;
                if (closed) {
                    return;
                }
                if (outcome.status() == PasswordResult.Status.OK) {
                    // 先通知适配层更新权限，再发送成功响应。
                    listener.passwordSet(login);
                }
                reply(outcome);
            }
        });
    }

    /** 玩家下线：废弃通道。 */
    public synchronized void close() {
        closed = true;
        channel.close();
    }

    private boolean withinRate() {
        long now = clock.millis();
        while (!recent.isEmpty() && recent.peekFirst() <= now - 60_000) {
            recent.removeFirst();
        }
        if (recent.size() >= MAX_REQUESTS_PER_MINUTE) {
            return false;
        }
        recent.addLast(now);
        return true;
    }

    /** 调用方须持有本对象的锁。 */
    private void reply(PasswordResult result) {
        try {
            listener.send(channel.seal(result));
        } catch (CryptoException e) {
            kick();
        }
    }

    private void kick() {
        closed = true;
        channel.close();
        listener.kick();
    }
}
