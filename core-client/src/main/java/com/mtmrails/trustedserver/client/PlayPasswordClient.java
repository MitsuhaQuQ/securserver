package com.mtmrails.trustedserver.client;

import com.mtmrails.trustedserver.core.crypto.CryptoException;
import com.mtmrails.trustedserver.core.crypto.SecureMessageChannel;
import com.mtmrails.trustedserver.core.message.Message;
import com.mtmrails.trustedserver.core.message.PasswordResult;
import com.mtmrails.trustedserver.core.message.SetPassword;
import com.mtmrails.trustedserver.core.message.SetRecoveryPassword;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import java.util.Objects;

/**
 * 游戏阶段密码通道的客户端一侧：持有从登录阶段移交来的同一个密码通道。同时只允许一个请求在途。
 * 解密失败或收到非法消息时通道已失去同步，上层应断开连接。非线程安全，须在客户端主线程使用。
 */
public final class PlayPasswordClient {
    private final SecureMessageChannel channel;
    private boolean awaiting;

    public PlayPasswordClient(SecureMessageChannel channel) {
        this.channel = Objects.requireNonNull(channel, "channel");
    }

    /** 是否有请求正在等待服务端结果（界面应提示“请稍候”）。 */
    public boolean awaitingResult() {
        return awaiting;
    }

    /**
     * 加密一条设定请求，返回要发送的 payload。
     *
     * @throws IllegalStateException 已有请求在途
     * @throws IllegalArgumentException 密码超出协议限制
     */
    public byte[] request(PasswordCommand.Set command) throws CryptoException {
        if (awaiting) {
            throw new IllegalStateException("a password request is already in progress");
        }
        Message message = command.kind() == PasswordCommand.Kind.LOGIN
                ? new SetPassword(command.password())
                : new SetRecoveryPassword(command.password());
        byte[] payload = channel.seal(message);
        awaiting = true;
        return payload;
    }

    /** 收到服务端发来的密码通道 payload。 */
    public PasswordResult onPayload(byte[] payload) throws CryptoException, MalformedMessageException {
        Message message = channel.open(payload);
        if (!(message instanceof PasswordResult result)) {
            channel.close();
            throw new MalformedMessageException("unexpected " + message.type() + " on play-phase password channel");
        }
        awaiting = false;
        return result;
    }

    public void close() {
        channel.close();
    }
}
