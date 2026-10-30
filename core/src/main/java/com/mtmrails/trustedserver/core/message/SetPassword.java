package com.mtmrails.trustedserver.core.message;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;

/**
 * C→S，密码通道（游戏阶段）：{@code /passwd} 设定登录密码（PROTOCOL.md 第 6 节）。
 * 两次输入是否一致由客户端在本地校验，这里只携带最终密码。
 */
public record SetPassword(String password) implements PasswordMessage {
    public SetPassword {
        Limits.checkPassword(password, false);
    }

    @Override
    public MessageType type() {
        return MessageType.SET_PASSWORD;
    }

    @Override
    public void writeBody(WireWriter out) {
        out.string(password, Limits.MAX_PASSWORD_BYTES);
    }

    static SetPassword read(WireReader in) throws MalformedMessageException {
        return new SetPassword(in.string(Limits.MAX_PASSWORD_BYTES));
    }

    @Override
    public String toString() {
        return "SetPassword[password=<redacted>]";
    }
}
