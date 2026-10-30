package com.mtmrails.trustedserver.core.message;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;

/** C→S，密码通道（游戏阶段）：{@code /recoverypasswd} 设定找回密码（PROTOCOL.md 第 6 节）。 */
public record SetRecoveryPassword(String password) implements PasswordMessage {
    public SetRecoveryPassword {
        Limits.checkPassword(password, false);
    }

    @Override
    public MessageType type() {
        return MessageType.SET_RECOVERY_PASSWORD;
    }

    @Override
    public void writeBody(WireWriter out) {
        out.string(password, Limits.MAX_PASSWORD_BYTES);
    }

    static SetRecoveryPassword read(WireReader in) throws MalformedMessageException {
        return new SetRecoveryPassword(in.string(Limits.MAX_PASSWORD_BYTES));
    }

    @Override
    public String toString() {
        return "SetRecoveryPassword[password=<redacted>]";
    }
}
