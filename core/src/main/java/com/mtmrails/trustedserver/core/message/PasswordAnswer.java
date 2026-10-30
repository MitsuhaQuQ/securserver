package com.mtmrails.trustedserver.core.message;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;

/**
 * C→S，密码通道：对 {@link PasswordRequest} 的回答（PROTOCOL.md 4.8）。
 * 空密码只对 SET 有意义，表示玩家选择跳过。
 */
public record PasswordAnswer(String password) implements PasswordMessage {
    public PasswordAnswer {
        Limits.checkPassword(password, true);
    }

    /** 是否为“跳过”（空密码）。 */
    public boolean skipped() {
        return password.isEmpty();
    }

    @Override
    public MessageType type() {
        return MessageType.PASSWORD_ANSWER;
    }

    @Override
    public void writeBody(WireWriter out) {
        out.string(password, Limits.MAX_PASSWORD_BYTES);
    }

    static PasswordAnswer read(WireReader in) throws MalformedMessageException {
        return new PasswordAnswer(in.string(Limits.MAX_PASSWORD_BYTES));
    }

    @Override
    public String toString() {
        return "PasswordAnswer[password=<redacted>]";
    }
}
