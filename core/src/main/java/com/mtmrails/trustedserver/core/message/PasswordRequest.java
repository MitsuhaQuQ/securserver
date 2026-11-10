package com.mtmrails.trustedserver.core.message;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;
import java.util.Objects;

/** S→C，密码通道：要求客户端弹出密码输入框（PROTOCOL.md 4.7）。 */
public record PasswordRequest(Kind kind, int attemptsLeft, int timeoutSec) implements PasswordMessage {
    public enum Kind {
        /** 输入登录密码。 */
        LOGIN(1),
        /** 输入找回密码，成功后改绑到当前设备的密钥。 */
        RECOVERY(2),
        /** 设定登录密码，可跳过。 */
        SET(3),
        /** 已取得一次性恢复授权后，设置或清除登录密码。 */
        RESET(4);

        private final int id;

        Kind(int id) {
            this.id = id;
        }

        public int id() {
            return id;
        }

        static Kind fromId(int id) throws MalformedMessageException {
            for (Kind kind : values()) {
                if (kind.id == id) {
                    return kind;
                }
            }
            throw new MalformedMessageException("unknown password request kind: " + id);
        }
    }

    public PasswordRequest {
        Objects.requireNonNull(kind, "kind");
        if (attemptsLeft < 0 || attemptsLeft > 0xFF) {
            throw new IllegalArgumentException("attemptsLeft out of range: " + attemptsLeft);
        }
        if ((kind == Kind.SET || kind == Kind.RESET) && attemptsLeft != 0) {
            throw new IllegalArgumentException("attemptsLeft must be 0 for " + kind);
        }
        if (timeoutSec < 1 || timeoutSec > 0xFFFF) {
            throw new IllegalArgumentException("timeoutSec out of range: " + timeoutSec);
        }
    }

    @Override
    public MessageType type() {
        return MessageType.PASSWORD_REQUEST;
    }

    @Override
    public void writeBody(WireWriter out) {
        out.u8(kind.id()).u8(attemptsLeft).u16(timeoutSec);
    }

    static PasswordRequest read(WireReader in) throws MalformedMessageException {
        return new PasswordRequest(Kind.fromId(in.u8()), in.u8(), in.u16());
    }
}
