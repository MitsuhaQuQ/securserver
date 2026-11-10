package com.mtmrails.trustedserver.core.message;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;

/**
 * C→S，密码通道：对 {@link PasswordRequest} 的回答（PROTOCOL.md 4.8）。
 * 动作与密码分开编码，避免把“跳过”“请求重设”“清除密码”混成空字符串。
 */
public record PasswordAnswer(Action action, String password) implements PasswordMessage {
    public enum Action {
        SUBMIT(0),
        SKIP(1),
        REQUEST_RESET(2),
        CLEAR(3);

        private final int id;

        Action(int id) {
            this.id = id;
        }

        int id() {
            return id;
        }

        static Action fromId(int id) throws MalformedMessageException {
            for (Action action : values()) {
                if (action.id == id) return action;
            }
            throw new MalformedMessageException("unknown password answer action: " + id);
        }
    }

    public PasswordAnswer {
        if (action == null) throw new NullPointerException("action");
        Limits.checkPassword(password, action != Action.SUBMIT);
        if (action == Action.SUBMIT && password.isEmpty()) {
            throw new IllegalArgumentException("SUBMIT requires a password");
        }
        if (action != Action.SUBMIT && action != Action.REQUEST_RESET && !password.isEmpty()) {
            throw new IllegalArgumentException(action + " must not carry a password");
        }
    }

    /** 旧调用点的便利构造；空串明确映射为 SKIP，而不是隐式协议语义。 */
    public PasswordAnswer(String password) {
        this(password.isEmpty() ? Action.SKIP : Action.SUBMIT, password);
    }

    public static PasswordAnswer requestReset() {
        return new PasswordAnswer(Action.REQUEST_RESET, "");
    }

    public static PasswordAnswer clear() {
        return new PasswordAnswer(Action.CLEAR, "");
    }

    /** 是否为“跳过”（空密码）。 */
    public boolean skipped() {
        return action == Action.SKIP;
    }

    @Override
    public MessageType type() {
        return MessageType.PASSWORD_ANSWER;
    }

    @Override
    public void writeBody(WireWriter out) {
        out.u8(action.id()).string(password, Limits.MAX_PASSWORD_BYTES);
    }

    static PasswordAnswer read(WireReader in) throws MalformedMessageException {
        return new PasswordAnswer(Action.fromId(in.u8()), in.string(Limits.MAX_PASSWORD_BYTES));
    }

    @Override
    public String toString() {
        return "PasswordAnswer[action=" + action + ", password=<redacted>]";
    }
}
