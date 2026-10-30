package com.mtmrails.trustedserver.core.message;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;
import java.util.Objects;

/** S→C，密码通道（游戏阶段）：设定密码的结果（PROTOCOL.md 第 6 节）。 */
public record PasswordResult(Status status, String message) implements PasswordMessage {
    public enum Status {
        OK(0),
        /** 密码不符合服务端策略。 */
        REJECTED(1),
        /** 请求过于频繁。 */
        RATE_LIMITED(2),
        /** 服务端内部错误（如存储失败）。 */
        ERROR(3);

        private final int id;

        Status(int id) {
            this.id = id;
        }

        public int id() {
            return id;
        }

        static Status fromId(int id) throws MalformedMessageException {
            for (Status status : values()) {
                if (status.id == id) {
                    return status;
                }
            }
            throw new MalformedMessageException("unknown password result status: " + id);
        }
    }

    public PasswordResult {
        Objects.requireNonNull(status, "status");
        Limits.checkString(message, Limits.MAX_RESULT_MESSAGE_BYTES, "message");
    }

    @Override
    public MessageType type() {
        return MessageType.PASSWORD_RESULT;
    }

    @Override
    public void writeBody(WireWriter out) {
        out.u8(status.id()).string(message, Limits.MAX_RESULT_MESSAGE_BYTES);
    }

    static PasswordResult read(WireReader in) throws MalformedMessageException {
        return new PasswordResult(Status.fromId(in.u8()), in.string(Limits.MAX_RESULT_MESSAGE_BYTES));
    }
}
