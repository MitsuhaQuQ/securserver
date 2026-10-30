package com.mtmrails.trustedserver.core.message;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;
import java.util.Objects;

/**
 * 消息与字节之间的转换。
 *
 * <ul>
 *   <li>明文消息（两条 Hello）：{@link #encodePlain} / {@link #decodePlain} 处理完整 payload
 *   <li>加密消息：只用 {@link #encodeBody} / {@link #decodeBody} 处理消息体，
 *       由加密层负责封装进 {@link Envelope}；明文接口拒绝处理它们，避免误把加密消息明文发送
 * </ul>
 */
public final class MessageCodec {
    private MessageCodec() {
    }

    public static byte[] encodePlain(Message message) {
        if (message.type().encrypted()) {
            throw new IllegalArgumentException(message.type() + " must be encrypted");
        }
        return new Envelope(message.type(), encodeBody(message)).toBytes();
    }

    public static Message decodePlain(Channel channel, byte[] payload) throws MalformedMessageException {
        Envelope envelope = Envelope.parse(channel, payload);
        if (envelope.type().encrypted()) {
            throw new MalformedMessageException(envelope.type() + " received without encryption");
        }
        return decodeBody(envelope.type(), envelope.body());
    }

    public static byte[] encodeBody(Message message) {
        WireWriter out = new WireWriter();
        message.writeBody(out);
        return out.toByteArray();
    }

    /** 按 {@code type} 解析消息体，要求恰好读完。 */
    public static Message decodeBody(MessageType type, byte[] body) throws MalformedMessageException {
        Objects.requireNonNull(type, "type");
        WireReader in = new WireReader(body);
        Message message;
        try {
            message = switch (type) {
                case SERVER_HELLO -> ServerHello.read(in);
                case CLIENT_HELLO -> ClientHello.read(in);
                case CHALLENGE -> Challenge.read(in);
                case CLIENT_PROOF -> ClientProof.read(in);
                case PASSWORD_REQUEST -> PasswordRequest.read(in);
                case PASSWORD_ANSWER -> PasswordAnswer.read(in);
                case FINISH -> Finish.read(in);
                case FINISH_ACK -> new FinishAck();
                case SET_PASSWORD -> SetPassword.read(in);
                case SET_RECOVERY_PASSWORD -> SetRecoveryPassword.read(in);
                case PASSWORD_RESULT -> PasswordResult.read(in);
            };
        } catch (IllegalArgumentException e) {
            throw new MalformedMessageException(e.getMessage(), e);
        }
        in.expectEnd();
        return message;
    }
}
