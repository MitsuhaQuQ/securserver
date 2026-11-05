package com.mtmrails.trustedserver.core.crypto;

import com.mtmrails.trustedserver.core.message.Channel;
import com.mtmrails.trustedserver.core.message.Envelope;
import com.mtmrails.trustedserver.core.message.Limits;
import com.mtmrails.trustedserver.core.message.Message;
import com.mtmrails.trustedserver.core.message.MessageCodec;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import java.util.Objects;

/**
 * 一个频道（认证或密码）上本端的加密收发：发送用一条 SEAL 流，接收用一条 OPEN 流。
 *
 * <p>接收时先检查总长度、magic、频道与 type，再验证标签，最后才解码消息体（PROTOCOL.md 4.3.2）。
 * 接收方向的任何失败都会关闭两条流；连接级的“废弃所有通道”由会话层负责。
 *
 * <p>密码通道从登录阶段移交到游戏阶段时，必须移交同一个实例，不能重新创建。
 */
public final class SecureMessageChannel {
    /** 加密消息体上限：4096 - 5 字节头 - 16 字节标签。 */
    public static final int MAX_BODY = Limits.MAX_PAYLOAD - Envelope.HEADER_LENGTH - Aes256Gcm.TAG_LENGTH;

    private final Channel channel;
    private final AeadStream outbound;
    private final AeadStream inbound;

    SecureMessageChannel(Channel channel, AeadStream outbound, AeadStream inbound) {
        this.channel = Objects.requireNonNull(channel, "channel");
        this.outbound = outbound;
        this.inbound = inbound;
    }

    public Channel channel() {
        return channel;
    }

    public byte[] seal(Message message) throws CryptoException {
        if (message.type().channel() != channel || !message.type().encrypted()) {
            throw new IllegalArgumentException(message.type() + " cannot be sent encrypted on " + channel.id());
        }
        byte[] body = MessageCodec.encodeBody(message);
        if (body.length > MAX_BODY) {
            throw new IllegalArgumentException("message body " + body.length + " exceeds " + MAX_BODY + " bytes");
        }
        byte[] header = Envelope.header(message.type());
        return Bytes.concat(header, outbound.seal(header, body));
    }

    public Message open(byte[] payload) throws CryptoException, MalformedMessageException {
        try {
            Envelope envelope = Envelope.parse(channel, payload);
            if (!envelope.type().encrypted()) {
                throw new MalformedMessageException(envelope.type() + " is not an encrypted message type");
            }
            byte[] body = inbound.open(envelope.header(), envelope.body());
            return MessageCodec.decodeBody(envelope.type(), body);
        } catch (CryptoException | MalformedMessageException | RuntimeException e) {
            close();
            throw e;
        }
    }

    public boolean isOpen() {
        return outbound.isOpen() && inbound.isOpen();
    }

    public void close() {
        outbound.close();
        inbound.close();
    }
}
