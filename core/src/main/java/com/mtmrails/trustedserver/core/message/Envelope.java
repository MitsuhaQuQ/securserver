package com.mtmrails.trustedserver.core.message;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import java.util.Arrays;
import java.util.Objects;

/**
 * payload 的外层：{@code magic(4) | type(1) | body}。
 *
 * <p>对加密消息，body 是密文，{@link #header()} 作为 AEAD 的附加认证数据（AAD）。
 */
public record Envelope(MessageType type, byte[] body) {
    private static final byte[] MAGIC = {'T', 'S', 'R', 'V'};
    public static final int HEADER_LENGTH = MAGIC.length + 1;

    public Envelope {
        Objects.requireNonNull(type, "type");
        body = body.clone();
        if (HEADER_LENGTH + body.length > Limits.MAX_PAYLOAD) {
            throw new IllegalArgumentException("payload exceeds " + Limits.MAX_PAYLOAD + " bytes");
        }
    }

    @Override
    public byte[] body() {
        return body.clone();
    }

    /** {@code magic | type}，即 AEAD 的 AAD。 */
    public byte[] header() {
        return header(type);
    }

    public static byte[] header(MessageType type) {
        byte[] header = Arrays.copyOf(MAGIC, HEADER_LENGTH);
        header[MAGIC.length] = (byte) type.id();
        return header;
    }

    public byte[] toBytes() {
        byte[] out = Arrays.copyOf(header(), HEADER_LENGTH + body.length);
        System.arraycopy(body, 0, out, HEADER_LENGTH, body.length);
        return out;
    }

    /**
     * 解析从 {@code channel} 收到的 payload：校验长度、magic、type，
     * 以及该 type 是否允许出现在这个频道。
     */
    public static Envelope parse(Channel channel, byte[] payload) throws MalformedMessageException {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(payload, "payload");
        if (payload.length > Limits.MAX_PAYLOAD) {
            throw new MalformedMessageException("payload exceeds " + Limits.MAX_PAYLOAD + " bytes");
        }
        if (payload.length < HEADER_LENGTH) {
            throw new MalformedMessageException("payload shorter than header");
        }
        if (!Arrays.equals(payload, 0, MAGIC.length, MAGIC, 0, MAGIC.length)) {
            throw new MalformedMessageException("bad magic");
        }
        int id = payload[MAGIC.length] & 0xFF;
        MessageType type = MessageType.fromId(id);
        if (type == null) {
            throw new MalformedMessageException("unknown message type: 0x" + Integer.toHexString(id));
        }
        if (type.channel() != channel) {
            throw new MalformedMessageException(type + " is not allowed on channel " + channel.id());
        }
        return new Envelope(type, Arrays.copyOfRange(payload, HEADER_LENGTH, payload.length));
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Envelope other && type == other.type && Arrays.equals(body, other.body);
    }

    @Override
    public int hashCode() {
        return 31 * type.hashCode() + Arrays.hashCode(body);
    }

    @Override
    public String toString() {
        return "Envelope[type=" + type + ", body=" + body.length + " bytes]";
    }
}
