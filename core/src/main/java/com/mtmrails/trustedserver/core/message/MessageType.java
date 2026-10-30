package com.mtmrails.trustedserver.core.message;

/**
 * 消息类型：线上 type 字节、所属频道、是否必须加密传输（PROTOCOL.md 第 4、6 节）。
 */
public enum MessageType {
    SERVER_HELLO(0x01, Channel.AUTH, false),
    CLIENT_HELLO(0x02, Channel.AUTH, false),
    CHALLENGE(0x03, Channel.AUTH, true),
    CLIENT_PROOF(0x04, Channel.AUTH, true),
    PASSWORD_REQUEST(0x05, Channel.PASSWORD, true),
    PASSWORD_ANSWER(0x06, Channel.PASSWORD, true),
    FINISH(0x07, Channel.AUTH, true),
    FINISH_ACK(0x08, Channel.AUTH, true),
    SET_PASSWORD(0x09, Channel.PASSWORD, true),
    SET_RECOVERY_PASSWORD(0x0A, Channel.PASSWORD, true),
    PASSWORD_RESULT(0x0B, Channel.PASSWORD, true);

    private static final MessageType[] BY_ID = new MessageType[0x100];

    static {
        for (MessageType type : values()) {
            BY_ID[type.id] = type;
        }
    }

    private final int id;
    private final Channel channel;
    private final boolean encrypted;

    MessageType(int id, Channel channel, boolean encrypted) {
        this.id = id;
        this.channel = channel;
        this.encrypted = encrypted;
    }

    /** 线上的 type 字节。 */
    public int id() {
        return id;
    }

    /** 允许出现的唯一频道。 */
    public Channel channel() {
        return channel;
    }

    /** 是否必须经 AEAD 加密后传输；只有两条 Hello 是明文。 */
    public boolean encrypted() {
        return encrypted;
    }

    /** 按 type 字节查找；未知时返回 {@code null}。 */
    public static MessageType fromId(int id) {
        return id >= 0 && id < BY_ID.length ? BY_ID[id] : null;
    }
}
