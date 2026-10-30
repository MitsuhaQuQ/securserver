package com.mtmrails.trustedserver.core.message;

import com.mtmrails.trustedserver.core.wire.WireWriter;

/**
 * 协议消息。实现均为不可变的 record；含字节数组的字段在构造和读取时都做防御性复制。
 */
public sealed interface Message permits AuthMessage, PasswordMessage {
    MessageType type();

    /** 写出消息体（不含 magic 和 type）。 */
    void writeBody(WireWriter out);
}
