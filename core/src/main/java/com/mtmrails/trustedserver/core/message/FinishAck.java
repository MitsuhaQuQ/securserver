package com.mtmrails.trustedserver.core.message;

import com.mtmrails.trustedserver.core.wire.WireWriter;

/** C→S，加密，空消息体：确认 Finish；开启隧道时也是切换点（PROTOCOL.md 4.10）。 */
public record FinishAck() implements AuthMessage {
    @Override
    public MessageType type() {
        return MessageType.FINISH_ACK;
    }

    @Override
    public void writeBody(WireWriter out) {
    }
}
