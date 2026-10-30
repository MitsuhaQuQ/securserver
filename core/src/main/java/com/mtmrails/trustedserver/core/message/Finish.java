package com.mtmrails.trustedserver.core.message;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;
import java.util.ArrayList;
import java.util.List;

/**
 * S→C，加密：认证成功（PROTOCOL.md 4.9）。
 *
 * <p>失败一律直接断开，不发 Finish，所以线上的 result 字段固定为 {@link #RESULT_OK}。
 */
public record Finish(boolean tunnel, List<String> notices) implements AuthMessage {
    public static final int RESULT_OK = 0;

    public Finish {
        notices = List.copyOf(notices);
        if (notices.size() > Limits.MAX_NOTICES) {
            throw new IllegalArgumentException("too many notices: " + notices.size());
        }
        for (String notice : notices) {
            Limits.checkString(notice, Limits.MAX_NOTICE_BYTES, "notice");
        }
    }

    @Override
    public MessageType type() {
        return MessageType.FINISH;
    }

    @Override
    public void writeBody(WireWriter out) {
        out.u8(RESULT_OK).bool(tunnel).varInt(notices.size());
        for (String notice : notices) {
            out.string(notice, Limits.MAX_NOTICE_BYTES);
        }
    }

    static Finish read(WireReader in) throws MalformedMessageException {
        int result = in.u8();
        if (result != RESULT_OK) {
            throw new MalformedMessageException("unknown Finish result: " + result);
        }
        boolean tunnel = in.bool();
        int count = in.varInt();
        if (count > Limits.MAX_NOTICES) {
            throw new MalformedMessageException("too many notices: " + count);
        }
        List<String> notices = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            notices.add(in.string(Limits.MAX_NOTICE_BYTES));
        }
        return new Finish(tunnel, notices);
    }
}
