package com.mtmrails.trustedserver.core.session;

import com.mtmrails.trustedserver.core.crypto.SessionHandover;
import java.util.List;
import java.util.Objects;

/** 客户端认证完成：Finish 的内容与移交给游戏阶段的加密状态。 */
public record ClientResult(boolean tunnel, List<String> notices, SessionHandover handover) {
    public ClientResult {
        notices = List.copyOf(notices);
        Objects.requireNonNull(handover, "handover");
    }
}
