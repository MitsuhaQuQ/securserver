package com.mtmrails.trustedserver.core.session;

import java.util.Objects;

/** 客户端本地检测到的失败，可在本地显示诊断（PROTOCOL.md 第 1 节）。 */
public record ClientFailure(Kind kind, String detail) {
    public enum Kind {
        /** 没有共同的协议版本。 */
        VERSION_MISMATCH,
        /** 消息格式、类型、频道或顺序不对。 */
        PROTOCOL_ERROR,
        /** DH 失败、AEAD 标签不匹配或超出使用上限（含中间人篡改 Hello 的情况）。 */
        CRYPTO_FAILURE,
        /** 服务端身份签名无效。 */
        SERVER_SIGNATURE_INVALID,
        /** 服务端身份公钥变化，玩家未确认。 */
        SERVER_KEY_REJECTED,
        /** 玩家取消了密码输入。 */
        USER_CANCELLED,
        /** 本地存储或界面故障。 */
        INTERNAL_ERROR
    }

    public ClientFailure {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(detail, "detail");
    }
}
