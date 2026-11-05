package com.mtmrails.trustedserver.core.session;

/**
 * 服务端拒绝的内部原因，用于审计日志与调试。
 *
 * <p>对外文本由上层决定：可信握手完成前一律使用配置的统一拒绝文本（PROTOCOL.md 第 1 节“拒绝提示的可信边界”）。
 */
public enum RejectReason {
    /** 对方回答“不理解”：没装本 mod。 */
    NO_MOD,
    /** 没有共同的协议版本。 */
    VERSION_MISMATCH,
    /** 消息格式、类型、频道或顺序不对。 */
    PROTOCOL_ERROR,
    /** DH 失败、AEAD 标签不匹配或超出使用上限。 */
    CRYPTO_FAILURE,
    /** ClientProof 的签名无效。 */
    INVALID_PROOF,
    /** 未经 Mojang 验证的连接上，公钥与已绑定的不一致，且未设找回密码。 */
    KEY_MISMATCH,
    /** 登录或找回密码错误次数用尽。 */
    PASSWORD_ATTEMPTS_EXHAUSTED,
    /** 新用户名绑定（或管理员清空绑定后的重新绑定）时被并发的另一连接抢先。 */
    ACCOUNT_CONFLICT,
    /** 服务端哈希线程池已排满。 */
    SERVER_BUSY,
    /** 认证总超时。 */
    TIMEOUT,
    /** 账号存储等内部故障。 */
    INTERNAL_ERROR
}
