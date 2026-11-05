package com.mtmrails.trustedserver.core.session;

/** 账号改绑到新玩家公钥的原因，供审计日志区分。 */
public enum RebindReason {
    /** 玩家输对了找回密码（离线模式，或 session 无效而回退为无验证的正版服务器连接）。 */
    RECOVERY,
    /** 正版模式：身份已由 Mojang session 验证，视为可信，直接改绑到新设备的密钥。 */
    ONLINE_MODE_IDENTITY,
    /** 设备绑定已被管理员清空，本次为重新绑定。 */
    KEY_RESET
}
