package com.mtmrails.trustedserver.core.session;

/** 密码重设授权的来源。 */
public enum RecoveryOrigin {
    /** Mojang session 与原绑定设备密钥同时验证正确。 */
    ONLINE_SESSION_AND_KEY,
    /** 新设备通过找回密码验证。 */
    RECOVERY_PASSWORD
}
