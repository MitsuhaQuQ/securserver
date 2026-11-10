package com.mtmrails.trustedserver.server.store;

/** 审计事件类型，写入 audit_log.event（PROTOCOL.md 第 9 节）。 */
public enum AuditEvent {
    BIND("bind"),
    BIND_AFTER_RESET("bind_after_reset"),
    LOGIN_OK("login_ok"),
    LOGIN_FAIL("login_fail"),
    RECOVER("recover"),
    ONLINE_REBIND("online_rebind"),
    ONLINE_PASSWORD_RESET("online_password_reset"),
    RECOVERY_REBIND("recovery_rebind"),
    RECOVERY_PASSWORD_RESET("recovery_password_reset"),
    SET_PASSWORD("set_password"),
    SET_RECOVERY("set_recovery"),
    RESET_KEY("reset_key"),
    RESET_PASSWORD("reset_password"),
    RESET_RECOVERY("reset_recovery"),
    RESET_ALL("reset_all"),
    TRUST("trust"),
    LOCKOUT("lockout"),
    REJECT("reject");

    private final String id;

    AuditEvent(String id) {
        this.id = id;
    }

    public String id() {
        return id;
    }
}
