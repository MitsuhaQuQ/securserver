package com.mtmrails.trustedserver.core.session;

/** 原子账户恢复操作的结果。 */
public enum RecoveryResult {
    OK,
    PASSWORD_REJECTED,
    ACCOUNT_CONFLICT
}
