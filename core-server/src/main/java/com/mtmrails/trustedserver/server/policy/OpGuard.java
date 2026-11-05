package com.mtmrails.trustedserver.server.policy;

/**
 * OP 权限暂停规则（AGENTS.md 第 9、14 条）：OP 未设登录密码，或处于新用户受限状态时，暂停其 OP 权限，
 * 设定密码 / 解除受限后恢复。实际的权限调整由适配层完成。
 */
public final class OpGuard {
    private OpGuard() {
    }

    public static boolean suspendOp(boolean isOp, boolean restricted, boolean hasLoginPassword) {
        return isOp && (restricted || !hasLoginPassword);
    }
}
