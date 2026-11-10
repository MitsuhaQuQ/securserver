package com.mtmrails.trustedserver.core.session;

/**
 * 状态机所需的账号快照。{@code playerPub} 为 {@code null} 表示设备绑定已被管理员清空（{@code reset key}），
 * 等待重新绑定。
 */
public record AccountView(byte[] playerPub, boolean restricted, boolean hasLoginPassword,
        boolean hasRecoveryPassword) {
    public AccountView {
        playerPub = playerPub == null ? null : playerPub.clone();
    }

    @Override
    public byte[] playerPub() {
        return playerPub == null ? null : playerPub.clone();
    }

    public boolean keyBound() {
        return playerPub != null;
    }

    AccountView withPlayerPub(byte[] newPub) {
        return new AccountView(newPub, restricted, hasLoginPassword, hasRecoveryPassword);
    }

    /** 设定登录密码后：有密码、解除受限。 */
    AccountView withLoginPassword() {
        return new AccountView(playerPub, false, true, hasRecoveryPassword);
    }

    /** 清除登录密码后：无密码，并恢复受限标记。 */
    AccountView withoutLoginPassword() {
        return new AccountView(playerPub, true, false, hasRecoveryPassword);
    }
}
