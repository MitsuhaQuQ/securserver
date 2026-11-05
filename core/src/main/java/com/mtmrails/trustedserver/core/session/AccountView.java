package com.mtmrails.trustedserver.core.session;

/** 状态机所需的账号快照。 */
public record AccountView(byte[] playerPub, boolean restricted, boolean hasLoginPassword,
        boolean hasRecoveryPassword) {
    public AccountView {
        playerPub = playerPub.clone();
    }

    @Override
    public byte[] playerPub() {
        return playerPub.clone();
    }

    AccountView withPlayerPub(byte[] newPub) {
        return new AccountView(newPub, restricted, hasLoginPassword, hasRecoveryPassword);
    }

    /** 设定登录密码后：有密码、解除受限。 */
    AccountView withLoginPassword() {
        return new AccountView(playerPub, false, true, hasRecoveryPassword);
    }
}
