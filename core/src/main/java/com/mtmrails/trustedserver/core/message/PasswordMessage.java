package com.mtmrails.trustedserver.core.message;

/** 密码通道 {@link Channel#PASSWORD} 上的消息。实现的 {@code toString()} 不会输出密码。 */
public sealed interface PasswordMessage extends Message
        permits PasswordRequest, PasswordAnswer, SetPassword, SetRecoveryPassword, PasswordResult {
}
