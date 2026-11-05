package com.mtmrails.trustedserver.core.crypto;

/**
 * 密码学检查失败：对方公钥非法、DH 结果全零、AEAD 标签不匹配、超出使用上限，
 * 或在已废弃的通道上继续操作。调用方应断开连接，不得重试。
 */
public final class CryptoException extends Exception {
    private static final long serialVersionUID = 1L;

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
