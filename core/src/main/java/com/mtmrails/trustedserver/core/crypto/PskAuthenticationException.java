package com.mtmrails.trustedserver.core.crypto;

/** 预共享密钥挑战应答失败；调用方应废弃本次握手。 */
public final class PskAuthenticationException extends Exception {
    private static final long serialVersionUID = 1L;

    public PskAuthenticationException(String message) {
        super(message);
    }
}
