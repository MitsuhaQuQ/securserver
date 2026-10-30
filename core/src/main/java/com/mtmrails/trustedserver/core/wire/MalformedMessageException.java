package com.mtmrails.trustedserver.core.wire;

/**
 * 收到的字节不符合协议格式：截断、超长、非法取值、多余字节等。
 *
 * <p>调用方应把它视为协议错误并断开连接，不要尝试恢复。
 */
public final class MalformedMessageException extends Exception {
    private static final long serialVersionUID = 1L;

    public MalformedMessageException(String message) {
        super(message);
    }

    public MalformedMessageException(String message, Throwable cause) {
        super(message, cause);
    }
}
