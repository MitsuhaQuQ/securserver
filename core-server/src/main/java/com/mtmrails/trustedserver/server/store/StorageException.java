package com.mtmrails.trustedserver.server.store;

/** 数据库访问失败。状态机遇到它时按内部错误拒绝。 */
public final class StorageException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public StorageException(String message, Throwable cause) {
        super(message, cause);
    }

    public StorageException(String message) {
        super(message);
    }
}
