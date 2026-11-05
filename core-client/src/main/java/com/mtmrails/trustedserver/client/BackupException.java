package com.mtmrails.trustedserver.client;

import java.util.Objects;

/** 读取备份文件失败。 */
public final class BackupException extends Exception {
    private static final long serialVersionUID = 1L;

    public enum Kind {
        /** 不是本 mod 的备份文件，或版本不受支持。 */
        UNSUPPORTED_FORMAT,
        /** 文件已加密，但没有提供备份密码。 */
        PASSWORD_REQUIRED,
        /** 备份密码错误，或加密文件被篡改 / 截断（两者无法区分）。 */
        WRONG_PASSWORD_OR_CORRUPTED,
        /** 未加密文件损坏、截断或内容不合法（含私钥与公钥不匹配）。 */
        CORRUPTED
    }

    private final Kind kind;

    BackupException(Kind kind, String message) {
        super(message);
        this.kind = Objects.requireNonNull(kind, "kind");
    }

    BackupException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = Objects.requireNonNull(kind, "kind");
    }

    public Kind kind() {
        return kind;
    }
}
