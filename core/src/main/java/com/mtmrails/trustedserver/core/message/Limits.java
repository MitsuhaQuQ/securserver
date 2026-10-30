package com.mtmrails.trustedserver.core.message;

import com.mtmrails.trustedserver.core.wire.WireWriter;

/** 线上格式的各项长度上限。 */
public final class Limits {
    /** 单条 payload（含 magic、type、密文和认证标签）的最大字节数。 */
    public static final int MAX_PAYLOAD = 4096;
    /** ServerHello 中最多列出的协议版本数。 */
    public static final int MAX_VERSIONS = 16;
    /** 密码最多的 Unicode 码点数。 */
    public static final int MAX_PASSWORD_CODE_POINTS = 128;
    /** 密码 UTF-8 编码后的最大字节数。 */
    public static final int MAX_PASSWORD_BYTES = MAX_PASSWORD_CODE_POINTS * 4;
    /** Finish 中最多携带的提示条数。 */
    public static final int MAX_NOTICES = 8;
    /** 单条提示 UTF-8 编码后的最大字节数。 */
    public static final int MAX_NOTICE_BYTES = 1024;
    /** PasswordResult 说明文字 UTF-8 编码后的最大字节数。 */
    public static final int MAX_RESULT_MESSAGE_BYTES = 1024;

    /** X25519 公钥长度。 */
    public static final int X25519_KEY_LENGTH = 32;
    /** Ed25519 公钥长度。 */
    public static final int ED25519_KEY_LENGTH = 32;
    /** Ed25519 签名长度。 */
    public static final int ED25519_SIGNATURE_LENGTH = 64;
    /** 握手随机数长度。 */
    public static final int NONCE_LENGTH = 32;

    private Limits() {
    }

    /** 校验字符串可编码为合法 UTF-8 且不超过 {@code maxBytes}。 */
    static String checkString(String value, int maxBytes, String name) {
        int length = WireWriter.utf8(value).length;
        if (length > maxBytes) {
            throw new IllegalArgumentException(name + " is " + length + " bytes, limit " + maxBytes);
        }
        return value;
    }

    /** 校验密码：合法 Unicode、码点数不超过上限；{@code allowEmpty} 为假时不能为空。 */
    static String checkPassword(String password, boolean allowEmpty) {
        checkString(password, MAX_PASSWORD_BYTES, "password");
        if (!allowEmpty && password.isEmpty()) {
            throw new IllegalArgumentException("password must not be empty");
        }
        int codePoints = password.codePointCount(0, password.length());
        if (codePoints > MAX_PASSWORD_CODE_POINTS) {
            throw new IllegalArgumentException(
                    "password has " + codePoints + " code points, limit " + MAX_PASSWORD_CODE_POINTS);
        }
        return password;
    }

    /** 复制并校验定长字节串。 */
    static byte[] copyExact(byte[] bytes, int length, String name) {
        if (bytes == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
        if (bytes.length != length) {
            throw new IllegalArgumentException(name + " must be " + length + " bytes, got " + bytes.length);
        }
        return bytes.clone();
    }
}
