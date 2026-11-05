package com.mtmrails.trustedserver.core.crypto;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

/** 本包内部使用的字节工具。 */
final class Bytes {
    private Bytes() {
    }

    static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) {
            length += part.length;
        }
        byte[] out = new byte[length];
        int pos = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, pos, part.length);
            pos += part.length;
        }
        return out;
    }

    static byte[] ascii(String label) {
        return label.getBytes(StandardCharsets.US_ASCII);
    }

    static byte[] requireLength(byte[] bytes, int length, String name) {
        if (bytes == null || bytes.length != length) {
            throw new IllegalArgumentException(name + " must be " + length + " bytes");
        }
        return bytes;
    }

    static boolean isAllZero(byte[] bytes) {
        int acc = 0;
        for (byte b : bytes) {
            acc |= b;
        }
        return acc == 0;
    }

    /** 小端字节序 → 非负整数。 */
    static BigInteger fromLittleEndian(byte[] bytes) {
        byte[] be = new byte[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            be[i] = bytes[bytes.length - 1 - i];
        }
        return new BigInteger(1, be);
    }

    /** 非负整数 → 定长小端字节序。 */
    static byte[] toLittleEndian(BigInteger value, int length) {
        byte[] be = value.toByteArray();
        byte[] out = new byte[length];
        for (int i = 0; i < length && i < be.length; i++) {
            out[i] = be[be.length - 1 - i];
        }
        if (be.length > length && !(be.length == length + 1 && be[0] == 0)) {
            throw new IllegalArgumentException("value does not fit in " + length + " bytes");
        }
        return out;
    }
}
