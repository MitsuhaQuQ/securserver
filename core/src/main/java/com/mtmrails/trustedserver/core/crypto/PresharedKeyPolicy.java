package com.mtmrails.trustedserver.core.crypto;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/** 对人工提供的 32 字节 PSK 做明显弱密钥检查；不能替代安全随机生成。 */
public final class PresharedKeyPolicy {
    public static final int KEY_LENGTH = 32;
    private static final String[] COMMON = {
            "password", "passwd", "123456", "12345678", "qwerty", "abc123", "admin",
            "administrator", "letmein", "welcome", "iloveyou", "minecraft", "trustedserver",
            "secret", "changeme", "default", "guest", "root", "server", "psk"
    };

    private PresharedKeyPolicy() {
    }

    public static void requireStrong(byte[] key) {
        if (key == null || key.length != KEY_LENGTH) {
            throw new IllegalArgumentException("PSK must be exactly 32 bytes");
        }

        int[] frequencies = new int[256];
        Set<Byte> unique = new HashSet<>();
        int maximum = 0;
        for (byte value : key) {
            unique.add(value);
            maximum = Math.max(maximum, ++frequencies[value & 0xff]);
        }
        if (unique.size() < 12 || maximum > 8) {
            throw weak("too few distinct byte values");
        }

        for (int period = 1; period <= KEY_LENGTH / 2; period++) {
            boolean repeated = true;
            for (int i = period; i < key.length; i++) {
                if (key[i] != key[i % period]) {
                    repeated = false;
                    break;
                }
            }
            if (repeated) {
                throw weak("repeated pattern");
            }
        }

        boolean ascending = true;
        boolean descending = true;
        for (int i = 1; i < key.length; i++) {
            ascending &= (key[i] & 0xff) == (((key[i - 1] & 0xff) + 1) & 0xff);
            descending &= (key[i] & 0xff) == (((key[i - 1] & 0xff) - 1) & 0xff);
        }
        if (ascending || descending) {
            throw weak("sequential byte pattern");
        }

        String normalized = normalizedText(key);
        for (String common : COMMON) {
            if (normalized.contains(normalizeLeet(common))) {
                throw weak("contains a common password pattern");
            }
        }

        boolean printable = true;
        boolean lower = false;
        boolean upper = false;
        boolean digit = false;
        boolean symbol = false;
        for (byte value : key) {
            int c = value & 0xff;
            printable &= c >= 0x20 && c <= 0x7e;
            lower |= c >= 'a' && c <= 'z';
            upper |= c >= 'A' && c <= 'Z';
            digit |= c >= '0' && c <= '9';
            symbol |= c >= 0x20 && c <= 0x7e && !Character.isLetterOrDigit(c);
        }
        if (printable && count(lower, upper, digit, symbol) < 3) {
            throw weak("printable keys must use at least three character classes");
        }
    }

    private static String normalizedText(byte[] key) {
        StringBuilder text = new StringBuilder(key.length);
        for (byte value : key) {
            int c = value & 0xff;
            if (c >= 0x20 && c <= 0x7e) {
                text.append((char) c);
            } else {
                text.append(' ');
            }
        }
        return normalizeLeet(text.toString());
    }

    private static String normalizeLeet(String value) {
        String lower = value.toLowerCase(Locale.ROOT);
        StringBuilder normalized = new StringBuilder(lower.length());
        for (int i = 0; i < lower.length(); i++) {
            char c = lower.charAt(i);
            c = switch (c) {
                case '0' -> 'o';
                case '1', '!' -> 'i';
                case '3' -> 'e';
                case '4', '@' -> 'a';
                case '5', '$' -> 's';
                case '7' -> 't';
                default -> c;
            };
            if (c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
                normalized.append(c);
            }
        }
        return normalized.toString();
    }

    private static int count(boolean... values) {
        int result = 0;
        for (boolean value : values) {
            if (value) result++;
        }
        return result;
    }

    private static IllegalArgumentException weak(String reason) {
        return new IllegalArgumentException("PSK does not meet the strength policy: " + reason
                + "; use the server-generated key");
    }
}
