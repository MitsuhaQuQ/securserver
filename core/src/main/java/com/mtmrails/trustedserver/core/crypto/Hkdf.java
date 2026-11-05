package com.mtmrails.trustedserver.core.crypto;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** HKDF-SHA256（RFC 5869）。 */
public final class Hkdf {
    public static final int HASH_LENGTH = 32;
    private static final int MAX_OUTPUT = 255 * HASH_LENGTH;

    private Hkdf() {
    }

    /** Extract：空 salt 按 RFC 视为 32 个零字节。 */
    public static byte[] extract(byte[] salt, byte[] ikm) {
        byte[] effectiveSalt = salt.length == 0 ? new byte[HASH_LENGTH] : salt;
        return hmac(effectiveSalt).doFinal(ikm);
    }

    public static byte[] expand(byte[] prk, byte[] info, int length) {
        if (prk.length < HASH_LENGTH) {
            throw new IllegalArgumentException("PRK shorter than hash length");
        }
        if (length < 1 || length > MAX_OUTPUT) {
            throw new IllegalArgumentException("invalid output length: " + length);
        }
        Mac mac = hmac(prk);
        byte[] out = new byte[length];
        byte[] block = new byte[0];
        int pos = 0;
        for (int counter = 1; pos < length; counter++) {
            mac.update(block);
            mac.update(info);
            mac.update((byte) counter);
            Arrays.fill(block, (byte) 0);
            block = mac.doFinal();
            int n = Math.min(block.length, length - pos);
            System.arraycopy(block, 0, out, pos, n);
            pos += n;
        }
        Arrays.fill(block, (byte) 0);
        return out;
    }

    private static Mac hmac(byte[] key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 unavailable", e);
        }
    }
}
