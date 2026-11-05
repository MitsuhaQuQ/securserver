package com.mtmrails.trustedserver.core.crypto;

import java.security.GeneralSecurityException;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** AES-256-GCM，128 位标签，输出为密文在前、标签在后（PROTOCOL.md 4.3.2）。 */
public final class Aes256Gcm {
    public static final int KEY_LENGTH = 32;
    public static final int NONCE_LENGTH = 12;
    public static final int TAG_LENGTH = 16;

    private Aes256Gcm() {
    }

    public static byte[] encrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext) throws CryptoException {
        return run(Cipher.ENCRYPT_MODE, key, nonce, aad, plaintext);
    }

    /** 标签不匹配时抛出 {@link CryptoException}，不返回任何明文。 */
    public static byte[] decrypt(byte[] key, byte[] nonce, byte[] aad, byte[] ciphertext) throws CryptoException {
        if (ciphertext.length < TAG_LENGTH) {
            throw new CryptoException("ciphertext shorter than tag");
        }
        return run(Cipher.DECRYPT_MODE, key, nonce, aad, ciphertext);
    }

    private static byte[] run(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] input) throws CryptoException {
        Bytes.requireLength(key, KEY_LENGTH, "key");
        Bytes.requireLength(nonce, NONCE_LENGTH, "nonce");
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_LENGTH * 8, nonce));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("AES-256-GCM unavailable", e);
        }
        cipher.updateAAD(aad);
        try {
            return cipher.doFinal(input);
        } catch (AEADBadTagException e) {
            throw new CryptoException("authentication tag mismatch", e);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AES-GCM failure", e);
        }
    }
}
