package com.mtmrails.trustedserver.client;

import com.mtmrails.trustedserver.core.crypto.Aes256Gcm;
import com.mtmrails.trustedserver.core.crypto.CryptoException;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * 玩家认证密钥的导出 / 导入文件（AGENTS.md 第 15 条）。
 *
 * <pre>
 * header  = "TSKB" | u8 格式版本 = 1 | u8 保护方式
 * 保护方式 0（明文）：header | body | SHA-256(header || body)
 * 保护方式 1（密码）：header | salt(16) | u32 迭代次数 | nonce(12) | AES-256-GCM(key, nonce, body, aad = 此前全部字节)
 *                    key = PBKDF2-HMAC-SHA256(备份密码, salt, 迭代次数, 256 位)
 * body    = VarInt 条数 | 条数 × (服务端身份公钥 32 | 用户名 string | 玩家公钥 32 | 私钥种子 32)
 * </pre>
 *
 * <p>只包含玩家用于 ClientProof 的密钥对及定位信息；不包含登录 / 找回密码、TOFU 记录或服务端私钥。
 * 读取时逐条校验私钥与公钥匹配，并拒绝重复的定位。是否覆盖本机已有的不同密钥由
 * {@link PlayerKeyStore#importKey} 决定，本类不会写入任何存储。
 */
public final class PlayerKeyBackup {
    private static final byte[] MAGIC = {'T', 'S', 'K', 'B'};
    private static final int VERSION = 1;
    private static final int PROTECTION_NONE = 0;
    private static final int PROTECTION_PASSWORD = 1;

    /** 新导出使用的 PBKDF2 迭代次数（OWASP 对 PBKDF2-HMAC-SHA256 的建议值）。 */
    public static final int DEFAULT_ITERATIONS = 600_000;
    /** 导入时接受的迭代次数范围：下限防止弱参数文件，上限防止恶意文件拖死客户端。 */
    static final int MIN_ITERATIONS = 100_000;
    static final int MAX_ITERATIONS = 10_000_000;
    static final int SALT_LENGTH = 16;
    static final int MAX_ENTRIES = 4096;
    static final int MAX_FILE_SIZE = 1 << 20;
    private static final int CHECKSUM_LENGTH = 32;

    private PlayerKeyBackup() {
    }

    /**
     * 导出。{@code password} 为空或空串时明文导出（界面须先明确警告）。
     */
    public static byte[] export(List<StoredKey> keys, Optional<String> password, SecureRandom random) {
        return export(keys, password, random, DEFAULT_ITERATIONS);
    }

    static byte[] export(List<StoredKey> keys, Optional<String> password, SecureRandom random, int iterations) {
        if (keys.isEmpty()) {
            throw new IllegalArgumentException("no keys selected for export");
        }
        if (keys.size() > MAX_ENTRIES) {
            throw new IllegalArgumentException("too many keys selected for export: " + keys.size()
                    + " (maximum " + MAX_ENTRIES + ")");
        }
        Set<KeyTarget> seen = new HashSet<>();
        WireWriter bodyWriter = new WireWriter().varInt(keys.size());
        for (StoredKey key : keys) {
            if (!seen.add(key.target())) {
                throw new IllegalArgumentException("duplicate key target " + key.target());
            }
            KeyRecordCodec.write(bodyWriter, key);
        }
        byte[] body = bodyWriter.toByteArray();
        try {
            if (password.isEmpty() || password.get().isEmpty()) {
                byte[] header = header(PROTECTION_NONE);
                byte[] content = concat(header, body);
                return concat(content, PlayerKeyStore.sha256(content));
            }
            byte[] salt = new byte[SALT_LENGTH];
            random.nextBytes(salt);
            byte[] nonce = new byte[Aes256Gcm.NONCE_LENGTH];
            random.nextBytes(nonce);
            byte[] aad = new WireWriter().fixed(header(PROTECTION_PASSWORD)).fixed(salt).u32(iterations).fixed(nonce)
                    .toByteArray();
            byte[] key = deriveKey(password.get(), salt, iterations);
            try {
                return concat(aad, Aes256Gcm.encrypt(key, nonce, aad, body));
            } catch (CryptoException e) {
                throw new IllegalStateException("AES-GCM encryption failed", e);
            } finally {
                Arrays.fill(key, (byte) 0);
            }
        } finally {
            Arrays.fill(body, (byte) 0);
        }
    }

    /** 是否为需要备份密码的文件（界面据此决定是否弹出密码框）。 */
    public static boolean isEncrypted(byte[] file) throws BackupException {
        return protectionOf(file) == PROTECTION_PASSWORD;
    }

    /** 读取并校验备份文件中的全部密钥。 */
    public static List<StoredKey> read(byte[] file, Optional<String> password) throws BackupException {
        int protection = protectionOf(file);
        byte[] body;
        BackupException.Kind bodyErrorKind;
        if (protection == PROTECTION_NONE) {
            if (file.length < MAGIC.length + 2 + CHECKSUM_LENGTH) {
                throw new BackupException(BackupException.Kind.CORRUPTED, "backup file is truncated");
            }
            byte[] content = Arrays.copyOf(file, file.length - CHECKSUM_LENGTH);
            byte[] checksum = Arrays.copyOfRange(file, content.length, file.length);
            if (!MessageDigest.isEqual(checksum, PlayerKeyStore.sha256(content))) {
                throw new BackupException(BackupException.Kind.CORRUPTED, "backup file checksum mismatch");
            }
            body = Arrays.copyOfRange(content, MAGIC.length + 2, content.length);
            bodyErrorKind = BackupException.Kind.CORRUPTED;
        } else {
            if (password.isEmpty() || password.get().isEmpty()) {
                throw new BackupException(BackupException.Kind.PASSWORD_REQUIRED, "backup file is password protected");
            }
            body = decrypt(file, password.get());
            // 标签已验证通过，之后的格式错误只可能来自导出端本身的问题
            bodyErrorKind = BackupException.Kind.CORRUPTED;
        }
        try {
            return parseBody(body);
        } catch (MalformedMessageException e) {
            throw new BackupException(bodyErrorKind, "backup content is invalid: " + e.getMessage(), e);
        } finally {
            Arrays.fill(body, (byte) 0);
        }
    }

    private static byte[] decrypt(byte[] file, String password) throws BackupException {
        WireReader in = new WireReader(file);
        byte[] salt;
        int iterations;
        byte[] nonce;
        try {
            in.fixed(MAGIC.length + 2);
            salt = in.fixed(SALT_LENGTH);
            iterations = in.u32();
            nonce = in.fixed(Aes256Gcm.NONCE_LENGTH);
        } catch (MalformedMessageException e) {
            throw new BackupException(BackupException.Kind.WRONG_PASSWORD_OR_CORRUPTED, "backup file is truncated", e);
        }
        if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
            throw new BackupException(BackupException.Kind.UNSUPPORTED_FORMAT,
                    "unsupported PBKDF2 iteration count " + Integer.toUnsignedString(iterations));
        }
        int aadLength = file.length - in.remaining();
        byte[] aad = Arrays.copyOf(file, aadLength);
        byte[] ciphertext = Arrays.copyOfRange(file, aadLength, file.length);
        byte[] key = deriveKey(password, salt, iterations);
        try {
            return Aes256Gcm.decrypt(key, nonce, aad, ciphertext);
        } catch (CryptoException e) {
            throw new BackupException(BackupException.Kind.WRONG_PASSWORD_OR_CORRUPTED,
                    "wrong backup password or corrupted file", e);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static List<StoredKey> parseBody(byte[] body) throws MalformedMessageException {
        WireReader in = new WireReader(body);
        int count = in.varInt();
        if (count < 1 || count > MAX_ENTRIES) {
            throw new MalformedMessageException("invalid key count " + count);
        }
        List<StoredKey> keys = new ArrayList<>(count);
        Set<KeyTarget> seen = new HashSet<>();
        for (int i = 0; i < count; i++) {
            StoredKey key = KeyRecordCodec.read(in);
            if (!seen.add(key.target())) {
                throw new MalformedMessageException("duplicate key target " + key.target());
            }
            keys.add(key);
        }
        in.expectEnd();
        return keys;
    }

    private static int protectionOf(byte[] file) throws BackupException {
        if (file.length > MAX_FILE_SIZE) {
            throw new BackupException(BackupException.Kind.UNSUPPORTED_FORMAT, "file is too large to be a key backup");
        }
        if (file.length < MAGIC.length + 2 || !Arrays.equals(file, 0, MAGIC.length, MAGIC, 0, MAGIC.length)) {
            throw new BackupException(BackupException.Kind.UNSUPPORTED_FORMAT, "not a TrustedServer key backup");
        }
        int version = file[MAGIC.length] & 0xFF;
        int protection = file[MAGIC.length + 1] & 0xFF;
        if (version != VERSION || (protection != PROTECTION_NONE && protection != PROTECTION_PASSWORD)) {
            throw new BackupException(BackupException.Kind.UNSUPPORTED_FORMAT,
                    "unsupported backup version " + version + " / protection " + protection);
        }
        return protection;
    }

    private static byte[] header(int protection) {
        return new WireWriter().fixed(MAGIC).u8(VERSION).u8(protection).toByteArray();
    }

    private static byte[] deriveKey(String password, byte[] salt, int iterations) {
        char[] chars = password.toCharArray();
        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, Aes256Gcm.KEY_LENGTH * 8);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2WithHmacSHA256 unavailable", e);
        } finally {
            spec.clearPassword();
            Arrays.fill(chars, '\0');
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
