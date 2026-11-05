package com.mtmrails.trustedserver.server;

import com.mtmrails.trustedserver.core.crypto.CryptoException;
import com.mtmrails.trustedserver.core.crypto.Ed25519;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * 服务端 Ed25519 身份密钥（PROTOCOL.md 第 3 节）：{@code config/trustedserver/server_identity.key}。
 *
 * <p>文件格式：{@code "TSID" | u8 版本 = 1 | 公钥 32 | 私钥种子 32 | SHA-256 校验和 32}。
 * 不存在时生成；存在但损坏时抛出 {@link IOException}，绝不自动重新生成——那会让所有玩家看到“服务器身份已变化”。
 */
public final class ServerIdentity {
    public static final String DEFAULT_PATH = "config/trustedserver/server_identity.key";
    private static final byte[] MAGIC = {'T', 'S', 'I', 'D'};
    private static final int VERSION = 1;
    private static final int LENGTH = MAGIC.length + 1 + 32 + 32 + 32;

    private ServerIdentity() {
    }

    /** 加载结果：密钥，以及本次是否为新生成。 */
    public record Loaded(Ed25519.KeyPairData key, boolean created) {
        /** 公钥指纹（十六进制），与客户端界面显示的一致，供服主公布、玩家核对。 */
        public String fingerprint() {
            return ServerIdentity.fingerprint(key.publicKey());
        }
    }

    public static Loaded loadOrCreate(Path file, SecureRandom random) throws IOException {
        if (Files.exists(file)) {
            return new Loaded(read(file), false);
        }
        Ed25519.KeyPairData key = Ed25519.generate(random);
        write(file, key);
        return new Loaded(key, true);
    }

    public static String fingerprint(byte[] publicKey) {
        return HexFormat.of().formatHex(publicKey);
    }

    private static Ed25519.KeyPairData read(Path file) throws IOException {
        byte[] content = Files.readAllBytes(file);
        try {
            if (content.length != LENGTH || !Arrays.equals(content, 0, MAGIC.length, MAGIC, 0, MAGIC.length)
                    || content[MAGIC.length] != VERSION) {
                throw new IOException("server identity file " + file + " has an unknown format; refusing to replace it");
            }
            byte[] body = Arrays.copyOf(content, LENGTH - 32);
            if (!MessageDigest.isEqual(sha256(body), Arrays.copyOfRange(content, LENGTH - 32, LENGTH))) {
                throw new IOException("server identity file " + file + " is corrupted; refusing to replace it");
            }
            byte[] pub = Arrays.copyOfRange(content, 5, 37);
            byte[] seed = Arrays.copyOfRange(content, 37, 69);
            try {
                return Ed25519.fromSeed(seed, pub);
            } catch (CryptoException e) {
                throw new IOException("server identity file " + file + " has a mismatched key pair", e);
            } finally {
                Arrays.fill(seed, (byte) 0);
            }
        } finally {
            Arrays.fill(content, (byte) 0);
        }
    }

    private static void write(Path file, Ed25519.KeyPairData key) throws IOException {
        byte[] body = new byte[LENGTH - 32];
        System.arraycopy(MAGIC, 0, body, 0, MAGIC.length);
        body[MAGIC.length] = VERSION;
        System.arraycopy(key.publicKey(), 0, body, 5, 32);
        byte[] seed = key.seed();
        System.arraycopy(seed, 0, body, 37, 32);
        Arrays.fill(seed, (byte) 0);
        byte[] content = Arrays.copyOf(body, LENGTH);
        System.arraycopy(sha256(body), 0, content, LENGTH - 32, 32);
        Arrays.fill(body, (byte) 0);

        Path parent = file.toAbsolutePath().getParent();
        Files.createDirectories(parent);
        Path temp = Files.createTempFile(parent, "identity", ".tmp");
        try {
            try {
                Files.setPosixFilePermissions(temp, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException e) {
                // 非 POSIX 文件系统
            }
            Files.write(temp, content);
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, file);
            }
        } finally {
            Files.deleteIfExists(temp);
            Arrays.fill(content, (byte) 0);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
