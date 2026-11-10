package com.mtmrails.trustedserver.server;

import com.mtmrails.trustedserver.core.crypto.PresharedKeyPolicy;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/** 服务端第一阶段 PSK 文件：一行 Base64 编码的 32 字节随机密钥。 */
public final class PresharedKeyFile {
    public static final String DEFAULT_PATH = "config/trustedserver/psk.key";
    public static final int KEY_LENGTH = 32;

    private PresharedKeyFile() {
    }

    public record Loaded(byte[] key, boolean created) {
        public Loaded {
            key = exactKey(key);
            PresharedKeyPolicy.requireStrong(key);
        }

        @Override
        public byte[] key() {
            return key.clone();
        }
    }

    public static Loaded loadOrCreate(Path file, SecureRandom random) throws IOException {
        Objects.requireNonNull(file, "file");
        Objects.requireNonNull(random, "random");
        if (Files.exists(file)) {
            restrict(file);
            return new Loaded(read(file), false);
        }
        byte[] key = new byte[KEY_LENGTH];
        do {
            random.nextBytes(key);
        } while (!strong(key));
        write(file, key);
        return new Loaded(key, true);
    }

    private static byte[] read(Path file) throws IOException {
        String encoded = Files.readString(file, StandardCharsets.US_ASCII).trim();
        if (encoded.isEmpty() || encoded.chars().anyMatch(Character::isWhitespace)) {
            throw new IOException("PSK file " + file + " must contain exactly one Base64 value");
        }
        byte[] key;
        try {
            key = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new IOException("PSK file " + file + " is not valid Base64", e);
        }
        if (key.length != KEY_LENGTH) {
            Arrays.fill(key, (byte) 0);
            throw new IOException("PSK file " + file + " must decode to exactly " + KEY_LENGTH + " bytes");
        }
        try {
            PresharedKeyPolicy.requireStrong(key);
        } catch (IllegalArgumentException e) {
            Arrays.fill(key, (byte) 0);
            throw new IOException("PSK file " + file + " contains a weak key: " + e.getMessage(), e);
        }
        return key;
    }

    private static void write(Path file, byte[] key) throws IOException {
        Path parent = file.toAbsolutePath().getParent();
        Files.createDirectories(parent);
        Path temp = Files.createTempFile(parent, "psk", ".tmp");
        try {
            restrict(temp);
            Files.writeString(temp, Base64.getEncoder().encodeToString(exactKey(key)) + "\n",
                    StandardCharsets.US_ASCII);
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, file);
            }
            restrict(file);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private static void restrict(Path file) throws IOException {
        try {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException e) {
            // 非 POSIX 文件系统沿用默认权限
        }
    }

    private static byte[] exactKey(byte[] key) {
        Objects.requireNonNull(key, "key");
        if (key.length != KEY_LENGTH) {
            throw new IllegalArgumentException("PSK must be exactly " + KEY_LENGTH + " bytes");
        }
        return key.clone();
    }

    private static boolean strong(byte[] key) {
        try {
            PresharedKeyPolicy.requireStrong(key);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
