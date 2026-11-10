package com.mtmrails.trustedserver.client;

import com.mtmrails.trustedserver.core.crypto.PresharedKeyPolicy;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

/** 客户端服务器地址 → 32 字节 PSK 的只读文本配置。 */
public final class PresharedKeys {
    public static final int KEY_LENGTH = 32;
    private static final String HEADER = "# TrustedServer PSK: <server-address> <Base64 32-byte key>\n";

    private final Path file;
    private Map<String, byte[]> entries;

    public PresharedKeys(Path file) {
        this.file = Objects.requireNonNull(file, "file");
    }

    /** 首次启动写出只有说明的空文件，便于玩家配置。 */
    public synchronized void createTemplateIfMissing() throws IOException {
        if (!Files.exists(file)) {
            Files.createDirectories(file.toAbsolutePath().getParent());
            Files.writeString(file, HEADER, StandardCharsets.UTF_8);
        }
        try {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException e) {
            // 非 POSIX 文件系统沿用默认权限
        }
    }

    public synchronized Optional<byte[]> get(String address) throws IOException {
        byte[] key = load().get(KnownServers.normalize(address));
        return Optional.ofNullable(key).map(byte[]::clone);
    }

    /** 写入或替换指定服务器的 PSK；始终重写为规范格式并使用原子替换。 */
    public synchronized void put(String address, byte[] key) throws IOException {
        Objects.requireNonNull(key, "key");
        if (key.length != KEY_LENGTH) {
            throw new IllegalArgumentException("PSK must be exactly " + KEY_LENGTH + " bytes");
        }
        PresharedKeyPolicy.requireStrong(key);
        String normalized = KnownServers.normalize(address);
        Map<String, byte[]> updated = new TreeMap<>(load());
        updated.put(normalized, key.clone());
        write(updated);
        entries = updated;
    }

    /** 严格解析界面输入的单个 Base64 PSK。 */
    public static byte[] decode(String encoded) throws IOException {
        if (encoded == null || encoded.isBlank() || encoded.chars().anyMatch(Character::isWhitespace)) {
            throw new IOException("密钥必须是单行 Base64 文本");
        }
        byte[] key;
        try {
            key = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new IOException("密钥不是有效的 Base64", e);
        }
        if (key.length != KEY_LENGTH) {
            Arrays.fill(key, (byte) 0);
            throw new IOException("密钥解码后必须正好是 " + KEY_LENGTH + " 字节");
        }
        try {
            PresharedKeyPolicy.requireStrong(key);
        } catch (IllegalArgumentException e) {
            Arrays.fill(key, (byte) 0);
            throw new IOException(e.getMessage(), e);
        }
        return key;
    }

    private void write(Map<String, byte[]> values) throws IOException {
        Path parent = file.toAbsolutePath().getParent();
        Files.createDirectories(parent);
        Path temp = Files.createTempFile(parent, "psk", ".tmp");
        try {
            setPrivatePermissions(temp);
            StringBuilder content = new StringBuilder(HEADER);
            for (Map.Entry<String, byte[]> entry : values.entrySet()) {
                content.append(entry.getKey()).append(' ')
                        .append(Base64.getEncoder().encodeToString(entry.getValue())).append('\n');
            }
            Files.writeString(temp, content, StandardCharsets.UTF_8);
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
            setPrivatePermissions(file);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private Map<String, byte[]> load() throws IOException {
        if (entries != null) {
            return entries;
        }
        Map<String, byte[]> loaded = new TreeMap<>();
        if (Files.exists(file)) {
            int lineNumber = 0;
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                lineNumber++;
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                String[] parts = trimmed.split("\\s+");
                if (parts.length != 2) {
                    throw malformed(lineNumber);
                }
                String address = KnownServers.normalize(parts[0]);
                if (loaded.containsKey(address)) {
                    throw new IOException(file + " line " + lineNumber + " duplicates server " + address);
                }
                byte[] key;
                try {
                    key = Base64.getDecoder().decode(parts[1]);
                } catch (IllegalArgumentException e) {
                    throw malformed(lineNumber);
                }
                if (key.length != KEY_LENGTH) {
                    Arrays.fill(key, (byte) 0);
                    throw malformed(lineNumber);
                }
                try {
                    PresharedKeyPolicy.requireStrong(key);
                } catch (IllegalArgumentException e) {
                    Arrays.fill(key, (byte) 0);
                    throw malformed(lineNumber);
                }
                loaded.put(address, key);
            }
        }
        entries = loaded;
        return entries;
    }

    private IOException malformed(int line) {
        return new IOException(file + " line " + line + " must be <server-address> <Base64 32-byte key>");
    }

    private static void setPrivatePermissions(Path target) throws IOException {
        try {
            Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException e) {
            // 非 POSIX 文件系统沿用默认权限
        }
    }
}
