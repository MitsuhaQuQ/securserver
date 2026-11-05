package com.mtmrails.trustedserver.client;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

/**
 * 服务器地址 → 服务端身份公钥的 TOFU 记录（PROTOCOL.md 第 3 节），类似 SSH 的 known_hosts。
 *
 * <p>文本文件，每行 {@code <地址> <公钥十六进制>}，地址统一转为小写。文件损坏时抛出 {@link IOException}，
 * 绝不静默丢弃已有记录：那等于放弃对这些服务器的中间人防护。线程安全。
 */
public final class KnownServers {
    private final Path file;
    private Map<String, byte[]> entries;

    public KnownServers(Path file) {
        this.file = Objects.requireNonNull(file, "file");
    }

    public synchronized Optional<byte[]> get(String address) throws IOException {
        byte[] key = load().get(normalize(address));
        return Optional.ofNullable(key).map(byte[]::clone);
    }

    public synchronized void put(String address, byte[] serverIdPub) throws IOException {
        if (serverIdPub.length != 32) {
            throw new IllegalArgumentException("server identity key must be 32 bytes");
        }
        load().put(normalize(address), serverIdPub.clone());
        save();
    }

    /** 地址规范化：去掉首尾空白并转小写；地址中不允许出现空白。 */
    static String normalize(String address) {
        String normalized = address.trim().toLowerCase(Locale.ROOT);
        if (normalized.isEmpty() || normalized.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("invalid server address: " + address);
        }
        return normalized;
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
                if (parts.length != 2 || !parts[1].matches("[0-9a-fA-F]{64}")) {
                    throw new IOException(file + " line " + lineNumber + " is malformed; refusing to discard trust records");
                }
                loaded.put(normalize(parts[0]), HexFormat.of().parseHex(parts[1]));
            }
        }
        entries = loaded;
        return entries;
    }

    private void save() throws IOException {
        StringBuilder out = new StringBuilder("# TrustedServer known server identities: <address> <public key>\n");
        for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
            out.append(entry.getKey()).append(' ').append(HexFormat.of().formatHex(entry.getValue())).append('\n');
        }
        Path parent = file.toAbsolutePath().getParent();
        Files.createDirectories(parent);
        Path temp = Files.createTempFile(parent, "known_servers", ".tmp");
        try {
            Files.writeString(temp, out, StandardCharsets.UTF_8);
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }
}
