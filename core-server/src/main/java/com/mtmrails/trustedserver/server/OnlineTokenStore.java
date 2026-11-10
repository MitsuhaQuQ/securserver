package com.mtmrails.trustedserver.server;

import com.mtmrails.trustedserver.core.crypto.OnlineTokenWire;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** 正版 UUID 的可撤销客户端令牌存储；每个账号最多保留八台客户端。 */
public final class OnlineTokenStore {
    public static final int MAX_TOKENS_PER_PLAYER = 8;
    private static final String HEADER = "# UUID issued-at username-base64 token-base64\n";

    public record Entry(UUID playerId, long issuedAt, String username, byte[] token) {
        public Entry {
            Objects.requireNonNull(playerId, "playerId");
            Objects.requireNonNull(username, "username");
            if (token == null || token.length != OnlineTokenWire.TOKEN_LENGTH) {
                throw new IllegalArgumentException("online token must be 32 bytes");
            }
            token = token.clone();
        }

        @Override public byte[] token() { return token.clone(); }
    }

    private final Path file;
    private List<Entry> entries;

    public OnlineTokenStore(Path file) {
        this.file = Objects.requireNonNull(file, "file");
    }

    public synchronized List<byte[]> tokens(UUID playerId) throws IOException {
        return load().stream().filter(e -> e.playerId().equals(playerId))
                .sorted(Comparator.comparingLong(Entry::issuedAt).reversed()).map(Entry::token).toList();
    }

    public synchronized void validate() throws IOException {
        load();
    }

    /** 已经由 Mojang session 确认过的名字保留给正版身份，离线回退不得同名顶替。 */
    public synchronized boolean isReservedName(String username) throws IOException {
        return load().stream().anyMatch(e -> e.username().equalsIgnoreCase(username));
    }

    public synchronized void add(UUID playerId, String username, byte[] token) throws IOException {
        List<Entry> all = load();
        boolean conflictingClaim = all.stream().anyMatch(e -> e.username().equalsIgnoreCase(username)
                && !e.playerId().equals(playerId));
        if (conflictingClaim) {
            throw new IOException("online username is already claimed by another UUID");
        }
        long now = Instant.now().toEpochMilli();
        all.add(new Entry(playerId, now, username, token));
        List<Entry> same = all.stream().filter(e -> e.playerId().equals(playerId))
                .sorted(Comparator.comparingLong(Entry::issuedAt).reversed()).toList();
        if (same.size() > MAX_TOKENS_PER_PLAYER) {
            for (Entry remove : same.subList(MAX_TOKENS_PER_PLAYER, same.size())) {
                all.remove(remove);
            }
        }
        save();
    }

    /** 管理员显式恢复离线名字时使用；不会由登录流程自动调用。 */
    public synchronized boolean clearClaim(String username) throws IOException {
        boolean removed = load().removeIf(e -> e.username().equalsIgnoreCase(username));
        if (removed) {
            save();
        }
        return removed;
    }

    private List<Entry> load() throws IOException {
        if (entries != null) {
            return entries;
        }
        List<Entry> loaded = new ArrayList<>();
        if (Files.exists(file)) {
            int lineNumber = 0;
            for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
                lineNumber++;
                String value = line.trim();
                if (value.isEmpty() || value.startsWith("#")) {
                    continue;
                }
                String[] parts = value.split("\\s+");
                try {
                    if (parts.length != 4) {
                        throw new IllegalArgumentException();
                    }
                    UUID playerId = UUID.fromString(parts[0]);
                    long issuedAt = Long.parseLong(parts[1]);
                    String username = new String(Base64.getUrlDecoder().decode(parts[2]), StandardCharsets.UTF_8);
                    byte[] token = Base64.getDecoder().decode(parts[3]);
                    loaded.add(new Entry(playerId, issuedAt, username, token));
                } catch (IllegalArgumentException e) {
                    throw new IOException(file + " line " + lineNumber + " is malformed; refusing to start", e);
                }
            }
        }
        entries = loaded;
        return entries;
    }

    private void save() throws IOException {
        StringBuilder out = new StringBuilder(HEADER);
        for (Entry entry : entries) {
            out.append(entry.playerId()).append(' ').append(entry.issuedAt()).append(' ')
                    .append(Base64.getUrlEncoder().withoutPadding().encodeToString(
                            entry.username().getBytes(StandardCharsets.UTF_8))).append(' ')
                    .append(Base64.getEncoder().encodeToString(entry.token())).append('\n');
        }
        Path parent = file.toAbsolutePath().getParent();
        Files.createDirectories(parent);
        Path temp = Files.createTempFile(parent, "online_tokens", ".tmp");
        try {
            Files.writeString(temp, out, StandardCharsets.UTF_8);
            restrict(temp);
            try {
                Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING);
            }
            restrict(file);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private static void restrict(Path target) throws IOException {
        try {
            Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException e) {
            // 非 POSIX 文件系统沿用默认权限
        }
    }
}
