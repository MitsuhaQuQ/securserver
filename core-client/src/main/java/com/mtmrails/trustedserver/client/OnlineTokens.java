package com.mtmrails.trustedserver.client;

import com.mtmrails.trustedserver.core.crypto.OnlineTokenWire;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/** 客户端自动取得的正版账号令牌；按服务器身份、地址和正版 UUID 定位。 */
public final class OnlineTokens {
    private static final String HEADER = "# address server-identity uuid username-base64 token-base64\n";

    private record Entry(String address, byte[] serverIdentity, UUID playerId, String username, byte[] token) {
        private Entry {
            serverIdentity = serverIdentity.clone();
            token = token.clone();
        }
    }

    private final Path file;
    private List<Entry> entries;

    public OnlineTokens(Path file) {
        this.file = Objects.requireNonNull(file, "file");
    }

    public synchronized Optional<byte[]> get(String address, byte[] serverIdentity, UUID playerId, String username)
            throws IOException {
        String normalized = KnownServers.normalize(address);
        return load().stream().filter(e -> e.address().equals(normalized) && e.playerId().equals(playerId)
                && e.username().equalsIgnoreCase(username)
                && java.security.MessageDigest.isEqual(e.serverIdentity(), serverIdentity))
                .findFirst().map(e -> e.token().clone());
    }

    public synchronized void put(String address, byte[] serverIdentity, UUID playerId, String username, byte[] token)
            throws IOException {
        if (serverIdentity.length != 32 || token.length != OnlineTokenWire.TOKEN_LENGTH) {
            throw new IllegalArgumentException("invalid online token metadata");
        }
        String normalized = KnownServers.normalize(address);
        load().removeIf(e -> e.address().equals(normalized) && e.playerId().equals(playerId));
        entries.add(new Entry(normalized, serverIdentity, playerId, username, token));
        save();
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
                if (value.isEmpty() || value.startsWith("#")) continue;
                String[] parts = value.split("\\s+");
                try {
                    if (parts.length != 5) throw new IllegalArgumentException();
                    byte[] identity = HexFormat.of().parseHex(parts[1]);
                    UUID id = UUID.fromString(parts[2]);
                    String username = new String(Base64.getUrlDecoder().decode(parts[3]), StandardCharsets.UTF_8);
                    byte[] token = Base64.getDecoder().decode(parts[4]);
                    if (identity.length != 32 || token.length != OnlineTokenWire.TOKEN_LENGTH) {
                        throw new IllegalArgumentException();
                    }
                    loaded.add(new Entry(KnownServers.normalize(parts[0]), identity, id, username, token));
                } catch (IllegalArgumentException e) {
                    throw new IOException(file + " line " + lineNumber + " is malformed; refusing to discard tokens", e);
                }
            }
        }
        entries = loaded;
        return entries;
    }

    private void save() throws IOException {
        StringBuilder out = new StringBuilder(HEADER);
        for (Entry e : entries) {
            out.append(e.address()).append(' ').append(HexFormat.of().formatHex(e.serverIdentity())).append(' ')
                    .append(e.playerId()).append(' ').append(Base64.getUrlEncoder().withoutPadding()
                            .encodeToString(e.username().getBytes(StandardCharsets.UTF_8))).append(' ')
                    .append(Base64.getEncoder().encodeToString(e.token())).append('\n');
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
