package com.mtmrails.trustedserver.server.store;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * 玩家数据的 SQLite 存储（PROTOCOL.md 第 9 节）。
 *
 * <ul>
 *   <li>直接实例化 {@code org.sqlite.JDBC} 建立连接，不依赖 {@code DriverManager}：Forge / NeoForge 的模块化
 *       类加载环境下自动发现可能失败
 *   <li>表结构版本记录在 {@code PRAGMA user_version}，打开时依次迁移；遇到比本程序更新的版本拒绝打开
 *   <li>开启 WAL；本类非线程安全，由 AccountService 在单一数据库线程上串行调用
 * </ul>
 */
public final class SqliteStore implements AutoCloseable {
    /** 默认数据库位置（相对服务端根目录）。 */
    public static final String DEFAULT_PATH = "config/trustedserver/players.db";
    static final int SCHEMA_VERSION = 1;

    /** 各版本的迁移脚本：下标 i 把版本 i 升到 i + 1。 */
    private static final List<String[]> MIGRATIONS = List.<String[]>of(new String[] {
        """
        CREATE TABLE players (
          id             TEXT PRIMARY KEY,
          last_name      TEXT NOT NULL,
          player_pub     BLOB,
          password_hash  TEXT,
          recovery_hash  TEXT,
          restricted     INTEGER NOT NULL DEFAULT 1,
          created_at     INTEGER NOT NULL,
          last_login_at  INTEGER,
          last_ip        TEXT
        )""",
        """
        CREATE TABLE lockouts (
          subject        TEXT PRIMARY KEY,
          failures       INTEGER NOT NULL,
          locked_until   INTEGER
        )""",
        """
        CREATE TABLE audit_log (
          ts             INTEGER NOT NULL,
          subject        TEXT NOT NULL,
          event          TEXT NOT NULL,
          ip             TEXT,
          detail         TEXT
        )""",
        "CREATE INDEX audit_log_ts ON audit_log (ts)"
    });

    private final Connection connection;

    /** 恢复事务对登录密码的处理。SET 需要非空的新 Argon2id 哈希，其余模式不得携带哈希。 */
    public enum PasswordMutation {
        KEEP,
        SET,
        CLEAR
    }

    private SqliteStore(Connection connection) {
        this.connection = connection;
    }

    public static SqliteStore open(Path file) {
        try {
            Path parent = file.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
        } catch (IOException e) {
            throw new StorageException("cannot create database directory for " + file, e);
        }
        Connection connection;
        try {
            connection = new org.sqlite.JDBC().connect("jdbc:sqlite:" + file.toAbsolutePath(), new Properties());
            if (connection == null) {
                throw new StorageException("SQLite driver rejected " + file);
            }
        } catch (SQLException e) {
            throw new StorageException("cannot open database " + file, e);
        }
        try {
            SqliteStore store = new SqliteStore(connection);
            store.initialise();
            return store;
        } catch (SQLException e) {
            closeAfterOpenFailure(connection, e);
            throw new StorageException("cannot open database " + file, e);
        } catch (RuntimeException e) {
            closeAfterOpenFailure(connection, e);
            throw e;
        }
    }

    private static void closeAfterOpenFailure(Connection connection, Throwable failure) {
        try {
            connection.close();
        } catch (SQLException e) {
            failure.addSuppressed(e);
        }
    }

    private void initialise() throws SQLException {
        try (Statement st = connection.createStatement()) {
            st.execute("PRAGMA journal_mode = WAL");
            st.execute("PRAGMA busy_timeout = 5000");
        }
        int version = schemaVersion();
        if (version > SCHEMA_VERSION) {
            throw new StorageException("database schema version " + version
                    + " is newer than this mod supports (" + SCHEMA_VERSION + "); refusing to open");
        }
        for (int v = version; v < SCHEMA_VERSION; v++) {
            connection.setAutoCommit(false);
            try (Statement st = connection.createStatement()) {
                for (String sql : MIGRATIONS.get(v)) {
                    st.execute(sql);
                }
                st.execute("PRAGMA user_version = " + (v + 1));
                connection.commit();
            } catch (SQLException e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(true);
            }
        }
    }

    int schemaVersion() throws SQLException {
        try (Statement st = connection.createStatement(); ResultSet rs = st.executeQuery("PRAGMA user_version")) {
            return rs.getInt(1);
        }
    }

    String journalMode() throws SQLException {
        try (Statement st = connection.createStatement(); ResultSet rs = st.executeQuery("PRAGMA journal_mode")) {
            return rs.getString(1);
        }
    }

    // ---------------- players ----------------

    public Optional<Account> find(String id) {
        return query("SELECT * FROM players WHERE id = ?", ps -> ps.setString(1, id), rs -> rs.next()
                ? Optional.of(new Account(rs.getString("id"), rs.getString("last_name"), rs.getBytes("player_pub"),
                        rs.getString("password_hash"), rs.getString("recovery_hash"), rs.getInt("restricted") != 0,
                        rs.getLong("created_at"), nullableLong(rs, "last_login_at"),
                        rs.getString("last_ip")))
                : Optional.empty());
    }

    /** 新建受限、无密码的账号；已存在时返回 {@code false}。 */
    public boolean insertNew(String id, String name, byte[] playerPub, long now) {
        return update("INSERT INTO players (id, last_name, player_pub, restricted, created_at) VALUES (?, ?, ?, 1, ?)"
                + " ON CONFLICT(id) DO NOTHING", ps -> {
                    ps.setString(1, id);
                    ps.setString(2, name);
                    ps.setBytes(3, playerPub);
                    ps.setLong(4, now);
                }) == 1;
    }

    public boolean setPlayerPub(String id, byte[] playerPub) {
        return update("UPDATE players SET player_pub = ? WHERE id = ?", ps -> {
            ps.setBytes(1, playerPub);
            ps.setString(2, id);
        }) == 1;
    }

    /** 仅当当前没有绑定公钥时写入。 */
    public boolean claimUnboundKey(String id, byte[] playerPub) {
        return update("UPDATE players SET player_pub = ? WHERE id = ? AND player_pub IS NULL", ps -> {
            ps.setBytes(1, playerPub);
            ps.setString(2, id);
        }) == 1;
    }

    /** 设定登录密码并解除受限。 */
    public boolean setPasswordHash(String id, String hash) {
        return update("UPDATE players SET password_hash = ?, restricted = 0 WHERE id = ?", ps -> {
            ps.setString(1, hash);
            ps.setString(2, id);
        }) == 1;
    }

    public boolean setRecoveryHash(String id, String hash) {
        return update("UPDATE players SET recovery_hash = ? WHERE id = ?", ps -> {
            ps.setString(1, hash);
            ps.setString(2, id);
        }) == 1;
    }

    public boolean clearKey(String id) {
        return update("UPDATE players SET player_pub = NULL WHERE id = ?", ps -> ps.setString(1, id)) == 1;
    }

    /** 清除登录密码并恢复受限（PROTOCOL.md 6.1）。 */
    public boolean clearPassword(String id) {
        return update("UPDATE players SET password_hash = NULL, restricted = 1 WHERE id = ?",
                ps -> ps.setString(1, id)) == 1;
    }

    public boolean clearRecovery(String id) {
        return update("UPDATE players SET recovery_hash = NULL WHERE id = ?", ps -> ps.setString(1, id)) == 1;
    }

    public boolean setRestricted(String id, boolean restricted) {
        return update("UPDATE players SET restricted = ? WHERE id = ?", ps -> {
            ps.setInt(1, restricted ? 1 : 0);
            ps.setString(2, id);
        }) == 1;
    }

    public boolean delete(String id) {
        return update("DELETE FROM players WHERE id = ?", ps -> ps.setString(1, id)) == 1;
    }

    public boolean recordLogin(String id, String name, String ip, long now) {
        return update("UPDATE players SET last_name = ?, last_ip = ?, last_login_at = ? WHERE id = ?", ps -> {
            ps.setString(1, name);
            ps.setString(2, ip);
            ps.setLong(3, now);
            ps.setString(4, id);
        }) == 1;
    }

    /**
     * 以旧公钥为比较条件，原子地提交设备改绑、登录密码变更和恢复审计。
     * 条件不匹配（账号消失或并发连接已改绑）时不写入任何内容并返回 {@code false}。
     */
    public boolean recoverAccount(String id, byte[] expectedOldPub, byte[] newPub,
            PasswordMutation passwordMutation, String newPasswordHash, long now, AuditEvent event) {
        Objects.requireNonNull(id, "id");
        requirePlayerKey(expectedOldPub, "expectedOldPub");
        requirePlayerKey(newPub, "newPub");
        Objects.requireNonNull(passwordMutation, "passwordMutation");
        Objects.requireNonNull(event, "event");
        if ((passwordMutation == PasswordMutation.SET) != (newPasswordHash != null && !newPasswordHash.isEmpty())) {
            throw new IllegalArgumentException("SET requires a non-empty hash; KEEP/CLEAR must not carry one");
        }
        if (event != AuditEvent.ONLINE_PASSWORD_RESET && event != AuditEvent.RECOVERY_REBIND
                && event != AuditEvent.RECOVERY_PASSWORD_RESET) {
            throw new IllegalArgumentException("not a recovery audit event: " + event);
        }
        if ((event == AuditEvent.RECOVERY_REBIND) != (passwordMutation == PasswordMutation.KEEP)) {
            throw new IllegalArgumentException("RECOVERY_REBIND must KEEP the password; reset events must change it");
        }
        return transaction(() -> {
            String sql = switch (passwordMutation) {
                case KEEP -> "UPDATE players SET player_pub = ? WHERE id = ? AND player_pub = ?";
                case SET -> "UPDATE players SET player_pub = ?, password_hash = ?, restricted = 0"
                        + " WHERE id = ? AND player_pub = ?";
                case CLEAR -> "UPDATE players SET player_pub = ?, password_hash = NULL, restricted = 1"
                        + " WHERE id = ? AND player_pub = ?";
            };
            int changed = update(sql, ps -> {
                int column = 1;
                ps.setBytes(column++, newPub);
                if (passwordMutation == PasswordMutation.SET) {
                    ps.setString(column++, newPasswordHash);
                }
                ps.setString(column++, id);
                ps.setBytes(column, expectedOldPub);
            });
            if (changed == 0) {
                return false;
            }
            if (passwordMutation != PasswordMutation.KEEP) {
                clearLockout("name:" + id);
            }
            audit(now, id, event, null, passwordMutation.name().toLowerCase(java.util.Locale.ROOT));
            return true;
        });
    }

    // ---------------- lockouts ----------------

    /** 累计失败次数加 1，返回新的次数。 */
    public int addFailure(String subject) {
        update("INSERT INTO lockouts (subject, failures) VALUES (?, 1)"
                + " ON CONFLICT(subject) DO UPDATE SET failures = failures + 1", ps -> ps.setString(1, subject));
        return failures(subject);
    }

    public int failures(String subject) {
        return query("SELECT failures FROM lockouts WHERE subject = ?", ps -> ps.setString(1, subject),
                rs -> rs.next() ? rs.getInt(1) : 0);
    }

    public void lockUntil(String subject, long until) {
        update("INSERT INTO lockouts (subject, failures, locked_until) VALUES (?, 0, ?)"
                + " ON CONFLICT(subject) DO UPDATE SET locked_until = excluded.locked_until", ps -> {
                    ps.setString(1, subject);
                    ps.setLong(2, until);
                });
    }

    public Optional<Long> lockedUntil(String subject) {
        return query("SELECT locked_until FROM lockouts WHERE subject = ?", ps -> ps.setString(1, subject),
                rs -> rs.next() ? Optional.ofNullable(nullableLong(rs, "locked_until")) : Optional.empty());
    }

    /** 清除累计次数与锁定（登录成功后）。 */
    public void clearLockout(String subject) {
        update("DELETE FROM lockouts WHERE subject = ?", ps -> ps.setString(1, subject));
    }

    // ---------------- audit ----------------

    public void audit(long ts, String subject, AuditEvent event, String ip, String detail) {
        update("INSERT INTO audit_log (ts, subject, event, ip, detail) VALUES (?, ?, ?, ?, ?)", ps -> {
            ps.setLong(1, ts);
            ps.setString(2, subject);
            ps.setString(3, event.id());
            ps.setString(4, ip);
            ps.setString(5, detail);
        });
    }

    public List<AuditRecord> auditFor(String subject) {
        return query("SELECT ts, subject, event, ip, detail FROM audit_log WHERE subject = ? ORDER BY rowid",
                ps -> ps.setString(1, subject), rs -> {
                    List<AuditRecord> out = new ArrayList<>();
                    while (rs.next()) {
                        out.add(new AuditRecord(rs.getLong(1), rs.getString(2), rs.getString(3), rs.getString(4),
                                rs.getString(5)));
                    }
                    return out;
                });
    }

    /** 删除早于 {@code before} 的审计记录，返回删除条数。 */
    public int purgeAuditBefore(long before) {
        return update("DELETE FROM audit_log WHERE ts < ?", ps -> ps.setLong(1, before));
    }

    @Override
    public void close() {
        try {
            connection.close();
        } catch (SQLException e) {
            throw new StorageException("cannot close database", e);
        }
    }

    // ---------------- helpers ----------------

    private interface Binder {
        void bind(PreparedStatement ps) throws SQLException;
    }

    private interface Reader<T> {
        T read(ResultSet rs) throws SQLException;
    }

    /** sqlite-jdbc 的 getObject(列, Long.class) 遇到 NULL 会报错，这里手动判断。 */
    private static Long nullableLong(ResultSet rs, String column) throws SQLException {
        long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    private int update(String sql, Binder binder) {
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            binder.bind(ps);
            return ps.executeUpdate();
        } catch (SQLException e) {
            throw new StorageException("database update failed", e);
        }
    }

    private <T> T query(String sql, Binder binder, Reader<T> reader) {
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            binder.bind(ps);
            try (ResultSet rs = ps.executeQuery()) {
                return reader.read(rs);
            }
        } catch (SQLException e) {
            throw new StorageException("database query failed", e);
        }
    }

    private <T> T transaction(Supplier<T> body) {
        try {
            if (!connection.getAutoCommit()) {
                throw new StorageException("nested database transaction is not supported");
            }
            connection.setAutoCommit(false);
            try {
                T result = body.get();
                connection.commit();
                return result;
            } catch (RuntimeException | Error e) {
                try {
                    connection.rollback();
                } catch (SQLException rollback) {
                    e.addSuppressed(rollback);
                }
                throw e;
            } finally {
                connection.setAutoCommit(true);
            }
        } catch (SQLException e) {
            throw new StorageException("database transaction failed", e);
        }
    }

    private static void requirePlayerKey(byte[] key, String name) {
        Objects.requireNonNull(key, name);
        if (key.length != 32) {
            throw new IllegalArgumentException(name + " must be 32 bytes");
        }
    }
}
