package com.mtmrails.trustedserver.server.store;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SqliteStoreTest {
    @TempDir
    Path dir;

    private Path db() {
        return dir.resolve("nested/players.db");
    }

    @Test
    void createsSchemaWithWal() throws Exception {
        try (SqliteStore store = SqliteStore.open(db())) {
            assertEquals(SqliteStore.SCHEMA_VERSION, store.schemaVersion());
            assertEquals("wal", store.journalMode());
        }
    }

    @Test
    void accountLifecycle() {
        byte[] pub = new byte[32];
        pub[0] = 1;
        try (SqliteStore store = SqliteStore.open(db())) {
            assertTrue(store.insertNew("steve", "Steve", pub, 1000));
            assertFalse(store.insertNew("steve", "Steve", pub, 2000));
            Account a = store.find("steve").orElseThrow();
            assertArrayEquals(pub, a.playerPub());
            assertTrue(a.restricted());
            assertNull(a.passwordHash());
            assertEquals(1000, a.createdAt());
            assertNull(a.lastLoginAt());

            assertTrue(store.setPasswordHash("steve", "h1"));
            assertFalse(store.find("steve").orElseThrow().restricted());
            assertTrue(store.clearPassword("steve"));
            assertTrue(store.find("steve").orElseThrow().restricted());

            assertFalse(store.claimUnboundKey("steve", new byte[32]));
            assertTrue(store.clearKey("steve"));
            assertNull(store.find("steve").orElseThrow().playerPub());
            assertTrue(store.claimUnboundKey("steve", pub));
            assertFalse(store.claimUnboundKey("steve", pub));

            assertTrue(store.recordLogin("steve", "STEVE", "10.0.0.1", 5000));
            Account after = store.find("steve").orElseThrow();
            assertEquals("STEVE", after.lastName());
            assertEquals(5000L, after.lastLoginAt());
            assertEquals("10.0.0.1", after.lastIp());

            assertTrue(store.delete("steve"));
            assertEquals(Optional.empty(), store.find("steve"));
            assertFalse(store.setRestricted("steve", false));
        }
    }

    @Test
    void persistsAcrossReopen() {
        try (SqliteStore store = SqliteStore.open(db())) {
            store.insertNew("steve", "Steve", new byte[32], 1);
        }
        try (SqliteStore store = SqliteStore.open(db())) {
            assertTrue(store.find("steve").isPresent());
        }
    }

    @Test
    void lockouts() {
        try (SqliteStore store = SqliteStore.open(db())) {
            assertEquals(0, store.failures("name:steve"));
            assertEquals(1, store.addFailure("name:steve"));
            assertEquals(2, store.addFailure("name:steve"));
            assertEquals(Optional.empty(), store.lockedUntil("name:steve"));
            store.lockUntil("name:steve", 9000);
            assertEquals(Optional.of(9000L), store.lockedUntil("name:steve"));
            assertEquals(2, store.failures("name:steve"));
            store.clearLockout("name:steve");
            assertEquals(0, store.failures("name:steve"));
            assertEquals(Optional.empty(), store.lockedUntil("name:steve"));
        }
    }

    @Test
    void auditAndRetention() {
        try (SqliteStore store = SqliteStore.open(db())) {
            store.audit(100, "steve", AuditEvent.BIND, null, null);
            store.audit(200, "steve", AuditEvent.LOGIN_OK, "1.2.3.4", "x");
            assertEquals(List.of(new AuditRecord(100, "steve", "bind", null, null),
                    new AuditRecord(200, "steve", "login_ok", "1.2.3.4", "x")), store.auditFor("steve"));
            assertEquals(1, store.purgeAuditBefore(150));
            assertEquals(1, store.auditFor("steve").size());
        }
    }

    @Test
    void refusesNewerSchema() throws Exception {
        SqliteStore.open(db()).close();
        try (Connection raw = new org.sqlite.JDBC().connect("jdbc:sqlite:" + db().toAbsolutePath(), new Properties());
                Statement st = raw.createStatement()) {
            st.execute("PRAGMA user_version = 99");
        }
        StorageException e = assertThrows(StorageException.class, () -> SqliteStore.open(db()));
        assertTrue(e.getMessage().contains("newer"));
    }

    @Test
    void sqlInjectionInIdsIsInert() {
        try (SqliteStore store = SqliteStore.open(db())) {
            String evil = "x'; DROP TABLE players; --";
            assertTrue(store.insertNew(evil, evil, new byte[32], 1));
            assertTrue(store.find(evil).isPresent());
            assertTrue(store.insertNew("steve", "Steve", new byte[32], 1));
        }
    }

    @Test
    void recoveryTransactionComparesOldKeyAndAppliesPasswordMutation() {
        byte[] oldKey = key(1);
        try (SqliteStore store = SqliteStore.open(db())) {
            assertTrue(store.insertNew("steve", "Steve", oldKey, 1));
            assertTrue(store.setPasswordHash("steve", "old-hash"));

            assertFalse(store.recoverAccount("steve", key(9), key(2), SqliteStore.PasswordMutation.SET,
                    "attacker-hash", 10, AuditEvent.RECOVERY_PASSWORD_RESET));
            assertArrayEquals(oldKey, store.find("steve").orElseThrow().playerPub());
            assertEquals("old-hash", store.find("steve").orElseThrow().passwordHash());
            assertEquals(List.of(), store.auditFor("steve"));

            assertTrue(store.recoverAccount("steve", oldKey, key(2), SqliteStore.PasswordMutation.KEEP,
                    null, 20, AuditEvent.RECOVERY_REBIND));
            assertArrayEquals(key(2), store.find("steve").orElseThrow().playerPub());
            assertEquals("old-hash", store.find("steve").orElseThrow().passwordHash());

            store.addFailure("name:steve");
            store.lockUntil("name:steve", 9999);
            assertTrue(store.recoverAccount("steve", key(2), key(3), SqliteStore.PasswordMutation.SET,
                    "new-hash", 30, AuditEvent.RECOVERY_PASSWORD_RESET));
            assertEquals("new-hash", store.find("steve").orElseThrow().passwordHash());
            assertFalse(store.find("steve").orElseThrow().restricted());
            assertEquals(0, store.failures("name:steve"));
            assertEquals(Optional.empty(), store.lockedUntil("name:steve"));

            assertTrue(store.recoverAccount("steve", key(3), key(4), SqliteStore.PasswordMutation.CLEAR,
                    null, 40, AuditEvent.ONLINE_PASSWORD_RESET));
            Account cleared = store.find("steve").orElseThrow();
            assertArrayEquals(key(4), cleared.playerPub());
            assertNull(cleared.passwordHash());
            assertTrue(cleared.restricted());
            assertEquals(List.of("recovery_rebind", "recovery_password_reset", "online_password_reset"),
                    store.auditFor("steve").stream().map(AuditRecord::event).toList());
            assertThrows(IllegalArgumentException.class, () -> store.recoverAccount("steve", key(4), key(5),
                    SqliteStore.PasswordMutation.KEEP, null, 50, AuditEvent.ONLINE_PASSWORD_RESET));
        }
    }

    @Test
    void recoveryTransactionRollsBackAccountWhenAuditFails() throws Exception {
        byte[] oldKey = key(1);
        try (SqliteStore store = SqliteStore.open(db())) {
            assertTrue(store.insertNew("steve", "Steve", oldKey, 1));
            try (Connection raw = new org.sqlite.JDBC().connect("jdbc:sqlite:" + db().toAbsolutePath(),
                    new Properties()); Statement st = raw.createStatement()) {
                st.execute("CREATE TRIGGER reject_recovery_audit BEFORE INSERT ON audit_log "
                        + "WHEN NEW.event = 'recovery_rebind' BEGIN SELECT RAISE(ABORT, 'test'); END");
            }
            assertThrows(StorageException.class, () -> store.recoverAccount("steve", oldKey, key(2),
                    SqliteStore.PasswordMutation.KEEP, null, 20, AuditEvent.RECOVERY_REBIND));
            assertArrayEquals(oldKey, store.find("steve").orElseThrow().playerPub());
            assertTrue(store.auditFor("steve").isEmpty());
        }
    }

    private static byte[] key(int firstByte) {
        byte[] key = new byte[32];
        key[0] = (byte) firstByte;
        return key;
    }
}
