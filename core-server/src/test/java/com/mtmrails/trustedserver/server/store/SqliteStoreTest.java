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
}
