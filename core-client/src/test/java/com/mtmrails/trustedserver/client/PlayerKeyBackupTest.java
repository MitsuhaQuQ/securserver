package com.mtmrails.trustedserver.client;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mtmrails.trustedserver.core.crypto.Ed25519;
import com.mtmrails.trustedserver.core.wire.WireWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PlayerKeyBackupTest {
    private static final SecureRandom RANDOM = new SecureRandom();
    /** 测试中加密导出用的最低允许迭代次数，避免测试过慢。 */
    private static final int FAST = PlayerKeyBackup.MIN_ITERATIONS;

    @TempDir
    Path dir;

    private static StoredKey key(String username) {
        return new StoredKey(PlayerKeyStoreTest.target(username), Ed25519.generate(RANDOM));
    }

    private static void assertSameKeys(List<StoredKey> expected, List<StoredKey> actual) {
        assertEquals(expected.size(), actual.size());
        for (int i = 0; i < expected.size(); i++) {
            assertEquals(expected.get(i).target(), actual.get(i).target());
            assertArrayEquals(expected.get(i).key().publicKey(), actual.get(i).key().publicKey());
            assertArrayEquals(expected.get(i).key().seed(), actual.get(i).key().seed());
        }
    }

    private static BackupException.Kind failureKind(byte[] file, Optional<String> password) {
        return assertThrows(BackupException.class, () -> PlayerKeyBackup.read(file, password)).kind();
    }

    // ---- 往返 ----

    @Test
    void plaintextRoundTrip() throws Exception {
        List<StoredKey> keys = List.of(key("Steve"), key("Alex"));
        byte[] file = PlayerKeyBackup.export(keys, Optional.empty(), RANDOM);
        assertFalse(PlayerKeyBackup.isEncrypted(file));
        assertSameKeys(keys, PlayerKeyBackup.read(file, Optional.empty()));
        // 空串等同于不设密码
        assertFalse(PlayerKeyBackup.isEncrypted(PlayerKeyBackup.export(keys, Optional.of(""), RANDOM)));
    }

    @Test
    void passwordProtectedRoundTrip() throws Exception {
        List<StoredKey> keys = List.of(key("Steve"));
        byte[] file = PlayerKeyBackup.export(keys, Optional.of("备份密码 pw"), RANDOM, FAST);
        assertTrue(PlayerKeyBackup.isEncrypted(file));
        assertSameKeys(keys, PlayerKeyBackup.read(file, Optional.of("备份密码 pw")));
    }

    @Test
    void defaultExportUsesRecommendedIterations() throws Exception {
        byte[] file = PlayerKeyBackup.export(List.of(key("Steve")), Optional.of("pw"), RANDOM);
        int iterations = ((file[22] & 0xFF) << 24) | ((file[23] & 0xFF) << 16) | ((file[24] & 0xFF) << 8)
                | (file[25] & 0xFF);
        assertEquals(PlayerKeyBackup.DEFAULT_ITERATIONS, iterations);
        assertEquals(1, PlayerKeyBackup.read(file, Optional.of("pw")).size());
    }

    @Test
    void encryptedFileRevealsNoKeyMaterial() throws Exception {
        StoredKey stored = key("SecretName");
        byte[] file = PlayerKeyBackup.export(List.of(stored), Optional.of("pw"), RANDOM, FAST);
        String hex = HexFormat.of().formatHex(file);
        assertFalse(hex.contains(HexFormat.of().formatHex(stored.key().seed())));
        assertFalse(hex.contains(HexFormat.of().formatHex(stored.key().publicKey())));
        assertFalse(new String(file, StandardCharsets.ISO_8859_1).contains("SecretName"));
    }

    // ---- 密码 ----

    @Test
    void wrongOrMissingPassword() throws Exception {
        byte[] file = PlayerKeyBackup.export(List.of(key("Steve")), Optional.of("right"), RANDOM, FAST);
        assertEquals(BackupException.Kind.WRONG_PASSWORD_OR_CORRUPTED, failureKind(file, Optional.of("wrong")));
        assertEquals(BackupException.Kind.PASSWORD_REQUIRED, failureKind(file, Optional.empty()));
        assertEquals(BackupException.Kind.PASSWORD_REQUIRED, failureKind(file, Optional.of("")));
    }

    @Test
    void encryptedHeaderIsAuthenticated() throws Exception {
        byte[] file = PlayerKeyBackup.export(List.of(key("Steve")), Optional.of("pw"), RANDOM, FAST);
        // salt、nonce 的每个字节都参与认证（迭代次数单独测试）
        for (int index : new int[] {6, 21, 26, 37}) {
            byte[] tampered = file.clone();
            tampered[index] ^= 1;
            assertEquals(BackupException.Kind.WRONG_PASSWORD_OR_CORRUPTED, failureKind(tampered, Optional.of("pw")),
                    "byte " + index);
        }
        byte[] tamperedIterations = file.clone();
        tamperedIterations[25] ^= 1; // 仍在允许范围内，但与加密时不同
        assertEquals(BackupException.Kind.WRONG_PASSWORD_OR_CORRUPTED,
                failureKind(tamperedIterations, Optional.of("pw")));
        byte[] tamperedBody = file.clone();
        tamperedBody[tamperedBody.length - 1] ^= 1;
        assertEquals(BackupException.Kind.WRONG_PASSWORD_OR_CORRUPTED, failureKind(tamperedBody, Optional.of("pw")));
    }

    @Test
    void iterationCountOutsideAllowedRangeIsRejected() throws Exception {
        byte[] weak = PlayerKeyBackup.export(List.of(key("Steve")), Optional.of("pw"), RANDOM, 1000);
        assertEquals(BackupException.Kind.UNSUPPORTED_FORMAT, failureKind(weak, Optional.of("pw")));
        byte[] huge = weak.clone();
        huge[22] = (byte) 0x7F; // 约 21 亿次
        assertEquals(BackupException.Kind.UNSUPPORTED_FORMAT, failureKind(huge, Optional.of("pw")));
    }

    // ---- 损坏与篡改 ----

    @Test
    void plaintextTamperingIsDetected() throws Exception {
        byte[] file = PlayerKeyBackup.export(List.of(key("Steve")), Optional.empty(), RANDOM);
        for (int index = 6; index < file.length; index++) {
            byte[] tampered = file.clone();
            tampered[index] ^= 1;
            assertEquals(BackupException.Kind.CORRUPTED, failureKind(tampered, Optional.empty()), "byte " + index);
        }
    }

    @Test
    void everyTruncationIsRejected() throws Exception {
        for (Optional<String> password : List.of(Optional.<String>empty(), Optional.of("pw"))) {
            byte[] file = PlayerKeyBackup.export(List.of(key("Steve")), password, RANDOM, FAST);
            for (int length = 0; length < file.length; length++) {
                byte[] truncated = Arrays.copyOf(file, length);
                assertThrows(BackupException.class, () -> PlayerKeyBackup.read(truncated, password),
                        "length " + length);
            }
        }
    }

    /** 绕过 export，手工构造带正确校验和的明文备份。 */
    private static byte[] craftPlaintext(WireWriter body) {
        byte[] content = new WireWriter().fixed(new byte[] {'T', 'S', 'K', 'B', 1, 0}).fixed(body.toByteArray())
                .toByteArray();
        byte[] out = Arrays.copyOf(content, content.length + 32);
        System.arraycopy(PlayerKeyStore.sha256(content), 0, out, content.length, 32);
        return out;
    }

    @Test
    void mismatchedKeyPairIsRejected() {
        StoredKey a = key("Steve");
        StoredKey b = key("Alex");
        WireWriter body = new WireWriter().varInt(1)
                .fixed(a.target().serverIdPub()).string("Steve", 256)
                .fixed(a.key().publicKey()).fixed(b.key().seed()); // 私钥不属于这个公钥
        BackupException e = assertThrows(BackupException.class,
                () -> PlayerKeyBackup.read(craftPlaintext(body), Optional.empty()));
        assertEquals(BackupException.Kind.CORRUPTED, e.kind());
        assertTrue(e.getMessage().contains("does not match"));
    }

    @Test
    void duplicateTargetsAreRejected() {
        StoredKey a = key("Steve");
        assertThrows(IllegalArgumentException.class,
                () -> PlayerKeyBackup.export(List.of(a, a), Optional.empty(), RANDOM));
        WireWriter body = new WireWriter().varInt(2);
        for (int i = 0; i < 2; i++) {
            body.fixed(a.target().serverIdPub()).string("Steve", 256).fixed(a.key().publicKey()).fixed(a.key().seed());
        }
        assertEquals(BackupException.Kind.CORRUPTED, failureKind(craftPlaintext(body), Optional.empty()));
    }

    @Test
    void emptyOrForeignFilesAreRejected() {
        IllegalArgumentException empty = assertThrows(IllegalArgumentException.class,
                () -> PlayerKeyBackup.export(List.of(), Optional.empty(), RANDOM));
        assertTrue(empty.getMessage().contains("no keys selected"));
        assertEquals(BackupException.Kind.CORRUPTED,
                failureKind(craftPlaintext(new WireWriter().varInt(0)), Optional.empty()));
        assertEquals(BackupException.Kind.UNSUPPORTED_FORMAT,
                failureKind("{\"not\":\"a backup\"}".getBytes(StandardCharsets.UTF_8), Optional.empty()));
        assertEquals(BackupException.Kind.UNSUPPORTED_FORMAT,
                failureKind(new byte[] {'T', 'S', 'K', 'B', 2, 0}, Optional.empty()));
        assertEquals(BackupException.Kind.UNSUPPORTED_FORMAT,
                failureKind(new byte[] {'T', 'S', 'K', 'B', 1, 9}, Optional.empty()));
        assertEquals(BackupException.Kind.UNSUPPORTED_FORMAT,
                failureKind(new byte[PlayerKeyBackup.MAX_FILE_SIZE + 1], Optional.empty()));
    }

    // ---- 迁移到另一台电脑 ----

    @Test
    void migrateAllKeysToAnotherComputer() throws Exception {
        PlayerKeyStore oldPc = new PlayerKeyStore(dir.resolve("old"));
        Ed25519.KeyPairData steve = oldPc.getOrCreate(PlayerKeyStoreTest.target("Steve"), RANDOM);
        oldPc.getOrCreate(PlayerKeyStoreTest.target("Alex"), RANDOM);

        byte[] file = PlayerKeyBackup.export(oldPc.list(), Optional.of("pw"), RANDOM, FAST);

        PlayerKeyStore newPc = new PlayerKeyStore(dir.resolve("new"));
        for (StoredKey stored : PlayerKeyBackup.read(file, Optional.of("pw"))) {
            assertEquals(PlayerKeyStore.ImportStatus.ADDED, newPc.importKey(stored, false));
        }
        Ed25519.KeyPairData migrated = newPc.find(PlayerKeyStoreTest.target("Steve")).orElseThrow().key();
        byte[] message = {1, 2, 3};
        assertTrue(Ed25519.verify(steve.publicKey(), message, migrated.sign(message)));

        for (StoredKey stored : PlayerKeyBackup.read(file, Optional.of("pw"))) {
            assertEquals(PlayerKeyStore.ImportStatus.IDENTICAL, newPc.importKey(stored, false));
        }
    }

    @Test
    void exportSelectedKeysOnly() throws Exception {
        PlayerKeyStore store = new PlayerKeyStore(dir);
        store.getOrCreate(PlayerKeyStoreTest.target("Steve"), RANDOM);
        store.getOrCreate(PlayerKeyStoreTest.target("Alex"), RANDOM);
        List<StoredKey> selected = store.list().stream().filter(k -> k.target().username().equals("Steve")).toList();
        List<StoredKey> imported = PlayerKeyBackup.read(
                PlayerKeyBackup.export(selected, Optional.empty(), RANDOM), Optional.empty());
        assertEquals(List.of("Steve"), imported.stream().map(k -> k.target().username()).toList());
    }

    @Test
    void importConflictRequiresExplicitOverwrite() throws Exception {
        StoredKey fromBackup = key("Steve");
        PlayerKeyStore store = new PlayerKeyStore(dir);
        Ed25519.KeyPairData local = store.getOrCreate(PlayerKeyStoreTest.target("Steve"), RANDOM);
        StoredKey read = PlayerKeyBackup.read(
                PlayerKeyBackup.export(List.of(fromBackup), Optional.empty(), RANDOM), Optional.empty()).get(0);
        assertEquals(PlayerKeyStore.ImportStatus.CONFLICT, store.importKey(read, false));
        assertArrayEquals(local.publicKey(), store.find(read.target()).orElseThrow().key().publicKey());
        assertEquals(PlayerKeyStore.ImportStatus.REPLACED, store.importKey(read, true));
    }
}
