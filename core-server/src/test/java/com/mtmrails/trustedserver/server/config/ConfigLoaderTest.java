package com.mtmrails.trustedserver.server.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mtmrails.trustedserver.core.session.ServerAuthConfig;
import com.mtmrails.trustedserver.server.status.StatusConfig;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigLoaderTest {
    @TempDir
    Path dir;

    private static String error(String json) {
        return assertThrows(ConfigException.class, () -> ConfigLoader.parse(json)).getMessage();
    }

    @Test
    void missingFileWritesDefaults() throws Exception {
        Path file = dir.resolve("config/trustedserver/server.json");
        ConfigLoader.Result created = ConfigLoader.loadOrCreate(file);
        assertTrue(created.createdDefault());
        assertEquals(ServerConfig.DEFAULT, created.config());
        String written = Files.readString(file, StandardCharsets.UTF_8);
        assertTrue(written.contains("\"tunnel\": \"optional\""));
        assertTrue(written.contains("\"ed25519\": true"));
        assertTrue(written.contains("\"loginPassword\": true"));
        assertTrue(written.contains("\"recoveryPassword\": true"));
        assertTrue(written.contains("\"newPlayerRestriction\": true"));
        assertTrue(written.contains("\"requirePasswordForVerifiedOps\": false"));
        assertTrue(written.contains("设定密码后解除新用户限制")); // 中文不被转义

        ConfigLoader.Result reloaded = ConfigLoader.loadOrCreate(file);
        assertFalse(reloaded.createdDefault());
        assertEquals(ServerConfig.DEFAULT, reloaded.config());
        assertEquals(List.of(), reloaded.unknownKeys());
    }

    @Test
    void writtenDefaultsDocumentEveryKnownKey() throws Exception {
        // 默认配置里写出的每个键都必须能被读取（不会被报告为未知）
        assertEquals(List.of(), ConfigLoader.parse(ConfigLoader.toJson(ServerConfig.DEFAULT)).unknownKeys());
    }

    @Test
    void partialConfigFallsBackToDefaults() throws Exception {
        ServerConfig config = ConfigLoader.parse("""
                {"auth": {"tunnel": "required"}, "status": {"playerCount": "fixed", "fixed": 42},
                 "network": {"trustedNetworks": ["10.0.0.0/8", "2001:db8::/32"]}}
                """).config();
        assertEquals(ServerAuthConfig.TunnelPolicy.REQUIRED, config.auth().tunnelPolicy());
        assertEquals(StatusConfig.PlayerCountMode.FIXED, config.status().mode());
        assertEquals(42, config.status().fixedCount());
        assertEquals(StatusConfig.ProtectionMode.NORMAL, config.status().protection());
        assertEquals(2, config.network().trustedNetworks().size());
        assertEquals(ServerConfig.DEFAULT.accounts(), config.accounts());
        assertEquals(90, config.authTimeoutSec());
    }

    @Test
    void roundTripPreservesSettings() throws Exception {
        String json = """
                {"configVersion": 1,
                 "auth": {"tunnel": "disabled",
                          "validation": {"ed25519": true, "loginPassword": false,
                                         "recoveryPassword": false, "newPlayerRestriction": false},
                          "maxPasswordAttempts": 5, "passwordPromptTimeoutSeconds": 30,
                          "authTimeoutSeconds": 60},
                 "password": {"minLength": 8, "argon2": {"memoryKib": 65536, "iterations": 3}},
                 "accounts": {"database": "data/p.db", "lockoutMinutes": 30},
                 "network": {"ping": {"perMinute": 100, "burst": 50}, "ipLockout": {"enabled": false},
                             "trustedNetworks": ["192.0.2.0/24"]},
                 "status": {"playerCount": "random", "randomMin": 1, "randomMax": 9},
                 "rejection": {"mode": "custom", "customText": "No."}}
                """;
        ServerConfig config = ConfigLoader.parse(json).config();
        assertEquals(ConfigLoader.toJson(config), ConfigLoader.toJson(ConfigLoader.parse(ConfigLoader.toJson(config))
                .config()));
        assertEquals(8, config.accounts().policy().minLength());
        assertEquals(65536, config.accounts().hashParams().memoryKib());
        assertEquals("data/p.db", config.databasePath());
        assertFalse(config.network().ipLockoutEnabled());
        assertEquals(RejectionText.Mode.CUSTOM, config.rejection().mode());
        assertFalse(config.auth().validation().loginPassword());
        assertFalse(config.auth().validation().recoveryPassword());
    }

    @Test
    void baseGateOnlyConfigCanOmitRecoverySwitch() throws Exception {
        var config = ConfigLoader.parse("""
                {"auth": {"tunnel": "disabled",
                          "validation": {"ed25519": false, "loginPassword": false}}}
                """).config();
        assertFalse(config.auth().validation().recoveryPassword());
        assertFalse(config.auth().validation().newPlayerRestriction());
        assertTrue(error("""
                {"auth": {"tunnel": "disabled",
                          "validation": {"ed25519": false, "loginPassword": false, "recoveryPassword": true}}}
                """).contains("require auth.validation.ed25519"));
    }

    @Test
    void operatorsWithVerifiedOriginalKeysCanBeRequiredToSetPassword() throws Exception {
        var config = ConfigLoader.parse("""
                {"auth": {"validation": {"requirePasswordForVerifiedOps": true}}}
                """).config();
        assertTrue(config.auth().validation().requirePasswordForVerifiedOps());
        assertTrue(ConfigLoader.parse(ConfigLoader.toJson(config)).config().auth().validation()
                .requirePasswordForVerifiedOps());
        assertTrue(error("""
                {"auth": {"validation": {"loginPassword": false, "requirePasswordForVerifiedOps": true}}}
                """).contains("requirePasswordForVerifiedOps"));
    }

    @Test
    void unknownKeysAreReportedWithPaths() throws Exception {
        ConfigLoader.Result result = ConfigLoader.parse("""
                {"auth": {"tunnel": "optional", "authTimeoutSeconds": 90, "tunel": "x"},
                 "accounts": {"database": "a.db", "hashThreads": 2},
                 "network": {"ping": {"perMinut": 3}}, "extra": 1}
                """);
        assertEquals(List.of("extra", "auth.tunel", "network.ping.perMinut"), result.unknownKeys());
    }

    @Test
    void invalidValuesNamePathAndRule() {
        assertTrue(error("{\"auth\": {\"maxPasswordAttempts\": 0}}").contains("auth.maxPasswordAttempts"));
        assertTrue(error("{\"auth\": {\"maxPasswordAttempts\": 2.5}}").contains("integer"));
        assertTrue(error("{\"auth\": {\"tunnel\": \"sometimes\"}}").contains("[disabled, optional, required]"));
        assertTrue(error("{\"auth\": \"yes\"}").contains("auth: expected an object"));
        assertTrue(error("{\"network\": {\"trustedNetworks\": [\"10.0.0.1/8\"]}}")
                .contains("network.trustedNetworks[0]"));
        assertTrue(error("{\"network\": {\"trustedNetworks\": [\"example.com\"]}}")
                .contains("network.trustedNetworks[0]"));
        assertTrue(error("{\"status\": {\"randomMin\": 9, \"randomMax\": 1}}").contains("status.randomMin"));
        assertTrue(error("{\"rejection\": {\"mode\": \"custom\", \"customText\": \"  \"}}")
                .contains("rejection.customText"));
        assertTrue(error("{\"auth\": {\"passwordPromptTimeoutSeconds\": 120}}").contains("authTimeoutSeconds"));
        assertTrue(error("{\"auth\": {\"tunnel\": \"disabled\", \"validation\": "
                + "{\"ed25519\": false, \"loginPassword\": true}}}")
                .contains("require auth.validation.ed25519"));
        assertTrue(error("{\"auth\": {\"tunnel\": \"disabled\", \"validation\": "
                + "{\"loginPassword\": false, \"newPlayerRestriction\": true}}}")
                .contains("newPlayerRestriction"));
        assertTrue(error("{\"password\": {\"minLength\": 10, \"maxLength\": 8}}").contains("password length"));
        assertTrue(error("{\"ipLockout\": 1, \"configVersion\": 2}").contains("newer"));
        assertTrue(error("{not json").contains("not valid JSON"));
        assertTrue(error("[]").contains("top level"));
    }
}
