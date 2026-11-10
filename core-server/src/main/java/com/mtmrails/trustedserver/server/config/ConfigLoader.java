package com.mtmrails.trustedserver.server.config;

import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import com.mtmrails.trustedserver.core.session.ServerAuthConfig;
import com.mtmrails.trustedserver.server.account.AccountServiceConfig;
import com.mtmrails.trustedserver.server.password.PasswordHasher;
import com.mtmrails.trustedserver.server.password.PasswordPolicy;
import com.mtmrails.trustedserver.server.policy.Cidr;
import com.mtmrails.trustedserver.server.policy.IpLockout;
import com.mtmrails.trustedserver.server.policy.NetworkPolicyConfig;
import com.mtmrails.trustedserver.server.policy.RateLimit;
import com.mtmrails.trustedserver.server.status.StatusConfig;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * 读写 {@code config/trustedserver/server.json}（AGENTS.md 第 19 条）。
 *
 * <ul>
 *   <li>文件不存在：写出默认配置并使用默认值
 *   <li>缺少的键：使用默认值（便于升级后保留旧配置）
 *   <li>格式、类型或范围错误：抛出 {@link ConfigException}，服务端应拒绝启动
 *   <li>未知的键：只在结果中报告，供上层打印警告
 * </ul>
 */
public final class ConfigLoader {
    public static final String DEFAULT_PATH = "config/trustedserver/server.json";
    static final int CONFIG_VERSION = 1;

    private ConfigLoader() {
    }

    /** 读取结果：配置、未知键的路径，以及本次是否写出了默认配置。 */
    public record Result(ServerConfig config, List<String> unknownKeys, boolean createdDefault) {
        public Result {
            unknownKeys = List.copyOf(unknownKeys);
        }
    }

    public static Result loadOrCreate(Path file) throws IOException, ConfigException {
        if (!Files.exists(file)) {
            Path parent = file.toAbsolutePath().getParent();
            Files.createDirectories(parent);
            Files.writeString(file, toJson(ServerConfig.DEFAULT), StandardCharsets.UTF_8);
            return new Result(ServerConfig.DEFAULT, List.of(), true);
        }
        return parse(Files.readString(file, StandardCharsets.UTF_8));
    }

    static Result parse(String json) throws ConfigException {
        JsonElement root;
        try {
            root = JsonParser.parseString(json);
        } catch (JsonParseException e) {
            throw new ConfigException("server.json is not valid JSON: " + e.getMessage(), e);
        }
        if (!root.isJsonObject()) {
            throw new ConfigException("server.json: top level must be an object");
        }
        JsonSection top = new JsonSection(root.getAsJsonObject(), "");
        int version = top.integer("configVersion", CONFIG_VERSION, 1, Integer.MAX_VALUE);
        if (version > CONFIG_VERSION) {
            throw new ConfigException("configVersion " + version + " is newer than this mod supports (" + CONFIG_VERSION
                    + ")");
        }
        ServerConfig d = ServerConfig.DEFAULT;
        try {
            ServerConfig config = new ServerConfig(readAuth(top, d), readAuthTimeout(top, d), readAccounts(top, d),
                    readDatabase(top, d), readNetwork(top, d), readStatus(top, d), readRejection(top, d),
                    top.section("notices").string("opSuspended", d.opSuspendedNotice()));
            List<String> unknown = new ArrayList<>();
            top.collectUnknown(unknown);
            return new Result(config, unknown, false);
        } catch (IllegalArgumentException e) {
            throw new ConfigException("server.json: " + e.getMessage(), e);
        }
    }

    private static ServerAuthConfig readAuth(JsonSection top, ServerConfig d) throws ConfigException {
        JsonSection auth = top.section("auth");
        JsonSection validation = auth.section("validation");
        JsonSection notices = top.section("notices");
        ServerAuthConfig a = d.auth();
        ServerAuthConfig.ValidationLevels v = a.validation();
        boolean ed25519 = validation.bool("ed25519", v.ed25519());
        boolean loginPassword = validation.bool("loginPassword", v.loginPassword());
        return new ServerAuthConfig(
                auth.enumValue("tunnel", a.tunnelPolicy(), ServerAuthConfig.TunnelPolicy.class),
                new ServerAuthConfig.ValidationLevels(
                        ed25519,
                        loginPassword,
                        validation.bool("recoveryPassword", ed25519 && v.recoveryPassword()),
                        validation.bool("newPlayerRestriction", loginPassword && v.newPlayerRestriction()),
                        validation.bool("requirePasswordForVerifiedOps", v.requirePasswordForVerifiedOps())),
                auth.integer("maxPasswordAttempts", a.maxPasswordAttempts(), 1, 255),
                auth.integer("passwordPromptTimeoutSeconds", a.passwordTimeoutSec(), 1, 65535),
                notices.string("restricted", a.restrictedNotice()),
                notices.string("recoveryReminder", a.recoveryReminderNotice()),
                notices.string("rebind", a.rebindNotice()));
    }

    private static int readAuthTimeout(JsonSection top, ServerConfig d) throws ConfigException {
        return top.section("auth").integer("authTimeoutSeconds", d.authTimeoutSec(), 2, 3600);
    }

    private static AccountServiceConfig readAccounts(JsonSection top, ServerConfig d) throws ConfigException {
        JsonSection password = top.section("password");
        JsonSection argon2 = password.section("argon2");
        JsonSection accounts = top.section("accounts");
        AccountServiceConfig a = d.accounts();
        PasswordHasher.Params params = a.hashParams();
        return new AccountServiceConfig(
                new PasswordHasher.Params(argon2.integer("memoryKib", params.memoryKib(), 8, 1024 * 1024),
                        argon2.integer("iterations", params.iterations(), 1, 64),
                        argon2.integer("parallelism", params.parallelism(), 1, 16)),
                new PasswordPolicy(password.integer("minLength", a.policy().minLength(), 1, 128),
                        password.integer("maxLength", a.policy().maxLength(), 1, 128)),
                accounts.integer("hashThreads", a.hashThreads(), 1, 64),
                accounts.integer("hashQueue", a.hashQueue(), 1, 100_000),
                accounts.integer("lockoutFailures", a.cumulativeFailureLimit(), 1, 10_000),
                Duration.ofMinutes(accounts.integer("lockoutMinutes", (int) a.lockoutDuration().toMinutes(), 1,
                        525_600)),
                Duration.ofDays(accounts.integer("auditRetentionDays", (int) a.auditRetention().toDays(), 1, 36_500)));
    }

    private static String readDatabase(JsonSection top, ServerConfig d) throws ConfigException {
        return top.section("accounts").string("database", d.databasePath());
    }

    private static NetworkPolicyConfig readNetwork(JsonSection top, ServerConfig d) throws ConfigException {
        JsonSection network = top.section("network");
        NetworkPolicyConfig n = d.network();
        JsonSection lockout = network.section("ipLockout");
        List<Cidr> trusted = new ArrayList<>();
        List<String> entries = network.stringList("trustedNetworks");
        for (int i = 0; i < entries.size(); i++) {
            try {
                trusted.add(Cidr.parse(entries.get(i)));
            } catch (IllegalArgumentException e) {
                throw network.error("trustedNetworks[" + i + "]", e.getMessage());
            }
        }
        return new NetworkPolicyConfig(
                rate(network.section("ping"), n.ping()),
                rate(network.section("login"), n.login()),
                rate(network.section("unverified"), n.unverified()),
                network.integer("maxPendingLogins", n.maxPendingLogins(), 1, 100_000),
                network.integer("gateTimeoutSeconds", n.gateTimeoutSeconds(), 2, 300),
                lockout.bool("enabled", n.ipLockoutEnabled()),
                ipLockout(lockout.section("ipv4"), n.ipv4Lockout()),
                ipLockout(lockout.section("ipv6"), n.ipv6Lockout()),
                trusted);
    }

    private static RateLimit rate(JsonSection s, RateLimit d) throws ConfigException {
        return new RateLimit(s.integer("perMinute", d.perMinute(), 1, 100_000), s.integer("burst", d.burst(), 1, 100_000));
    }

    private static IpLockout ipLockout(JsonSection s, IpLockout d) throws ConfigException {
        return new IpLockout(s.integer("failures", d.failures(), 1, 100_000),
                Duration.ofMinutes(s.integer("windowMinutes", (int) d.window().toMinutes(), 1, 10_080)),
                Duration.ofMinutes(s.integer("lockMinutes", (int) d.lockFor().toMinutes(), 1, 10_080)));
    }

    private static StatusConfig readStatus(JsonSection top, ServerConfig d) throws ConfigException {
        JsonSection status = top.section("status");
        StatusConfig s = d.status();
        int min = status.integer("randomMin", s.randomMin(), 0, 1_000_000);
        int max = status.integer("randomMax", s.randomMax(), 0, 1_000_000);
        if (min > max) {
            throw status.error("randomMin", "must not be greater than randomMax");
        }
        return new StatusConfig(
                status.enumValue("mode", s.protection(), StatusConfig.ProtectionMode.class),
                status.bool("disablePing", s.disablePing()), status.string("enhancedMotd", s.enhancedMotd()),
                status.enumValue("playerCount", s.mode(), StatusConfig.PlayerCountMode.class),
                status.integer("fixed", s.fixedCount(), 0, 1_000_000), min, max,
                Duration.ofMinutes(status.integer("rerollMinutes", (int) s.reroll().toMinutes(), 1, 1440)));
    }

    private static RejectionText readRejection(JsonSection top, ServerConfig d) throws ConfigException {
        JsonSection rejection = top.section("rejection");
        RejectionText r = d.rejection();
        RejectionText.Mode mode = rejection.enumValue("mode", r.mode(), RejectionText.Mode.class);
        String text = rejection.string("customText", r.customText());
        if (mode == RejectionText.Mode.CUSTOM && text.isBlank()) {
            throw rejection.error("customText", "must not be blank when mode is custom");
        }
        return new RejectionText(mode, text);
    }

    /** 序列化为带缩进的 JSON（写出默认配置时使用）。 */
    public static String toJson(ServerConfig c) {
        JsonObject root = new JsonObject();
        root.addProperty("configVersion", CONFIG_VERSION);

        JsonObject auth = new JsonObject();
        auth.addProperty("tunnel", lower(c.auth().tunnelPolicy()));
        JsonObject validation = new JsonObject();
        validation.addProperty("ed25519", c.auth().validation().ed25519());
        validation.addProperty("loginPassword", c.auth().validation().loginPassword());
        validation.addProperty("recoveryPassword", c.auth().validation().recoveryPassword());
        validation.addProperty("newPlayerRestriction", c.auth().validation().newPlayerRestriction());
        validation.addProperty("requirePasswordForVerifiedOps", c.auth().validation().requirePasswordForVerifiedOps());
        auth.add("validation", validation);
        auth.addProperty("maxPasswordAttempts", c.auth().maxPasswordAttempts());
        auth.addProperty("passwordPromptTimeoutSeconds", c.auth().passwordTimeoutSec());
        auth.addProperty("authTimeoutSeconds", c.authTimeoutSec());
        root.add("auth", auth);

        JsonObject notices = new JsonObject();
        notices.addProperty("restricted", c.auth().restrictedNotice());
        notices.addProperty("recoveryReminder", c.auth().recoveryReminderNotice());
        notices.addProperty("rebind", c.auth().rebindNotice());
        notices.addProperty("opSuspended", c.opSuspendedNotice());
        root.add("notices", notices);

        JsonObject password = new JsonObject();
        password.addProperty("minLength", c.accounts().policy().minLength());
        password.addProperty("maxLength", c.accounts().policy().maxLength());
        JsonObject argon2 = new JsonObject();
        argon2.addProperty("memoryKib", c.accounts().hashParams().memoryKib());
        argon2.addProperty("iterations", c.accounts().hashParams().iterations());
        argon2.addProperty("parallelism", c.accounts().hashParams().parallelism());
        password.add("argon2", argon2);
        root.add("password", password);

        JsonObject accounts = new JsonObject();
        accounts.addProperty("database", c.databasePath());
        accounts.addProperty("hashThreads", c.accounts().hashThreads());
        accounts.addProperty("hashQueue", c.accounts().hashQueue());
        accounts.addProperty("lockoutFailures", c.accounts().cumulativeFailureLimit());
        accounts.addProperty("lockoutMinutes", c.accounts().lockoutDuration().toMinutes());
        accounts.addProperty("auditRetentionDays", c.accounts().auditRetention().toDays());
        root.add("accounts", accounts);

        JsonObject network = new JsonObject();
        network.add("ping", rateJson(c.network().ping()));
        network.add("login", rateJson(c.network().login()));
        network.add("unverified", rateJson(c.network().unverified()));
        network.addProperty("maxPendingLogins", c.network().maxPendingLogins());
        network.addProperty("gateTimeoutSeconds", c.network().gateTimeoutSeconds());
        JsonObject lockout = new JsonObject();
        lockout.addProperty("enabled", c.network().ipLockoutEnabled());
        lockout.add("ipv4", lockoutJson(c.network().ipv4Lockout()));
        lockout.add("ipv6", lockoutJson(c.network().ipv6Lockout()));
        network.add("ipLockout", lockout);
        JsonArray trusted = new JsonArray();
        c.network().trustedNetworks().forEach(n -> trusted.add(n.toString()));
        network.add("trustedNetworks", trusted);
        root.add("network", network);

        JsonObject status = new JsonObject();
        status.addProperty("mode", lower(c.status().protection()));
        status.addProperty("disablePing", c.status().disablePing());
        status.addProperty("enhancedMotd", c.status().enhancedMotd());
        status.addProperty("playerCount", lower(c.status().mode()));
        status.addProperty("fixed", c.status().fixedCount());
        status.addProperty("randomMin", c.status().randomMin());
        status.addProperty("randomMax", c.status().randomMax());
        status.addProperty("rerollMinutes", c.status().reroll().toMinutes());
        root.add("status", status);

        JsonObject rejection = new JsonObject();
        rejection.addProperty("mode", lower(c.rejection().mode()));
        rejection.addProperty("customText", c.rejection().customText());
        root.add("rejection", rejection);

        return new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create().toJson(root) + "\n";
    }

    private static JsonObject rateJson(RateLimit r) {
        JsonObject o = new JsonObject();
        o.addProperty("perMinute", r.perMinute());
        o.addProperty("burst", r.burst());
        return o;
    }

    private static JsonObject lockoutJson(IpLockout l) {
        JsonObject o = new JsonObject();
        o.addProperty("failures", l.failures());
        o.addProperty("windowMinutes", l.window().toMinutes());
        o.addProperty("lockMinutes", l.lockFor().toMinutes());
        return o;
    }

    private static String lower(Enum<?> e) {
        return e.name().toLowerCase(Locale.ROOT);
    }
}
