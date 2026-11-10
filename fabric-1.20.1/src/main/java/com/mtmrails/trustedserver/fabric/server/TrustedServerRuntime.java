package com.mtmrails.trustedserver.fabric.server;

import com.mtmrails.trustedserver.core.crypto.Ed25519;
import com.mtmrails.trustedserver.core.session.AuthOutcome;
import com.mtmrails.trustedserver.core.session.ServerAuthConfig;
import com.mtmrails.trustedserver.fabric.MinecraftAccess;
import com.mtmrails.trustedserver.fabric.TrustedServerFabric;
import com.mtmrails.trustedserver.server.ServerIdentity;
import com.mtmrails.trustedserver.server.PresharedKeyFile;
import com.mtmrails.trustedserver.server.OnlineTokenStore;
import com.mtmrails.trustedserver.server.account.AccountService;
import com.mtmrails.trustedserver.server.account.PlayPasswordEndpoint;
import com.mtmrails.trustedserver.server.config.ConfigException;
import com.mtmrails.trustedserver.server.config.ConfigLoader;
import com.mtmrails.trustedserver.server.config.RejectionText;
import com.mtmrails.trustedserver.server.config.ServerConfig;
import com.mtmrails.trustedserver.server.policy.ConnectionGate;
import com.mtmrails.trustedserver.server.status.StatusSanitizer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.status.ServerStatus;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ServerGamePacketListenerImpl;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;

/**
 * 独立服务端上的全部运行时状态。只在独立服务端创建；内置服务器上 {@link #get()} 为 {@code null}，
 * 所有 mixin 据此不做任何事。
 */
public final class TrustedServerRuntime {
    private static volatile TrustedServerRuntime instance;

    private final ServerConfig config;
    private final ServerAuthConfig authConfig;
    private final Ed25519.KeyPairData identity;
    private final String fingerprint;
    private final byte[] psk;
    private final OnlineTokenStore onlineTokens;
    private final AccountService accounts;
    private final ConnectionGate gate;
    private final StatusSanitizer status;
    private final SecureRandom random = new SecureRandom();
    private final ScheduledExecutorService scheduler;
    final Map<ServerLoginPacketListenerImpl, LoginFlow> flows = new ConcurrentHashMap<>();
    private static final class PlayAccess {
        final Connection connection;
        final AuthOutcome.Accepted login;
        volatile boolean restricted;
        volatile boolean hasPassword;
        volatile PlayPasswordEndpoint endpoint;

        PlayAccess(Connection connection, AuthOutcome.Accepted login) {
            this.connection = connection;
            this.login = login;
            restricted = login.restricted();
            hasPassword = login.hasLoginPassword();
        }

        void close() {
            if (endpoint != null) {
                endpoint.close();
            }
            login.handover().close();
        }
    }

    private final Map<Connection, AuthOutcome.Accepted> handovers = new ConcurrentHashMap<>();
    private final Map<UUID, PlayAccess> playing = new ConcurrentHashMap<>();

    private TrustedServerRuntime(ServerConfig config, ServerIdentity.Loaded identity,
            PresharedKeyFile.Loaded psk, OnlineTokenStore onlineTokens, AccountService accounts) {
        this.config = config;
        this.identity = identity.key();
        this.fingerprint = identity.fingerprint();
        this.psk = psk.key();
        this.onlineTokens = onlineTokens;
        this.accounts = accounts;
        this.gate = new ConnectionGate(config.network(), Clock.systemUTC());
        this.status = new StatusSanitizer(config.status(), Clock.systemUTC(), new Random());
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread thread = new Thread(r, "trustedserver-timeouts");
            thread.setDaemon(true);
            return thread;
        });
        ServerAuthConfig auth = config.auth();
        if (auth.tunnelPolicy() != ServerAuthConfig.TunnelPolicy.DISABLED) {
            if (auth.tunnelPolicy() == ServerAuthConfig.TunnelPolicy.REQUIRED) {
                TrustedServerFabric.LOGGER.warn("auth.tunnel = required is not supported yet in this version; "
                        + "tunnel mode is disabled");
            } else {
                TrustedServerFabric.LOGGER.info("Tunnel mode is not available yet in this version; "
                        + "authentication is still encrypted");
            }
            auth = new ServerAuthConfig(ServerAuthConfig.TunnelPolicy.DISABLED, auth.validation(),
                    auth.maxPasswordAttempts(),
                    auth.passwordTimeoutSec(), auth.restrictedNotice(), auth.recoveryReminderNotice(), auth.rebindNotice());
        }
        this.authConfig = auth;
    }

    /** 独立服务端初始化时调用。配置或身份密钥有问题时抛出异常，服务端拒绝启动。 */
    static void start(Path configDir) {
        Path dir = configDir.resolve("trustedserver");
        ConfigLoader.Result loaded;
        try {
            loaded = ConfigLoader.loadOrCreate(dir.resolve("server.json"));
        } catch (ConfigException | IOException e) {
            throw new IllegalStateException("TrustedServer: invalid configuration, refusing to start: " + e.getMessage(), e);
        }
        if (loaded.createdDefault()) {
            TrustedServerFabric.LOGGER.info("Wrote default configuration to {}", dir.resolve("server.json"));
        }
        for (String key : loaded.unknownKeys()) {
            TrustedServerFabric.LOGGER.warn("Unknown key in server.json ignored: {}", key);
        }
        ServerIdentity.Loaded identity;
        PresharedKeyFile.Loaded psk;
        OnlineTokenStore onlineTokens = new OnlineTokenStore(dir.resolve("online_tokens.txt"));
        SecureRandom random = new SecureRandom();
        try {
            identity = ServerIdentity.loadOrCreate(dir.resolve("server_identity.key"), random);
            psk = PresharedKeyFile.loadOrCreate(dir.resolve("psk.key"), random);
            onlineTokens.validate();
        } catch (IOException e) {
            throw new IllegalStateException("TrustedServer: cannot load server credentials, refusing to start: "
                    + e.getMessage(), e);
        }
        AccountService accounts = AccountService.open(Path.of(loaded.config().databasePath()),
                loaded.config().accounts(), Clock.systemUTC(), new SecureRandom());
        instance = new TrustedServerRuntime(loaded.config(), identity, psk, onlineTokens, accounts);
        TrustedServerFabric.LOGGER.info("Server identity {}: {}", identity.created() ? "created" : "loaded",
                identity.fingerprint());
        TrustedServerFabric.LOGGER.info("PSK login gate enabled ({} {})",
                psk.created() ? "created" : "loaded", dir.resolve("psk.key"));
        accounts.purgeOldAudit().thenAccept(n -> {
            if (n > 0) {
                TrustedServerFabric.LOGGER.info("Purged {} old audit records", n);
            }
        });
    }

    static void stop() {
        TrustedServerRuntime runtime = instance;
        instance = null;
        if (runtime != null) {
            runtime.scheduler.shutdownNow();
            runtime.handovers.values().forEach(pending -> pending.handover().close());
            runtime.playing.values().forEach(PlayAccess::close);
            runtime.accounts.close();
            Arrays.fill(runtime.psk, (byte) 0);
        }
    }

    /** 当前运行时；不在独立服务端时为 {@code null}。 */
    public static TrustedServerRuntime get() {
        return instance;
    }

    public ServerAuthConfig authConfig() {
        return authConfig;
    }

    public int authTimeoutSec() {
        return config.authTimeoutSec();
    }

    public int gateTimeoutSec() {
        return config.network().gateTimeoutSeconds();
    }

    /** 原版登录超时（tick）须不短于我们的认证超时，留出余量。 */
    public int loginTimeoutTicks() {
        return (config.authTimeoutSec() + 15) * 20;
    }

    public Ed25519.KeyPairData identity() {
        return identity;
    }

    public String fingerprint() {
        return fingerprint;
    }

    public byte[] psk() {
        return psk.clone();
    }

    public OnlineTokenStore onlineTokens() {
        return onlineTokens;
    }

    public AccountService accounts() {
        return accounts;
    }

    public ConnectionGate gate() {
        return gate;
    }

    public SecureRandom random() {
        return random;
    }

    ScheduledExecutorService scheduler() {
        return scheduler;
    }

    /** 对外统一的拒绝提示。 */
    public Component rejection() {
        RejectionText text = config.rejection();
        return text.mode() == RejectionText.Mode.VANILLA_BAN
                ? Component.translatable(RejectionText.VANILLA_BAN_KEY)
                : Component.literal(text.customText());
    }

    /** 服务器列表 Ping 是否放行（非 IP 地址一律放行）。 */
    public boolean allowPing(SocketAddress address) {
        return inet(address).map(gate::allowPing).orElse(true);
    }

    /** 清空玩家样本，人数按配置显示。 */
    public ServerStatus sanitize(ServerStatus original) {
        if (status.enhanced()) {
            Optional<ServerStatus.Players> players = Optional.of(new ServerStatus.Players(20,
                    status.displayedOnline(original.players().map(ServerStatus.Players::online).orElse(0), 20),
                    List.of()));
            Component motd = Component.literal(status.enhancedMotd() + "§b§d§f§d§b");
            Optional<ServerStatus.Version> version = original.version().map(v ->
                    new ServerStatus.Version("Minecraft Server", v.protocol()));
            return new ServerStatus(motd, players, version, Optional.empty(), original.enforcesSecureChat());
        }
        Optional<ServerStatus.Players> players = original.players().map(p ->
                new ServerStatus.Players(p.max(), status.displayedOnline(p.online(), p.max()), List.of()));
        return new ServerStatus(original.description(), players, original.version(), original.favicon(),
                original.enforcesSecureChat());
    }

    public boolean statusPingDisabled() {
        return status.pingDisabled();
    }

    /** 增强模式不回答旧版 Ping，避免它绕过现代状态响应的诱饵字段。 */
    public boolean legacyPingDisabled() {
        return status.enhanced();
    }

    public int displayedPlayerCount(int real, int max) {
        return status.displayedOnline(real, max);
    }

    /**
     * 收到登录 Hello 时建立该连接的认证流程并做限流与 IP 封禁检查。
     *
     * @return 放行时返回流程；被拒绝（已断开）时返回 {@code null}
     */
    public LoginFlow beginLogin(ServerLoginPacketListenerImpl handler, net.minecraft.server.MinecraftServer server) {
        LoginFlow flow = new LoginFlow(this, handler, server);
        flows.put(handler, flow);
        return flow.onHello() ? flow : null;
    }

    /** 该登录连接的认证流程；认证已通过或不存在时为 {@code null}。 */
    public LoginFlow loginFlow(ServerLoginPacketListenerImpl handler) {
        return flows.get(handler);
    }

    void registerHandover(Connection connection, AuthOutcome.Accepted accepted) {
        AuthOutcome.Accepted previous = handovers.put(connection, accepted);
        if (previous != null) {
            previous.handover().close();
        }
    }

    void closePendingHandover(Connection connection) {
        AuthOutcome.Accepted pending = handovers.remove(connection);
        if (pending != null) {
            pending.handover().close();
        }
    }

    /** 在原版载入玩家模式、生成能力及指令树之前安装权限状态。 */
    public boolean beginPlay(Connection connection, ServerPlayer player) {
        AuthOutcome.Accepted accepted = handovers.remove(connection);
        if (accepted == null) {
            if (authConfig.validation().ed25519()) {
                connection.disconnect(rejection());
                return false;
            }
            return true;
        }
        PlayAccess previous = playing.put(player.getUUID(), new PlayAccess(connection, accepted));
        if (previous != null) {
            previous.close();
        }
        return true;
    }

    private PlayAccess playAccess(UUID player, Connection connection) {
        PlayAccess access = playing.get(player);
        return access != null && access.connection == connection ? access : null;
    }

    static Connection connectionOf(ServerGamePacketListenerImpl listener) {
        return MinecraftAccess.connection(listener);
    }

    String playAccountId(ServerPlayer player) {
        PlayAccess access = playAccess(player.getUUID(), connectionOf(player.connection));
        return access == null ? null : access.login.accountId();
    }

    public boolean restricted(ServerPlayer player) {
        // 载入玩家存档时原版尚未设置 player.connection。
        PlayAccess access = player.connection == null ? playing.get(player.getUUID())
                : playAccess(player.getUUID(), connectionOf(player.connection));
        return access != null && access.restricted;
    }

    public boolean opSuspended(UUID player) {
        PlayAccess access = player == null ? null : playing.get(player);
        return access != null && authConfig.validation().suspendOp(
                access.restricted, access.hasPassword, access.login.verifiedOriginalKey());
    }

    void notifySuspendedOp(ServerPlayer player) {
        String notice = config.opSuspendedNotice();
        if (!notice.isEmpty() && opSuspended(player.getUUID())
                && player.server.getPlayerList().getOps().get(player.getGameProfile()) != null) {
            player.sendSystemMessage(Component.literal("[TrustedServer] " + notice));
        }
    }

    void openPasswordEndpoint(UUID player, Connection connection, PlayPasswordEndpoint.Listener listener) {
        PlayAccess access = playAccess(player, connection);
        if (access != null) {
            access.endpoint = new PlayPasswordEndpoint(access.login.accountId(),
                    access.login.handover().passwordChannel(), accounts, listener, Clock.systemUTC(),
                    authConfig.validation().loginPassword(), authConfig.validation().recoveryPassword());
        }
    }

    PlayPasswordEndpoint passwordEndpoint(UUID player, Connection connection) {
        PlayAccess access = playAccess(player, connection);
        return access == null ? null : access.endpoint;
    }

    void closePlay(UUID player, Connection connection) {
        PlayAccess access = playAccess(player, connection);
        if (access != null && playing.remove(player, access)) {
            access.close();
        }
    }

    /** 必须在服务端线程调用，且以连接区分同 UUID 的旧会话。 */
    void loginPasswordSet(ServerPlayer player) {
        PlayAccess access = playAccess(player.getUUID(), connectionOf(player.connection));
        if (access != null) {
            access.hasPassword = true;
            access.restricted = false;
            player.server.getPlayerList().sendPlayerPermissionLevel(player);
        }
    }

    void trustOnlinePlayer(MinecraftServer server, String accountId) {
        for (ServerPlayer player : server.getPlayerList().getPlayers()) {
            PlayAccess access = playAccess(player.getUUID(), connectionOf(player.connection));
            if (access != null && access.login.accountId().equals(accountId) && access.restricted) {
                access.restricted = false;
                server.getPlayerList().sendPlayerPermissionLevel(player);
            }
        }
    }

    void disconnectResetAccount(MinecraftServer server, String accountId) {
        // 账号重置后用新的认证重新判定限制和 OP，避免继续使用登录时的状态。
        handovers.forEach((connection, accepted) -> {
            if (accepted.accountId().equals(accountId)) {
                connection.disconnect(Component.literal("认证资料已重置，请重新登录"));
                closePendingHandover(connection);
            }
        });
        for (ServerPlayer player : server.getPlayerList().getPlayers()) {
            PlayAccess access = playAccess(player.getUUID(), connectionOf(player.connection));
            if (access != null && access.login.accountId().equals(accountId)) {
                player.connection.disconnect(Component.literal("认证资料已重置，请重新登录"));
            }
        }
    }

    static Optional<InetAddress> inet(SocketAddress address) {
        return address instanceof InetSocketAddress socket && socket.getAddress() != null
                ? Optional.of(socket.getAddress())
                : Optional.empty();
    }
}
