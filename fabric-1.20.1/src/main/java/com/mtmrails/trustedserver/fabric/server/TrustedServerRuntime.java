package com.mtmrails.trustedserver.fabric.server;

import com.mtmrails.trustedserver.core.crypto.Ed25519;
import com.mtmrails.trustedserver.core.crypto.SessionHandover;
import com.mtmrails.trustedserver.core.session.ServerAuthConfig;
import com.mtmrails.trustedserver.fabric.TrustedServerFabric;
import com.mtmrails.trustedserver.server.ServerIdentity;
import com.mtmrails.trustedserver.server.account.AccountService;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.status.ServerStatus;
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
    private final AccountService accounts;
    private final ConnectionGate gate;
    private final StatusSanitizer status;
    private final SecureRandom random = new SecureRandom();
    private final ScheduledExecutorService scheduler;
    final Map<ServerLoginPacketListenerImpl, LoginFlow> flows = new ConcurrentHashMap<>();
    private final Map<UUID, SessionHandover> handovers = new ConcurrentHashMap<>();

    private TrustedServerRuntime(ServerConfig config, ServerIdentity.Loaded identity, AccountService accounts) {
        this.config = config;
        this.identity = identity.key();
        this.fingerprint = identity.fingerprint();
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
            auth = new ServerAuthConfig(ServerAuthConfig.TunnelPolicy.DISABLED, auth.maxPasswordAttempts(),
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
        try {
            identity = ServerIdentity.loadOrCreate(dir.resolve("server_identity.key"), new SecureRandom());
        } catch (IOException e) {
            throw new IllegalStateException("TrustedServer: cannot load server identity, refusing to start: "
                    + e.getMessage(), e);
        }
        AccountService accounts = AccountService.open(Path.of(loaded.config().databasePath()),
                loaded.config().accounts(), Clock.systemUTC(), new SecureRandom());
        instance = new TrustedServerRuntime(loaded.config(), identity, accounts);
        TrustedServerFabric.LOGGER.info("Server identity {}: {}", identity.created() ? "created" : "loaded",
                identity.fingerprint());
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
            runtime.handovers.values().forEach(SessionHandover::close);
            runtime.accounts.close();
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
        Optional<ServerStatus.Players> players = original.players().map(p ->
                new ServerStatus.Players(p.max(), status.displayedOnline(p.online(), p.max()), List.of()));
        return new ServerStatus(original.description(), players, original.version(), original.favicon(),
                original.enforcesSecureChat());
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

    void registerHandover(UUID player, SessionHandover handover) {
        SessionHandover previous = handovers.put(player, handover);
        if (previous != null) {
            previous.close();
        }
    }

    void closeHandover(UUID player) {
        SessionHandover handover = handovers.remove(player);
        if (handover != null) {
            handover.close();
        }
    }

    static Optional<InetAddress> inet(SocketAddress address) {
        return address instanceof InetSocketAddress socket && socket.getAddress() != null
                ? Optional.of(socket.getAddress())
                : Optional.empty();
    }
}
