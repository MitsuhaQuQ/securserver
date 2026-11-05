package com.mtmrails.trustedserver.fabric.server;

import com.mojang.authlib.GameProfile;
import com.mtmrails.trustedserver.core.message.Channel;
import com.mtmrails.trustedserver.core.session.AuthOutcome;
import com.mtmrails.trustedserver.core.session.Outbound;
import com.mtmrails.trustedserver.core.session.RejectReason;
import com.mtmrails.trustedserver.core.session.ServerAuthSession;
import com.mtmrails.trustedserver.core.session.ServerStep;
import com.mtmrails.trustedserver.fabric.TrustedServerFabric;
import com.mtmrails.trustedserver.fabric.mixin.ServerLoginPacketListenerAccessor;
import com.mtmrails.trustedserver.server.policy.ConnectionGate;
import java.net.InetAddress;
import net.minecraft.core.UUIDUtil;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import net.fabricmc.fabric.api.networking.v1.PacketByteBufs;
import net.fabricmc.fabric.api.networking.v1.PacketSender;
import net.fabricmc.fabric.api.networking.v1.ServerLoginNetworking;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;

/**
 * 一个登录连接上的认证流程（PROTOCOL.md 第 1、7 节）。
 *
 * <p>开始时向 Fabric 登记一个“认证完成” future，只在状态机得出放行结果时完成：整个认证期间 Fabric 都不会放行，
 * 避免两轮 query 之间因“暂时没有在途 query”而被提前接受。拒绝时以统一文本断开，该 future 永不完成。
 *
 * <p>分两段：收到登录 Hello 时（Mojang 验证之前）先做限流与 IP 封禁检查，使所有登录连接都计入限流；
 * Fabric 的 QUERY_START（验证之后，已知可信 UUID）再做名字 / UUID 封禁、账号锁定和协议握手。
 *
 * <p>状态机的调用都在 {@link #lock} 内进行；其异步部分在账号服务的线程上完成后再回到这里。
 */
public final class LoginFlow {
    private final TrustedServerRuntime runtime;
    private final ServerLoginPacketListenerImpl handler;
    private final MinecraftServer server;
    private final Object lock = new Object();
    private final CompletableFuture<Void> authDone = new CompletableFuture<>();

    private PacketSender sender;
    private InetAddress address;
    private GameProfile profile;
    private String accountId;
    private ServerAuthSession session;
    private ScheduledFuture<?> timeoutTask;
    private boolean done;
    private boolean gateReported;
    private AuthOutcome.Accepted accepted;

    LoginFlow(TrustedServerRuntime runtime, ServerLoginPacketListenerImpl handler, MinecraftServer server) {
        this.runtime = runtime;
        this.handler = handler;
        this.server = server;
    }

    /**
     * 收到登录 Hello（网络线程，Mojang 验证之前）：限流与 IP 封禁。
     *
     * @return 是否放行；不放行时已断开
     */
    boolean onHello() {
        ServerLoginPacketListenerAccessor access = (ServerLoginPacketListenerAccessor) handler;
        address = TrustedServerRuntime.inet(access.trustedserver$connection().getRemoteAddress())
                .orElse(InetAddress.getLoopbackAddress());
        ConnectionGate.Verdict verdict = runtime.gate().beginLogin(address);
        if (verdict != ConnectionGate.Verdict.ALLOW) {
            rejectBeforeHandshake(verdict.name().toLowerCase(Locale.ROOT));
            return false;
        }
        if (server.getPlayerList().getIpBans().isBanned(access.trustedserver$connection().getRemoteAddress())) {
            rejectBeforeHandshake("ip banned");
            return false;
        }
        return true;
    }

    /** Fabric 的 QUERY_START（服务器主线程，Mojang 验证之后）：封禁与锁定检查，然后发出 ServerHello。 */
    void start(PacketSender sender, ServerLoginNetworking.LoginSynchronizer synchronizer) {
        this.sender = sender;
        synchronizer.waitFor(authDone);
        synchronized (lock) {
            if (done) {
                return;
            }
        }
        GameProfile raw = ((ServerLoginPacketListenerAccessor) handler).trustedserver$gameProfile();
        if (raw == null) {
            rejectBeforeHandshake("no game profile");
            return;
        }
        // 离线模式下此时还没有 UUID（原版稍后才生成）；按原版规则提前算出离线 UUID，封禁记录也是按它存的
        profile = raw.getId() != null ? raw : new GameProfile(UUIDUtil.createOfflinePlayerUUID(raw.getName()), raw.getName());
        if (server.getPlayerList().getBans().isBanned(profile)) {
            rejectBeforeHandshake("banned");
            return;
        }
        boolean online = server.usesAuthentication();
        accountId = online ? profile.getId().toString() : profile.getName().toLowerCase(Locale.ROOT);
        timeoutTask = runtime.scheduler().schedule(this::onTimeout, runtime.authTimeoutSec(), TimeUnit.SECONDS);
        runtime.accounts().isLocked(accountId).whenComplete((locked, error) -> {
            if (error != null || Boolean.TRUE.equals(locked)) {
                rejectBeforeHandshake(error != null ? "lock check failed" : "account locked");
            } else {
                beginHandshake(online);
            }
        });
    }

    private void beginHandshake(boolean online) {
        Outbound first;
        synchronized (lock) {
            if (done) {
                return;
            }
            // 第一阶段：invalid session 保持原版行为（直接断开），能走到这里的正版连接都已通过 Mojang 验证
            session = new ServerAuthSession(accountId, profile.getName(), online, online, runtime.authConfig(),
                    runtime.identity(), runtime.accounts(), runtime.random());
            first = session.start();
        }
        send(first);
    }

    /** 收到一条 query 回答（网络线程）。 */
    void onAnswer(Channel channel, boolean understood, FriendlyByteBuf buf) {
        byte[] payload = null;
        if (understood) {
            payload = new byte[buf.readableBytes()];
            buf.readBytes(payload);
        }
        CompletableFuture<ServerStep> step;
        synchronized (lock) {
            if (done || session == null) {
                return;
            }
            try {
                step = session.onAnswer(channel, payload);
            } catch (IllegalStateException e) {
                // 对方在上一轮尚未处理完时又发来回答
                step = CompletableFuture.completedFuture(
                        new ServerStep.Done(new AuthOutcome.Rejected(RejectReason.PROTOCOL_ERROR, false)));
            }
        }
        step.whenComplete(this::onStep);
    }

    private void onStep(ServerStep step, Throwable error) {
        if (error != null) {
            finish(new AuthOutcome.Rejected(RejectReason.INTERNAL_ERROR, false));
            return;
        }
        if (step instanceof ServerStep.Send send) {
            synchronized (lock) {
                if (done) {
                    return;
                }
            }
            send(send.next());
            return;
        }
        finish(((ServerStep.Done) step).outcome());
    }

    private void onTimeout() {
        AuthOutcome outcome;
        synchronized (lock) {
            if (done) {
                return;
            }
            outcome = session != null ? session.timeout() : new AuthOutcome.Rejected(RejectReason.TIMEOUT, false);
        }
        finish(outcome);
    }

    private void finish(AuthOutcome outcome) {
        synchronized (lock) {
            if (done) {
                if (outcome instanceof AuthOutcome.Accepted late) {
                    late.handover().close();
                }
                return;
            }
            done = true;
        }
        cancelTimeout();
        if (outcome instanceof AuthOutcome.Accepted ok) {
            accepted = ok;
            reportGate(true);
            runtime.registerHandover(profile.getId(), ok.handover());
            runtime.accounts().recordLogin(ok.accountId(), ok.username(), address.getHostAddress());
            runtime.flows.remove(handler);
            TrustedServerFabric.LOGGER.info("{} passed TrustedServer authentication", ok.username());
            authDone.complete(null);
            return;
        }
        AuthOutcome.Rejected rejected = (AuthOutcome.Rejected) outcome;
        reportGate(rejected.trusted());
        log(rejected.reason().name(), rejected.trusted());
        handler.disconnect(runtime.rejection());
    }

    /** 协议握手之前的拒绝（限流、封禁、锁定）。 */
    private void rejectBeforeHandshake(String reason) {
        synchronized (lock) {
            if (done) {
                return;
            }
            done = true;
        }
        cancelTimeout();
        reportGate(false);
        log(reason, false);
        handler.disconnect(runtime.rejection());
    }

    /** Fabric 的登录阶段断开事件。 */
    void onDisconnect() {
        cancelTimeout();
        synchronized (lock) {
            if (!done) {
                done = true;
                if (session != null) {
                    session.timeout();
                }
            }
        }
        if (accepted != null) {
            // 放行后、进入游戏前就断开了
            runtime.closeHandover(profile.getId());
        }
        reportGate(false);
        runtime.flows.remove(handler);
    }

    private void send(Outbound outbound) {
        FriendlyByteBuf buf = PacketByteBufs.create();
        buf.writeBytes(outbound.payload());
        sender.sendPacket(new ResourceLocation(outbound.channel().id()), buf);
    }

    private synchronized void reportGate(boolean trustedHandshake) {
        if (!gateReported) {
            gateReported = true;
            runtime.gate().endLogin(address, trustedHandshake);
        }
    }

    private void cancelTimeout() {
        ScheduledFuture<?> task = timeoutTask;
        if (task != null) {
            task.cancel(false);
        }
    }

    private void log(String reason, boolean trusted) {
        String who = profile != null ? profile.getName() : "?";
        if (trusted) {
            TrustedServerFabric.LOGGER.info("Rejected {} from {} after trusted handshake: {}", who,
                    address.getHostAddress(), reason);
        } else {
            TrustedServerFabric.LOGGER.debug("Rejected {} from {}: {}", who, address.getHostAddress(), reason);
        }
    }
}
