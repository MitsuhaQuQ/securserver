package com.mtmrails.trustedserver.fabric.server;

import com.mojang.authlib.GameProfile;
import com.mtmrails.trustedserver.core.crypto.PresharedKeyHandshake;
import com.mtmrails.trustedserver.core.crypto.PskAuthenticationException;
import com.mtmrails.trustedserver.core.crypto.PskWire;
import com.mtmrails.trustedserver.core.crypto.OnlineTokenWire;
import com.mtmrails.trustedserver.core.message.Channel;
import com.mtmrails.trustedserver.core.session.AuthOutcome;
import com.mtmrails.trustedserver.core.session.Outbound;
import com.mtmrails.trustedserver.core.session.RejectReason;
import com.mtmrails.trustedserver.core.session.ServerAuthSession;
import com.mtmrails.trustedserver.core.session.ServerStep;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.fabric.MinecraftAccess;
import com.mtmrails.trustedserver.fabric.TrustedServerFabric;
import com.mtmrails.trustedserver.fabric.network.PlayPasswordNetworking;
import com.mtmrails.trustedserver.server.policy.ConnectionGate;
import java.net.InetAddress;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import net.minecraft.network.Connection;
import net.minecraft.network.PacketSendListener;
import net.minecraft.network.protocol.Packet;
import net.minecraft.network.protocol.login.ClientboundCustomQueryPacket;
import net.minecraft.core.UUIDUtil;
import java.util.Locale;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import net.fabricmc.fabric.api.networking.v1.PacketByteBufs;
import net.fabricmc.fabric.api.networking.v1.PacketSender;
import net.fabricmc.fabric.api.networking.v1.ServerLoginNetworking;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.chat.Component;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;

/**
 * 一个登录连接上的认证流程（PROTOCOL.md 第 1、7 节）。
 *
 * <p>开始时向 Fabric 登记一个“认证完成” future，只在状态机得出放行结果时完成：整个认证期间 Fabric 都不会放行，
 * 避免两轮 query 之间因“暂时没有在途 query”而被提前接受。拒绝时以统一文本断开，该 future 永不完成。
 *
 * <p>分两段：收到登录 Hello 时先做限流与 IP 封禁；Fabric 的 QUERY_START 再做名字 / UUID 封禁并启动
 * 第一阶段 PSK 门禁。online/offline 两种模式都必须通过；证明绑定登录用户名。
 *
 * <p>认证通过之前，其他登录 query（Fabric API 自身的、其他 mod 的）一律扣下，机器人在握手前只能看到本 mod 的
 * query，无从判断服务器使用的加载器与 mod；认证通过时按原顺序补发后才放行，被拒时丢弃。
 *
 * <p>PSK 状态转换都在 {@link #lock} 内进行。
 */
public final class LoginFlow {
    private final TrustedServerRuntime runtime;
    private final ServerLoginPacketListenerImpl handler;
    private final MinecraftServer server;
    private final Object lock = new Object();
    private final CompletableFuture<Void> authDone = new CompletableFuture<>();

    private Object sender;
    private InetAddress address;
    private GameProfile profile;
    private PresharedKeyHandshake.Server psk;
    private PskStage pskStage = PskStage.NOT_STARTED;
    private OnlineTokenWire.Challenge tokenChallenge;
    private OnlineStage onlineStage = OnlineStage.NOT_STARTED;
    private byte[] issuedToken;
    private ServerAuthSession formalAuth;
    private String helloName;
    private boolean offlineFallback;
    private ScheduledFuture<?> timeoutTask;
    private boolean done;
    private boolean gateReported;
    private boolean gateSlot;
    private boolean promptGranted;
    private long timeoutGeneration;
    /** 认证通过前扣下的其他登录 query，按发送顺序保存。 */
    private final List<HeldPacket> held = new ArrayList<>();
    private boolean released;

    private record HeldPacket(Connection connection, Packet<?> packet, PacketSendListener listener) {
    }

    private enum PskStage {
        NOT_STARTED,
        WAIT_CLIENT_RESPONSE,
        WAIT_ACK,
        PASSED
    }

    private enum OnlineStage {
        NOT_STARTED,
        WAIT_PROOF,
        WAIT_ISSUE_ACK,
        PASSED
    }

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
        Connection connection = MinecraftAccess.connection(handler);
        address = TrustedServerRuntime.inet(connection.getRemoteAddress())
                .orElse(InetAddress.getLoopbackAddress());
        ConnectionGate.Verdict verdict = runtime.gate().beginLogin(address);
        if (verdict != ConnectionGate.Verdict.ALLOW) {
            rejectBeforeHandshake(verdict.name().toLowerCase(Locale.ROOT));
            return false;
        }
        gateSlot = true;
        if (server.getPlayerList().getIpBans().isBanned(connection.getRemoteAddress())) {
            rejectBeforeHandshake("ip banned");
            return false;
        }
        return true;
    }

    public void recordHelloName(String name) {
        synchronized (lock) {
            if (helloName == null) helloName = name;
        }
    }

    /** 原版 session 失败后切换到 PSK 回退；并不因此获得正版 UUID。 */
    public String beginOfflineFallback() {
        synchronized (lock) {
            offlineFallback = true;
            return helloName;
        }
    }

    /** Fabric 的 QUERY_START：完成封禁检查后启动第一阶段 PSK 门禁。 */
    void start(Object sender, ServerLoginNetworking.LoginSynchronizer synchronizer) {
        this.sender = sender;
        synchronizer.waitFor(authDone);
        synchronized (lock) {
            if (done) {
                return;
            }
        }
        GameProfile raw = MinecraftAccess.loginProfile(handler);
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
        scheduleTimeout(runtime.gateTimeoutSec());
        if (server.usesAuthentication() && !offlineFallback && raw.getId() != null) {
            beginOnlineToken();
            return;
        }
        try {
            if (runtime.onlineTokens().isReservedName(profile.getName())) {
                rejectBeforeHandshake("offline fallback attempted reserved online name");
                return;
            }
        } catch (IOException e) {
            rejectBeforeHandshake("cannot read online name claims");
            return;
        }
        beginPsk();
    }

    private void beginOnlineToken() {
        byte[] nonce = new byte[OnlineTokenWire.NONCE_LENGTH];
        runtime.random().nextBytes(nonce);
        tokenChallenge = new OnlineTokenWire.Challenge(runtime.identity().publicKey(), profile.getId(),
                profile.getName(), nonce);
        onlineStage = OnlineStage.WAIT_PROOF;
        sendOnline(OnlineTokenWire.encodeChallenge(tokenChallenge));
    }

    private void beginPsk() {
        byte[] challenge;
        synchronized (lock) {
            if (done) {
                return;
            }
            psk = PresharedKeyHandshake.beginServer(runtime.psk(), PskWire.context(profile.getName()), runtime.random());
            pskStage = PskStage.WAIT_CLIENT_RESPONSE;
            challenge = PskWire.encodeChallenge(psk.challenge());
        }
        sendPsk(challenge);
    }

    /** 收到 PSK query 回答；任一异常都按未可信连接统一拒绝。 */
    void onPskAnswer(boolean understood, FriendlyByteBuf buf) {
        byte[] next = null;
        boolean accepted = false;
        synchronized (lock) {
            if (done) {
                return;
            }
            try {
                if (!understood) {
                    throw new MalformedMessageException("client did not understand PSK query");
                }
                byte[] payload = new byte[buf.readableBytes()];
                buf.readBytes(payload);
                if (pskStage == PskStage.WAIT_CLIENT_RESPONSE) {
                    if (PskWire.type(payload) == PskWire.Type.PROMPT_REQUEST) {
                        PskWire.decodePromptRequest(payload);
                        if (promptGranted) {
                            throw new MalformedMessageException("duplicate PSK prompt request");
                        }
                        promptGranted = true;
                        psk.close();
                        psk = PresharedKeyHandshake.beginServer(runtime.psk(),
                                PskWire.context(profile.getName()), runtime.random());
                        next = PskWire.encodeChallenge(psk.challenge());
                        scheduleTimeout(runtime.authConfig().passwordTimeoutSec());
                    } else {
                        PresharedKeyHandshake.ServerProof proof = psk.verify(PskWire.decodeClientResponse(payload));
                        pskStage = PskStage.WAIT_ACK;
                        next = PskWire.encodeServerProof(proof);
                    }
                } else if (pskStage == PskStage.WAIT_ACK) {
                    PskWire.decodeAck(payload);
                    psk.close();
                    pskStage = PskStage.PASSED;
                    accepted = true;
                } else {
                    throw new MalformedMessageException("unexpected PSK answer state");
                }
            } catch (MalformedMessageException | PskAuthenticationException | IllegalArgumentException e) {
                // 失败原因只记固定类别，绝不输出证明或密钥材料
            }
        }
        if (accepted) {
            finishBaseAccepted("PSK", false);
            return;
        }
        if (next != null) {
            sendPsk(next);
            return;
        }
        rejectBeforeHandshake("PSK authentication failed");
    }

    /** 正版 session 已确认后的令牌证明；本地缺失或旧令牌会自动签发新令牌。 */
    void onOnlineTokenAnswer(boolean understood, FriendlyByteBuf buf) {
        byte[] next = null;
        boolean accepted = false;
        synchronized (lock) {
            if (done) return;
            try {
                if (!understood) throw new MalformedMessageException("client did not understand online token query");
                byte[] payload = new byte[buf.readableBytes()];
                buf.readBytes(payload);
                if (onlineStage == OnlineStage.WAIT_PROOF) {
                    OnlineTokenWire.ClientProof proof = OnlineTokenWire.decodeClientProof(payload);
                    boolean matched = false;
                    for (byte[] token : runtime.onlineTokens().tokens(profile.getId())) {
                        try {
                            matched |= OnlineTokenWire.verifiesToken(token, tokenChallenge, proof);
                        } finally {
                            Arrays.fill(token, (byte) 0);
                        }
                    }
                    if (matched) {
                        onlineStage = OnlineStage.PASSED;
                        accepted = true;
                    } else {
                        issuedToken = new byte[OnlineTokenWire.TOKEN_LENGTH];
                        runtime.random().nextBytes(issuedToken);
                        onlineStage = OnlineStage.WAIT_ISSUE_ACK;
                        next = OnlineTokenWire.encodeIssue(issuedToken);
                    }
                } else if (onlineStage == OnlineStage.WAIT_ISSUE_ACK) {
                    if (!OnlineTokenWire.verifiesAck(issuedToken, tokenChallenge,
                            OnlineTokenWire.decodeAck(payload))) {
                        throw new MalformedMessageException("bad online token acknowledgement");
                    }
                    runtime.onlineTokens().add(profile.getId(), profile.getName(), issuedToken);
                    clearIssuedToken();
                    onlineStage = OnlineStage.PASSED;
                    accepted = true;
                } else {
                    throw new MalformedMessageException("unexpected online token answer state");
                }
            } catch (MalformedMessageException | IllegalArgumentException | IOException e) {
                // 远端只收到统一拒绝；不记录令牌、证明或可区分的详细原因。
            }
        }
        if (accepted) {
            finishBaseAccepted("online session token", true);
        } else if (next != null) {
            sendOnline(next);
        } else {
            rejectBeforeHandshake("online token authentication failed");
        }
    }

    private void scheduleTimeout(int seconds) {
        long generation = ++timeoutGeneration;
        ScheduledFuture<?> previous = timeoutTask;
        if (previous != null) {
            previous.cancel(false);
        }
        timeoutTask = runtime.scheduler().schedule(() -> onTimeout(generation), seconds, TimeUnit.SECONDS);
    }

    private void onTimeout(long generation) {
        synchronized (lock) {
            if (done || generation != timeoutGeneration) {
                return;
            }
        }
        rejectBeforeHandshake("authentication timeout");
    }

    /** 基础门禁通过后按配置进入 Ed25519 正式认证，或直接放行。 */
    private void finishBaseAccepted(String method, boolean mojangVerified) {
        if (!runtime.authConfig().validation().ed25519()) {
            finishAccepted(method, null);
            return;
        }
        ServerAuthSession session;
        synchronized (lock) {
            if (done || formalAuth != null) {
                return;
            }
            String accountId = mojangVerified
                    ? profile.getId().toString()
                    : profile.getName().toLowerCase(Locale.ROOT);
            session = new ServerAuthSession(accountId, profile.getName(), server.usesAuthentication(),
                    mojangVerified, runtime.authConfig(), runtime.identity(), runtime.accounts(), runtime.random());
            formalAuth = session;
            scheduleTimeout(runtime.authTimeoutSec());
        }
        sendFormal(session.start());
        TrustedServerFabric.LOGGER.debug("{} passed {} base gate; starting Ed25519 authentication",
                profile.getName(), method);
    }

    /** 处理正式认证频道的回答；数据库和密码哈希结果统一切回服务端线程。 */
    void onFormalAnswer(Channel channel, boolean understood, FriendlyByteBuf buf) {
        ServerAuthSession session;
        byte[] payload = null;
        synchronized (lock) {
            if (done || formalAuth == null) {
                rejectBeforeHandshake("unexpected formal authentication answer");
                return;
            }
            session = formalAuth;
            if (understood) {
                payload = new byte[buf.readableBytes()];
                buf.readBytes(payload);
            }
        }
        try {
            session.onAnswer(channel, payload).whenComplete((step, error) ->
                    server.execute(() -> handleFormalStep(step, error)));
        } catch (RuntimeException e) {
            rejectAuthentication("formal authentication protocol state error", false);
        }
    }

    private void handleFormalStep(ServerStep step, Throwable error) {
        if (error != null || step == null) {
            rejectAuthentication("formal authentication internal error", false);
            return;
        }
        if (step instanceof ServerStep.Send send) {
            sendFormal(send.next());
            return;
        }
        AuthOutcome outcome = ((ServerStep.Done) step).outcome();
        if (outcome instanceof AuthOutcome.Rejected rejected) {
            Component message = rejected.trusted() && rejected.reason() == RejectReason.KEY_MISMATCH
                    ? Component.literal("设备密钥与绑定不匹配或无法自助恢复。请使用原设备或导入认证备份，"
                            + "也可使用已设置的找回密码，或联系管理员。")
                    : runtime.rejection();
            rejectAuthentication("formal authentication " + rejected.reason().name().toLowerCase(Locale.ROOT),
                    rejected.trusted(), message);
            return;
        }
        AuthOutcome.Accepted accepted = (AuthOutcome.Accepted) outcome;
        runtime.accounts().recordLogin(accepted.accountId(), accepted.username(), address.getHostAddress())
                .whenComplete((ignored, recordError) -> server.execute(() -> {
                    if (recordError != null) {
                        accepted.handover().close();
                        rejectAuthentication("cannot record authenticated login", true);
                    } else {
                        finishAccepted("Ed25519", accepted);
                    }
                }));
    }

    /**
     * 连接要发出一条非本 mod 的登录 query 时调用（任意线程）。
     *
     * @return {@code true} 表示已扣下或丢弃，调用方不应再发送
     */
    public boolean holdOutgoing(Connection connection, Packet<?> packet, PacketSendListener listener) {
        synchronized (lock) {
            if (released) {
                return false;
            }
            if (done) {
                // 已被拒绝：直接丢弃
                release(packet);
                return true;
            }
            held.add(new HeldPacket(connection, packet, listener));
            return true;
        }
    }

    private void finishAccepted(String method, AuthOutcome.Accepted accepted) {
        List<HeldPacket> toSend = List.of();
        synchronized (lock) {
            if (done) {
                if (accepted != null) accepted.handover().close();
                return;
            }
            done = true;
            released = true;
            toSend = new ArrayList<>(held);
            held.clear();
            if (accepted != null) {
                runtime.registerHandover(
                        MinecraftAccess.connection(handler), accepted);
            }
        }
        cancelTimeout();
        // 先补发被扣下的加载器 query，再完成 synchronizer，防止 Fabric 提前放行
        for (HeldPacket h : toSend) {
            h.connection().send(h.packet(), h.listener());
        }
        reportGate(true);
        runtime.flows.remove(handler);
        TrustedServerFabric.LOGGER.info("{} passed TrustedServer {} gate", profile.getName(), method);
        authDone.complete(null);
    }

    /** 协议握手之前的拒绝（限流、封禁、锁定）。 */
    private void rejectBeforeHandshake(String reason) {
        rejectAuthentication(reason, false);
    }

    private void rejectAuthentication(String reason, boolean trusted) {
        rejectAuthentication(reason, trusted, runtime.rejection());
    }

    private void rejectAuthentication(String reason, boolean trusted, Component message) {
        synchronized (lock) {
            if (done) {
                return;
            }
            done = true;
            held.forEach(h -> release(h.packet()));
            held.clear();
        }
        cancelTimeout();
        closePsk();
        clearIssuedToken();
        ServerAuthSession formal = formalAuth;
        if (formal != null) {
            formal.timeout();
        }
        reportGate(trusted);
        log(reason, trusted);
        handler.disconnect(message);
    }

    /** Fabric 的登录阶段断开事件。 */
    void onDisconnect() {
        cancelTimeout();
        synchronized (lock) {
            if (!done) {
                done = true;
            }
            held.forEach(h -> release(h.packet()));
            held.clear();
        }
        closePsk();
        clearIssuedToken();
        ServerAuthSession formal = formalAuth;
        if (formal != null) {
            formal.timeout();
        }
        reportGate(false);
        runtime.flows.remove(handler);
    }

    private static void release(Packet<?> packet) {
        if (packet instanceof ClientboundCustomQueryPacket query) {
            MinecraftAccess.releaseLoginQuery(query);
        }
    }

    private void sendPsk(byte[] payload) {
        PlayPasswordNetworking.sendLoginQuery(sender, PskWire.CHANNEL, payload);
    }

    private void sendOnline(byte[] payload) {
        PlayPasswordNetworking.sendLoginQuery(sender, OnlineTokenWire.CHANNEL, payload);
    }

    private void sendFormal(Outbound outbound) {
        PlayPasswordNetworking.sendLoginQuery(sender, outbound.channel().id(), outbound.payload());
    }

    private void clearIssuedToken() {
        if (issuedToken != null) {
            Arrays.fill(issuedToken, (byte) 0);
            issuedToken = null;
        }
    }

    private void closePsk() {
        PresharedKeyHandshake.Server current = psk;
        if (current != null) {
            current.close();
        }
    }

    private synchronized void reportGate(boolean trustedHandshake) {
        if (!gateReported) {
            gateReported = true;
            if (gateSlot) {
                runtime.gate().endLogin(address, trustedHandshake);
            } else if (!trustedHandshake) {
                runtime.gate().rejectLogin(address);
            }
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
