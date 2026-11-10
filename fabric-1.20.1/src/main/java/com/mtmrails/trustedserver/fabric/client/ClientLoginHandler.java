package com.mtmrails.trustedserver.fabric.client;

import com.mtmrails.trustedserver.core.message.Channel;
import com.mtmrails.trustedserver.core.session.ClientAuthSession;
import com.mtmrails.trustedserver.core.session.ClientFailure;
import com.mtmrails.trustedserver.core.session.ClientResult;
import com.mtmrails.trustedserver.core.session.ClientStep;
import com.mtmrails.trustedserver.fabric.TrustedServerFabric;
import com.mtmrails.trustedserver.fabric.mixin.ClientHandshakePacketListenerAccessor;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import net.fabricmc.fabric.api.client.networking.v1.ClientLoginConnectionEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientLoginNetworking;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.fabric.api.networking.v1.PacketByteBufs;
import net.minecraft.ChatFormatting;
import net.minecraft.client.Minecraft;
import net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.network.Connection;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.chat.Component;
import net.minecraft.resources.ResourceLocation;

/**
 * 客户端登录阶段：把服务端的 query 交给 {@link ClientAuthSession}，把结果写回。
 * 本地检测到的失败（版本不兼容、服务端身份变化等）直接断开，并在断开界面显示原因。
 */
final class ClientLoginHandler {
    private final FabricClientEnvironment environment;
    private final SecureRandom random = new SecureRandom();
    private final Map<ClientHandshakePacketListenerImpl, ClientAuthSession> sessions = new ConcurrentHashMap<>();
    private final Map<Connection, ClientResult> completed = new ConcurrentHashMap<>();

    ClientLoginHandler(FabricClientEnvironment environment) {
        this.environment = environment;
    }

    void register() {
        for (Channel channel : Channel.values()) {
            ClientLoginNetworking.registerGlobalReceiver(new ResourceLocation(channel.id()),
                    (client, handler, buf, listenerAdder) -> onQuery(channel, client, handler, buf));
        }
        ClientLoginConnectionEvents.DISCONNECT.register((handler, client) -> {
            ClientAuthSession session = sessions.remove(handler);
            if (session != null) {
                session.abort();
            }
            ClientResult result = completed.remove(connection(handler));
            if (result != null) {
                result.handover().close();
            }
        });
        ClientPlayConnectionEvents.JOIN.register((handler, sender, client) -> {
            ClientResult result = completed.get(handler.getConnection());
            if (result != null && !result.notices().isEmpty()) {
                client.execute(() -> {
                    if (client.player != null) {
                        for (String notice : result.notices()) {
                            client.player.displayClientMessage(Component.literal("[TrustedServer] " + notice)
                                    .withStyle(ChatFormatting.YELLOW), false);
                        }
                    }
                });
            }
        });
        ClientPlayConnectionEvents.DISCONNECT.register((handler, client) -> {
            ClientResult result = completed.remove(handler.getConnection());
            if (result != null) {
                result.handover().close();
            }
        });
    }

    private CompletableFuture<FriendlyByteBuf> onQuery(Channel channel, Minecraft client,
            ClientHandshakePacketListenerImpl handler, FriendlyByteBuf buf) {
        byte[] payload = new byte[buf.readableBytes()];
        buf.readBytes(payload);
        ClientAuthSession session = sessions.computeIfAbsent(handler, h -> new ClientAuthSession(
                serverAddress(client, h), client.getUser().getName(), false, environment, random));
        CompletableFuture<ClientStep> step;
        try {
            step = session.onQuery(channel, payload);
        } catch (IllegalStateException e) {
            step = CompletableFuture.completedFuture(new ClientStep.Fail(
                    new ClientFailure(ClientFailure.Kind.PROTOCOL_ERROR, e.getMessage()), java.util.Optional.empty()));
        }
        return step.handle((result, error) -> {
            if (error != null) {
                return fail(handler, new ClientFailure(ClientFailure.Kind.INTERNAL_ERROR, String.valueOf(error)));
            }
            if (result instanceof ClientStep.Reply reply) {
                return toBuf(reply.payload());
            }
            if (result instanceof ClientStep.Complete complete) {
                sessions.remove(handler);
                completed.put(connection(handler), complete.result());
                return toBuf(complete.payload());
            }
            return fail(handler, ((ClientStep.Fail) result).failure());
        });
    }

    private FriendlyByteBuf fail(ClientHandshakePacketListenerImpl handler, ClientFailure failure) {
        sessions.remove(handler);
        TrustedServerFabric.LOGGER.warn("TrustedServer authentication failed locally: {} ({})", failure.kind(),
                failure.detail());
        connection(handler).disconnect(message(failure));
        return null;
    }

    private static FriendlyByteBuf toBuf(byte[] payload) {
        FriendlyByteBuf buf = PacketByteBufs.create();
        buf.writeBytes(payload);
        return buf;
    }

    static Connection connection(ClientHandshakePacketListenerImpl handler) {
        return ((ClientHandshakePacketListenerAccessor) handler).trustedserver$connection();
    }

    /** TOFU 记录使用玩家输入的服务器地址；拿不到时退回连接的远端地址。 */
    static String serverAddress(Minecraft client, ClientHandshakePacketListenerImpl handler) {
        ServerData server = ((ClientHandshakePacketListenerAccessor) handler).trustedserver$serverData();
        if (server == null) {
            server = client.getCurrentServer();
        }
        if (server != null && server.ip != null && !server.ip.isBlank()) {
            return server.ip;
        }
        return String.valueOf(connection(handler).getRemoteAddress()).replace("/", "");
    }

    static Component message(ClientFailure failure) {
        String text = switch (failure.kind()) {
            case VERSION_MISMATCH -> "TrustedServer 认证协议版本不兼容，请更新 mod。\n" + failure.detail();
            case SERVER_SIGNATURE_INVALID -> "服务器身份验证失败（签名无效），连接可能被中间人篡改。";
            case SERVER_KEY_REJECTED -> "服务器身份公钥与上次记录的不一致，连接可能被中间人篡改，已拒绝连接。\n"
                    + "如果服主确认更换了服务器密钥，请删除 config/trustedserver/known_servers.txt 中该服务器的那一行后重试。";
            case USER_CANCELLED -> "此服务器要求输入密码，当前版本的 TrustedServer 尚不支持密码输入。";
            case CRYPTO_FAILURE, PROTOCOL_ERROR -> "TrustedServer 认证失败（" + failure.kind() + "）。";
            case INTERNAL_ERROR -> "TrustedServer 本地错误：" + failure.detail();
        };
        return Component.literal(text);
    }
}
