package com.mtmrails.trustedserver.fabric.client;

import com.mtmrails.trustedserver.client.OnlineTokens;
import com.mtmrails.trustedserver.core.crypto.OnlineTokenWire;
import com.mtmrails.trustedserver.fabric.MinecraftAccess;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.fabric.TrustedServerFabric;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import net.fabricmc.fabric.api.client.networking.v1.ClientLoginConnectionEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientLoginNetworking;
import net.fabricmc.fabric.api.networking.v1.PacketByteBufs;
import net.minecraft.client.Minecraft;
import net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.chat.Component;
import net.minecraft.resources.ResourceLocation;

/** 正版 session 成功后的自动令牌登记；无需玩家复制凭据或在换机时请求重置。 */
final class OnlineTokenLoginHandler {
    private final OnlineTokens tokens;
    private final Map<ClientHandshakePacketListenerImpl, Pending> pending = new ConcurrentHashMap<>();

    private record Pending(String address, OnlineTokenWire.Challenge challenge) {
    }

    OnlineTokenLoginHandler(OnlineTokens tokens) {
        this.tokens = tokens;
    }

    void register() {
        ClientLoginNetworking.registerGlobalReceiver(MinecraftAccess.resourceLocation(OnlineTokenWire.CHANNEL),
                (client, handler, buf, listenerAdder) -> onQuery(client, handler, buf));
        ClientLoginConnectionEvents.DISCONNECT.register((handler, client) -> pending.remove(handler));
    }

    private CompletableFuture<FriendlyByteBuf> onQuery(Minecraft client,
            ClientHandshakePacketListenerImpl handler, FriendlyByteBuf buf) {
        byte[] payload = new byte[buf.readableBytes()];
        buf.readBytes(payload);
        try {
            if (pending.containsKey(handler)) {
                return CompletableFuture.completedFuture(onIssue(handler, payload));
            }
            return CompletableFuture.completedFuture(onChallenge(client, handler, payload));
        } catch (IOException e) {
            return fail(handler, "无法保存正版登录令牌：" + e.getMessage());
        } catch (MalformedMessageException | IllegalArgumentException e) {
            return fail(handler, "正版令牌协议错误。");
        }
    }

    private FriendlyByteBuf onChallenge(Minecraft client, ClientHandshakePacketListenerImpl handler, byte[] payload)
            throws IOException, MalformedMessageException {
        OnlineTokenWire.Challenge challenge = OnlineTokenWire.decodeChallenge(payload);
        String address = ClientLoginHandler.serverAddress(client, handler);
        pending.put(handler, new Pending(address, challenge));
        Optional<byte[]> existing = tokens.get(address, challenge.serverIdentity(), challenge.playerId(),
                challenge.username());
        if (existing.isEmpty()) {
            return toBuf(OnlineTokenWire.encodeClientProof(new OnlineTokenWire.ClientProof(false, new byte[0])));
        }
        byte[] token = existing.orElseThrow();
        try {
            return toBuf(OnlineTokenWire.encodeClientProof(new OnlineTokenWire.ClientProof(true,
                    OnlineTokenWire.tokenProof(token, challenge))));
        } finally {
            Arrays.fill(token, (byte) 0);
        }
    }

    private FriendlyByteBuf onIssue(ClientHandshakePacketListenerImpl handler, byte[] payload)
            throws IOException, MalformedMessageException {
        Pending state = pending.remove(handler);
        if (state == null) {
            throw new MalformedMessageException("token issue without challenge");
        }
        byte[] token = OnlineTokenWire.decodeIssue(payload);
        try {
            OnlineTokenWire.Challenge challenge = state.challenge();
            tokens.put(state.address(), challenge.serverIdentity(), challenge.playerId(), challenge.username(), token);
            return toBuf(OnlineTokenWire.encodeAck(OnlineTokenWire.issueAck(token, challenge)));
        } finally {
            Arrays.fill(token, (byte) 0);
        }
    }

    private CompletableFuture<FriendlyByteBuf> fail(ClientHandshakePacketListenerImpl handler, String message) {
        pending.remove(handler);
        TrustedServerFabric.LOGGER.warn("TrustedServer online token failed locally: {}", message);
        ClientLoginHandler.connection(handler).disconnect(Component.literal(message));
        return CompletableFuture.completedFuture(null);
    }

    private static FriendlyByteBuf toBuf(byte[] payload) {
        FriendlyByteBuf buf = PacketByteBufs.create();
        buf.writeBytes(payload);
        return buf;
    }
}
