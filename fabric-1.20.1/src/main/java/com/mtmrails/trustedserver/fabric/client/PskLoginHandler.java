package com.mtmrails.trustedserver.fabric.client;

import com.mtmrails.trustedserver.client.PresharedKeys;
import com.mtmrails.trustedserver.core.crypto.PresharedKeyHandshake;
import com.mtmrails.trustedserver.core.crypto.PskAuthenticationException;
import com.mtmrails.trustedserver.core.crypto.PskWire;
import com.mtmrails.trustedserver.fabric.MinecraftAccess;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.fabric.TrustedServerFabric;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CancellationException;
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

/** 第一阶段客户端 PSK 门禁；验证成功后由原版继续登录。 */
final class PskLoginHandler {
    private final PresharedKeys keys;
    private final SecureRandom random = new SecureRandom();
    private final Map<ClientHandshakePacketListenerImpl, PresharedKeyHandshake.Client> sessions =
            new ConcurrentHashMap<>();
    private final Map<ClientHandshakePacketListenerImpl, PromptState> prompts = new ConcurrentHashMap<>();

    private record PromptState(String address, CompletableFuture<byte[]> key, PskPromptScreen screen) {
    }

    PskLoginHandler(PresharedKeys keys) {
        this.keys = keys;
    }

    void register() {
        ClientLoginNetworking.registerGlobalReceiver(MinecraftAccess.resourceLocation(PskWire.CHANNEL),
                (client, handler, buf, listenerAdder) -> onQuery(client, handler, buf));
        ClientLoginConnectionEvents.DISCONNECT.register((handler, client) -> close(handler));
    }

    private CompletableFuture<FriendlyByteBuf> onQuery(Minecraft minecraft,
            ClientHandshakePacketListenerImpl handler, FriendlyByteBuf buf) {
        byte[] payload = new byte[buf.readableBytes()];
        buf.readBytes(payload);
        try {
            PskWire.Type type = PskWire.type(payload);
            if (type == PskWire.Type.CHALLENGE) {
                return onChallenge(minecraft, handler, payload);
            }
            if (type == PskWire.Type.SERVER_PROOF) {
                return CompletableFuture.completedFuture(onServerProof(handler, payload));
            }
            return fail(handler, "服务器发送了错误的 PSK 消息顺序。");
        } catch (IOException e) {
            return fail(handler, "无法读取 config/trustedserver/psk.txt：" + e.getMessage());
        } catch (MalformedMessageException | PskAuthenticationException | IllegalArgumentException e) {
            return fail(handler, "PSK 验证失败，服务器密钥可能不匹配。");
        }
    }

    private CompletableFuture<FriendlyByteBuf> onChallenge(Minecraft minecraft,
            ClientHandshakePacketListenerImpl handler,
            byte[] payload) throws IOException, MalformedMessageException {
        if (sessions.containsKey(handler)) {
            throw new MalformedMessageException("duplicate PSK challenge");
        }
        String address = ClientLoginHandler.serverAddress(minecraft, handler);
        PromptState pending = prompts.get(handler);
        if (pending == null) {
            Optional<byte[]> configured = keys.get(address);
            if (configured.isPresent()) {
                return CompletableFuture.completedFuture(beginResponse(minecraft, handler, payload,
                        configured.orElseThrow()));
            }
            CompletableFuture<byte[]> supplied = new CompletableFuture<>();
            PskPromptScreen screen = new PskPromptScreen(minecraft.screen, address, encoded -> {
                byte[] key = null;
                try {
                    key = PresharedKeys.decode(encoded);
                    keys.put(address, key);
                    supplied.complete(key);
                    key = null; // future 接管并在生成证明后清零
                    return Optional.empty();
                } catch (IOException | IllegalArgumentException e) {
                    return Optional.of(Component.literal(e.getMessage()));
                } finally {
                    if (key != null) {
                        Arrays.fill(key, (byte) 0);
                    }
                }
            }, () -> supplied.completeExceptionally(new CancellationException("PSK input cancelled")));
            pending = new PromptState(address, supplied, screen);
            PromptState raced = prompts.putIfAbsent(handler, pending);
            if (raced != null) {
                pending = raced;
            } else {
                PskPromptScreen prompt = screen;
                minecraft.execute(() -> minecraft.setScreen(prompt));
                return CompletableFuture.completedFuture(toBuf(PskWire.encodePromptRequest()));
            }
        }
        if (!pending.address().equals(address)) {
            throw new MalformedMessageException("server address changed during PSK prompt");
        }
        PromptState selected = pending;
        return selected.key().handle((key, error) -> {
            prompts.remove(handler, selected);
            if (error != null) {
                return failNow(handler, "已取消输入 TrustedServer PSK。");
            }
            try {
                return beginResponse(minecraft, handler, payload, key);
            } catch (MalformedMessageException | IllegalArgumentException e) {
                return failNow(handler, "PSK 验证失败，服务器密钥可能不匹配。");
            }
        });
    }

    private FriendlyByteBuf beginResponse(Minecraft minecraft, ClientHandshakePacketListenerImpl handler,
            byte[] payload, byte[] key) throws MalformedMessageException {
        try {
            PresharedKeyHandshake.Client session = PresharedKeyHandshake.beginClient(key,
                    PskWire.context(minecraft.getUser().getName()), PskWire.decodeChallenge(payload), random);
            sessions.put(handler, session);
            return toBuf(PskWire.encodeClientResponse(session.response()));
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private FriendlyByteBuf onServerProof(ClientHandshakePacketListenerImpl handler, byte[] payload)
            throws MalformedMessageException, PskAuthenticationException {
        PresharedKeyHandshake.Client session = sessions.remove(handler);
        if (session == null) {
            throw new MalformedMessageException("server proof without challenge");
        }
        try {
            session.verify(PskWire.decodeServerProof(payload));
            return toBuf(PskWire.encodeAck());
        } finally {
            session.close();
        }
    }

    private CompletableFuture<FriendlyByteBuf> fail(ClientHandshakePacketListenerImpl handler, String message) {
        return CompletableFuture.completedFuture(failNow(handler, message));
    }

    private FriendlyByteBuf failNow(ClientHandshakePacketListenerImpl handler, String message) {
        close(handler);
        TrustedServerFabric.LOGGER.warn("TrustedServer PSK gate failed locally: {}", message);
        ClientLoginHandler.connection(handler).disconnect(Component.literal(message));
        return null;
    }

    private void close(ClientHandshakePacketListenerImpl handler) {
        PromptState prompt = prompts.remove(handler);
        if (prompt != null) {
            prompt.key().completeExceptionally(new CancellationException("connection closed"));
        }
        PresharedKeyHandshake.Client session = sessions.remove(handler);
        if (session != null) {
            session.close();
        }
    }

    private static FriendlyByteBuf toBuf(byte[] payload) {
        FriendlyByteBuf buf = PacketByteBufs.create();
        buf.writeBytes(payload);
        return buf;
    }
}
