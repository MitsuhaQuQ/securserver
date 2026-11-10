package com.mtmrails.trustedserver.fabric.network;

import com.mtmrails.trustedserver.core.message.Channel;
import com.mtmrails.trustedserver.fabric.MinecraftAccess;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.fabricmc.fabric.api.networking.v1.PacketByteBufs;
import net.fabricmc.fabric.api.networking.v1.PacketSender;
import net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.server.level.ServerPlayer;

/** Fabric 1.20.1–1.20.4 的频道 + FriendlyByteBuf API。 */
final class VersionedPlayPasswordNetworking {
    private static final ResourceLocation CHANNEL = MinecraftAccess.resourceLocation(Channel.PASSWORD.id());

    private VersionedPlayPasswordNetworking() {
    }

    static void registerClientReceiver(Consumer<byte[]> receiver) {
        ClientPlayNetworking.registerGlobalReceiver(CHANNEL, (client, handler, buf, responseSender) ->
                receiver.accept(read(buf)));
    }

    static void sendClient(byte[] payload) {
        ClientPlayNetworking.send(CHANNEL, write(payload));
    }

    static void registerServerReceiver(BiConsumer<ServerPlayer, byte[]> receiver) {
        ServerPlayNetworking.registerGlobalReceiver(CHANNEL,
                (server, player, handler, buf, responseSender) -> receiver.accept(player, read(buf)));
    }

    static void sendServer(ServerPlayer player, byte[] payload) {
        ServerPlayNetworking.send(player, CHANNEL, write(payload));
    }

    static void sendLoginQuery(Object sender, String channel, byte[] payload) {
        ((PacketSender) sender).sendPacket(MinecraftAccess.resourceLocation(channel), write(payload));
    }

    private static FriendlyByteBuf write(byte[] payload) {
        FriendlyByteBuf buf = PacketByteBufs.create();
        buf.writeBytes(payload);
        return buf;
    }

    private static byte[] read(FriendlyByteBuf buf) {
        byte[] payload = new byte[buf.readableBytes()];
        buf.readBytes(payload);
        return payload;
    }
}
