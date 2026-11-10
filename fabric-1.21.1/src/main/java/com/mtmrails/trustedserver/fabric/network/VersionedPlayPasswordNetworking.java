package com.mtmrails.trustedserver.fabric.network;

import com.mtmrails.trustedserver.core.message.Channel;
import com.mtmrails.trustedserver.fabric.MinecraftAccess;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayNetworking;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.fabricmc.fabric.api.networking.v1.LoginPacketSender;
import net.fabricmc.fabric.api.networking.v1.PacketByteBufs;
import net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking;
import net.minecraft.network.RegistryFriendlyByteBuf;
import net.minecraft.network.codec.StreamCodec;
import net.minecraft.network.protocol.common.custom.CustomPacketPayload;
import net.minecraft.server.level.ServerPlayer;

/** Fabric 1.21.1 的强类型 CustomPacketPayload API。 */
final class VersionedPlayPasswordNetworking {
    private static boolean registered;

    private VersionedPlayPasswordNetworking() {
    }

    static void registerClientReceiver(Consumer<byte[]> receiver) {
        registerTypes();
        ClientPlayNetworking.registerGlobalReceiver(PasswordPayload.TYPE,
                (payload, context) -> receiver.accept(payload.data()));
    }

    static void sendClient(byte[] payload) {
        ClientPlayNetworking.send(new PasswordPayload(payload));
    }

    static void registerServerReceiver(BiConsumer<ServerPlayer, byte[]> receiver) {
        registerTypes();
        ServerPlayNetworking.registerGlobalReceiver(PasswordPayload.TYPE,
                (payload, context) -> receiver.accept(context.player(), payload.data()));
    }

    static void sendServer(ServerPlayer player, byte[] payload) {
        ServerPlayNetworking.send(player, new PasswordPayload(payload));
    }

    static void sendLoginQuery(Object sender, String channel, byte[] payload) {
        net.minecraft.network.FriendlyByteBuf buf = PacketByteBufs.create();
        buf.writeBytes(payload);
        ((LoginPacketSender) sender).sendPacket(MinecraftAccess.resourceLocation(channel), buf);
    }

    private static synchronized void registerTypes() {
        if (registered) {
            return;
        }
        PayloadTypeRegistry.playC2S().register(PasswordPayload.TYPE, PasswordPayload.CODEC);
        PayloadTypeRegistry.playS2C().register(PasswordPayload.TYPE, PasswordPayload.CODEC);
        registered = true;
    }

    private record PasswordPayload(byte[] data) implements CustomPacketPayload {
        private static final int MAX_LENGTH = 1 << 20;
        private static final Type<PasswordPayload> TYPE = new Type<>(
                MinecraftAccess.resourceLocation(Channel.PASSWORD.id()));
        private static final StreamCodec<RegistryFriendlyByteBuf, PasswordPayload> CODEC =
                StreamCodec.ofMember(PasswordPayload::write, PasswordPayload::read);

        private PasswordPayload {
            data = data.clone();
        }

        private static PasswordPayload read(RegistryFriendlyByteBuf buf) {
            int length = buf.readVarInt();
            if (length < 0 || length > MAX_LENGTH) {
                throw new IllegalArgumentException("invalid TrustedServer password payload length " + length);
            }
            byte[] data = new byte[length];
            buf.readBytes(data);
            return new PasswordPayload(data);
        }

        private void write(RegistryFriendlyByteBuf buf) {
            buf.writeVarInt(data.length);
            buf.writeBytes(data);
        }

        @Override
        public Type<PasswordPayload> type() {
            return TYPE;
        }

        @Override
        public byte[] data() {
            return data.clone();
        }
    }
}
