package com.mtmrails.trustedserver.fabric.network;

import java.util.function.BiConsumer;
import java.util.function.Consumer;
import net.minecraft.server.level.ServerPlayer;

/** Minecraft/Fabric 版本专用游戏阶段 payload API 的稳定入口。 */
public final class PlayPasswordNetworking {
    private PlayPasswordNetworking() {
    }

    public static void registerClientReceiver(Consumer<byte[]> receiver) {
        VersionedPlayPasswordNetworking.registerClientReceiver(receiver);
    }

    public static void sendClient(byte[] payload) {
        VersionedPlayPasswordNetworking.sendClient(payload);
    }

    public static void registerServerReceiver(BiConsumer<ServerPlayer, byte[]> receiver) {
        VersionedPlayPasswordNetworking.registerServerReceiver(receiver);
    }

    public static void sendServer(ServerPlayer player, byte[] payload) {
        VersionedPlayPasswordNetworking.sendServer(player, payload);
    }

    public static void sendLoginQuery(Object sender, String channel, byte[] payload) {
        VersionedPlayPasswordNetworking.sendLoginQuery(sender, channel, payload);
    }
}
