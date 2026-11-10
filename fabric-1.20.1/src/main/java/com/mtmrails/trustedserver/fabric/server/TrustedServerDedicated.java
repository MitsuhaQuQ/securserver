package com.mtmrails.trustedserver.fabric.server;

import com.mtmrails.trustedserver.core.crypto.PskWire;
import com.mtmrails.trustedserver.core.crypto.OnlineTokenWire;
import com.mtmrails.trustedserver.core.message.Channel;
import com.mtmrails.trustedserver.server.account.PlayPasswordEndpoint;
import net.fabricmc.api.DedicatedServerModInitializer;
import net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerLifecycleEvents;
import net.fabricmc.fabric.api.networking.v1.ServerLoginConnectionEvents;
import net.fabricmc.fabric.api.networking.v1.ServerLoginNetworking;
import net.fabricmc.fabric.api.networking.v1.ServerPlayConnectionEvents;
import net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking;
import net.fabricmc.fabric.api.networking.v1.PacketByteBufs;
import net.minecraft.network.FriendlyByteBuf;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.resources.ResourceLocation;

/**
 * 独立服务端入口。内置服务器（单人游戏、局域网）不会调用它，因此认证只在独立服务端生效（AGENTS.md）。
 */
public final class TrustedServerDedicated implements DedicatedServerModInitializer {
    private static final ResourceLocation PASSWORD_CHANNEL = new ResourceLocation(Channel.PASSWORD.id());

    @Override
    public void onInitializeServer() {
        TrustedServerRuntime.start(FabricLoader.getInstance().getConfigDir());

        ServerLoginConnectionEvents.QUERY_START.register((handler, server, sender, synchronizer) -> {
            TrustedServerRuntime runtime = TrustedServerRuntime.get();
            if (runtime == null) {
                return;
            }
            LoginFlow flow = runtime.flows.get(handler);
            if (flow == null) {
                // 正常情况下 Hello 时已建立；保险起见补做 Hello 阶段的检查
                flow = runtime.beginLogin(handler, server);
                if (flow == null) {
                    return;
                }
            }
            flow.start(sender, synchronizer);
        });
        ServerLoginNetworking.registerGlobalReceiver(new ResourceLocation(PskWire.CHANNEL),
                (server, handler, understood, buf, synchronizer, responseSender) -> {
                    TrustedServerRuntime runtime = TrustedServerRuntime.get();
                    LoginFlow flow = runtime == null ? null : runtime.flows.get(handler);
                    if (flow != null) {
                        flow.onPskAnswer(understood, buf);
                    }
                });
        ServerLoginNetworking.registerGlobalReceiver(new ResourceLocation(OnlineTokenWire.CHANNEL),
                (server, handler, understood, buf, synchronizer, responseSender) -> {
                    TrustedServerRuntime runtime = TrustedServerRuntime.get();
                    LoginFlow flow = runtime == null ? null : runtime.flows.get(handler);
                    if (flow != null) {
                        flow.onOnlineTokenAnswer(understood, buf);
                    }
                });
        for (Channel channel : Channel.values()) {
            ServerLoginNetworking.registerGlobalReceiver(new ResourceLocation(channel.id()),
                    (server, handler, understood, buf, synchronizer, responseSender) -> {
                        TrustedServerRuntime runtime = TrustedServerRuntime.get();
                        LoginFlow flow = runtime == null ? null : runtime.flows.get(handler);
                        if (flow != null) {
                            flow.onFormalAnswer(channel, understood, buf);
                        }
                    });
        }
        ServerLoginConnectionEvents.DISCONNECT.register((handler, server) -> {
            TrustedServerRuntime runtime = TrustedServerRuntime.get();
            LoginFlow flow = runtime == null ? null : runtime.flows.get(handler);
            if (flow != null) {
                flow.onDisconnect();
            }
        });
        ServerPlayConnectionEvents.JOIN.register((handler, sender, server) -> {
            TrustedServerRuntime runtime = TrustedServerRuntime.get();
            if (runtime == null) {
                return;
            }
            runtime.openPasswordEndpoint(handler.getPlayer().getUUID(), new PlayPasswordEndpoint.Listener() {
                @Override
                public void send(byte[] payload) {
                    server.execute(() -> {
                        FriendlyByteBuf buf = PacketByteBufs.create();
                        buf.writeBytes(payload);
                        sender.sendPacket(PASSWORD_CHANNEL, buf);
                    });
                }

                @Override
                public void passwordSet(boolean login) {
                    // 账号存储已更新；游戏内受限权限将在限制执行阶段接到这里。
                }

                @Override
                public void kick() {
                    server.execute(() -> {
                        runtime.closeHandover(handler.getPlayer().getUUID());
                        handler.disconnect(runtime.rejection());
                    });
                }
            });
        });
        ServerPlayNetworking.registerGlobalReceiver(PASSWORD_CHANNEL,
                (server, handler, serverPacketListener, buf, responseSender) -> {
                    TrustedServerRuntime runtime = TrustedServerRuntime.get();
                    PlayPasswordEndpoint endpoint = runtime == null ? null
                            : runtime.passwordEndpoint(handler.getUUID());
                    if (endpoint == null) {
                        if (runtime != null) {
                            handler.connection.disconnect(runtime.rejection());
                        }
                        return;
                    }
                    byte[] payload = new byte[buf.readableBytes()];
                    buf.readBytes(payload);
                    endpoint.onPayload(payload);
                });
        ServerPlayConnectionEvents.DISCONNECT.register((handler, server) -> {
            TrustedServerRuntime runtime = TrustedServerRuntime.get();
            if (runtime != null) {
                runtime.closeHandover(handler.getPlayer().getUUID());
            }
        });
        CommandRegistrationCallback.EVENT.register((dispatcher, registryAccess, environment) ->
                AdminCommands.register(dispatcher));
        ServerLifecycleEvents.SERVER_STOPPED.register(server -> TrustedServerRuntime.stop());
    }
}
