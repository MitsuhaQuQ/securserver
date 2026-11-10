package com.mtmrails.trustedserver.fabric.server;

import com.mtmrails.trustedserver.core.crypto.PskWire;
import com.mtmrails.trustedserver.core.crypto.OnlineTokenWire;
import com.mtmrails.trustedserver.core.message.Channel;
import com.mtmrails.trustedserver.fabric.MinecraftAccess;
import com.mtmrails.trustedserver.fabric.network.PlayPasswordNetworking;
import com.mtmrails.trustedserver.server.account.PlayPasswordEndpoint;
import java.util.UUID;
import net.fabricmc.api.DedicatedServerModInitializer;
import net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerLifecycleEvents;
import net.fabricmc.fabric.api.networking.v1.ServerLoginConnectionEvents;
import net.fabricmc.fabric.api.networking.v1.ServerLoginNetworking;
import net.fabricmc.fabric.api.networking.v1.ServerPlayConnectionEvents;
import net.minecraft.network.Connection;
import net.fabricmc.loader.api.FabricLoader;

/**
 * 独立服务端入口。内置服务器（单人游戏、局域网）不会调用它，因此认证只在独立服务端生效（AGENTS.md）。
 */
public final class TrustedServerDedicated implements DedicatedServerModInitializer {
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
        ServerLoginNetworking.registerGlobalReceiver(MinecraftAccess.resourceLocation(PskWire.CHANNEL),
                (server, handler, understood, buf, synchronizer, responseSender) -> {
                    TrustedServerRuntime runtime = TrustedServerRuntime.get();
                    LoginFlow flow = runtime == null ? null : runtime.flows.get(handler);
                    if (flow != null) {
                        flow.onPskAnswer(understood, buf);
                    }
                });
        ServerLoginNetworking.registerGlobalReceiver(MinecraftAccess.resourceLocation(OnlineTokenWire.CHANNEL),
                (server, handler, understood, buf, synchronizer, responseSender) -> {
                    TrustedServerRuntime runtime = TrustedServerRuntime.get();
                    LoginFlow flow = runtime == null ? null : runtime.flows.get(handler);
                    if (flow != null) {
                        flow.onOnlineTokenAnswer(understood, buf);
                    }
                });
        for (Channel channel : Channel.values()) {
            ServerLoginNetworking.registerGlobalReceiver(MinecraftAccess.resourceLocation(channel.id()),
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
            if (runtime != null) {
                runtime.closePendingHandover(
                        MinecraftAccess.connection(handler));
            }
        });
        ServerPlayConnectionEvents.JOIN.register((handler, sender, server) -> {
            TrustedServerRuntime runtime = TrustedServerRuntime.get();
            if (runtime == null) {
                return;
            }
            Connection connection = TrustedServerRuntime.connectionOf(handler);
            UUID playerId = handler.getPlayer().getUUID();
            runtime.openPasswordEndpoint(playerId, connection, new PlayPasswordEndpoint.Listener() {
                @Override
                public void send(byte[] payload) {
                    server.execute(() -> PlayPasswordNetworking.sendServer(handler.getPlayer(), payload));
                }

                @Override
                public void passwordSet(boolean login) {
                    if (login) {
                        server.execute(() -> {
                            if (connection.isConnected()) {
                                runtime.loginPasswordSet(handler.getPlayer());
                            }
                        });
                    }
                }

                @Override
                public void kick() {
                    server.execute(() -> handler.disconnect(runtime.rejection()));
                }
            });
            runtime.notifySuspendedOp(handler.getPlayer());
        });
        PlayPasswordNetworking.registerServerReceiver((handler, payload) -> {
                    TrustedServerRuntime runtime = TrustedServerRuntime.get();
                    PlayPasswordEndpoint endpoint = runtime == null ? null
                            : runtime.passwordEndpoint(handler.getUUID(),
                                    TrustedServerRuntime.connectionOf(handler.connection));
                    if (endpoint == null) {
                        if (runtime != null) {
                            handler.connection.disconnect(runtime.rejection());
                        }
                        return;
                    }
                    endpoint.onPayload(payload);
                });
        ServerPlayConnectionEvents.DISCONNECT.register((handler, server) -> {
            TrustedServerRuntime runtime = TrustedServerRuntime.get();
            if (runtime != null) {
                runtime.closePlay(handler.getPlayer().getUUID(), TrustedServerRuntime.connectionOf(handler));
            }
        });
        CommandRegistrationCallback.EVENT.register((dispatcher, registryAccess, environment) ->
                AdminCommands.register(dispatcher));
        ServerLifecycleEvents.SERVER_STOPPED.register(server -> TrustedServerRuntime.stop());
    }
}
