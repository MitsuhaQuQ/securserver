package com.mtmrails.trustedserver.fabric.client;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mtmrails.trustedserver.client.PasswordCommand;
import com.mtmrails.trustedserver.client.PlayPasswordClient;
import com.mtmrails.trustedserver.core.crypto.CryptoException;
import com.mtmrails.trustedserver.core.message.Channel;
import com.mtmrails.trustedserver.core.message.PasswordResult;
import com.mtmrails.trustedserver.core.session.ClientAuthSession;
import com.mtmrails.trustedserver.core.session.ClientFailure;
import com.mtmrails.trustedserver.core.session.ClientResult;
import com.mtmrails.trustedserver.core.session.ClientStep;
import com.mtmrails.trustedserver.fabric.TrustedServerFabric;
import com.mtmrails.trustedserver.fabric.MinecraftAccess;
import com.mtmrails.trustedserver.fabric.mixin.ClientHandshakePacketListenerAccessor;
import com.mtmrails.trustedserver.fabric.network.PlayPasswordNetworking;
import com.mtmrails.trustedserver.fabric.tunnel.TunnelPipeline;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import net.fabricmc.fabric.api.client.networking.v1.ClientLoginConnectionEvents;
import net.fabricmc.fabric.api.client.networking.v1.ClientLoginNetworking;
import net.fabricmc.fabric.api.client.networking.v1.ClientPlayConnectionEvents;
import net.fabricmc.fabric.api.client.message.v1.ClientSendMessageEvents;
import net.fabricmc.fabric.api.client.command.v2.ClientCommandManager;
import net.fabricmc.fabric.api.client.command.v2.ClientCommandRegistrationCallback;
import net.fabricmc.fabric.api.client.command.v2.FabricClientCommandSource;
import net.fabricmc.fabric.api.networking.v1.PacketByteBufs;
import net.minecraft.ChatFormatting;
import net.minecraft.client.Minecraft;
import net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.network.Connection;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.network.chat.Component;

/**
 * 客户端登录阶段：把服务端的 query 交给 {@link ClientAuthSession}，把结果写回。
 * 本地检测到的失败（版本不兼容、服务端身份变化等）直接断开，并在断开界面显示原因。
 */
final class ClientLoginHandler {
    private static final Pattern MIN_LENGTH = Pattern.compile("密码至少需要 (\\d+) 个字符");
    private static final Pattern MAX_LENGTH = Pattern.compile("密码最多 (\\d+) 个字符");
    private final FabricClientEnvironment environment;
    private final SecureRandom random = new SecureRandom();
    private final boolean wantTunnel;
    private final Map<ClientHandshakePacketListenerImpl, ClientAuthSession> sessions = new ConcurrentHashMap<>();
    private final Map<Connection, ClientResult> completed = new ConcurrentHashMap<>();
    private final Map<Connection, PlayPasswordClient> playPasswords = new ConcurrentHashMap<>();
    ClientLoginHandler(FabricClientEnvironment environment, boolean wantTunnel) {
        this.environment = environment;
        this.wantTunnel = wantTunnel;
    }

    void register() {
        for (Channel channel : Channel.values()) {
            ClientLoginNetworking.registerGlobalReceiver(MinecraftAccess.resourceLocation(channel.id()),
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
            if (result != null) {
                playPasswords.put(handler.getConnection(),
                        new PlayPasswordClient(result.handover().passwordChannel()));
            }
            if (result != null && !result.notices().isEmpty()) {
                client.execute(() -> {
                    if (client.player != null) {
                        for (String notice : result.notices()) {
                            client.player.displayClientMessage(Component.literal("[TrustedServer] ")
                                    .append(noticeMessage(notice)).withStyle(ChatFormatting.YELLOW), false);
                        }
                    }
                });
            }
        });
        ClientPlayConnectionEvents.DISCONNECT.register((handler, client) -> {
            playPasswords.remove(handler.getConnection());
            ClientResult result = completed.remove(handler.getConnection());
            if (result != null) {
                result.handover().close();
            }
        });
        PlayPasswordNetworking.registerClientReceiver(payload -> {
            Minecraft client = Minecraft.getInstance();
            if (client.getConnection() == null) {
                return;
            }
            Connection connection = client.getConnection().getConnection();
            client.execute(() -> {
                if (client.getConnection() != null && client.getConnection().getConnection() == connection) {
                    onPasswordResult(connection, payload);
                }
            });
        });
        ClientCommandRegistrationCallback.EVENT.register((dispatcher, buildContext) -> {
            registerPasswordCommand(dispatcher, "passwd");
            registerPasswordCommand(dispatcher, "recoverypasswd");
        });
        ClientSendMessageEvents.ALLOW_COMMAND.register(this::interceptPasswordCommand);
    }

    /**
     * 注册客户端命令树以提供命令名补全。参数使用 greedy string，由现有安全解析器统一校验，
     * 避免 Brigadier 在参数错误提示中回显玩家输入的密码。
     */
    private void registerPasswordCommand(CommandDispatcher<FabricClientCommandSource> dispatcher, String name) {
        dispatcher.register(ClientCommandManager.literal(name)
                .executes(context -> executePasswordCommand("/" + name))
                .then(ClientCommandManager.argument("arguments", StringArgumentType.greedyString())
                        .executes(context -> executePasswordCommand("/" + name + " "
                                + StringArgumentType.getString(context, "arguments")))));
    }

    private int executePasswordCommand(String commandLine) {
        try {
            return handlePasswordCommand(PasswordCommand.parse(commandLine)) ? 1 : 0;
        } catch (RuntimeException e) {
            // 不把异常交给 Fabric 命令执行器；它的默认日志会包含整行命令和密码。
            TrustedServerFabric.LOGGER.warn("Cannot execute local password command: {}",
                    e.getClass().getSimpleName());
            display(Component.translatable("trustedserver.password_channel.send_failed"), ChatFormatting.RED);
            return 0;
        }
    }

    /** 密码命令始终在本地截获，绝不进入原版命令包或聊天日志。 */
    private boolean interceptPasswordCommand(String commandLine) {
        PasswordCommand command = PasswordCommand.parse("/" + commandLine);
        if (command instanceof PasswordCommand.NotOurs) {
            return true;
        }
        handlePasswordCommand(command);
        return false;
    }

    private boolean handlePasswordCommand(PasswordCommand command) {
        if (command instanceof PasswordCommand.NotOurs) {
            return false;
        }
        if (command instanceof PasswordCommand.Invalid invalid) {
            Component reason = invalid.reason() == PasswordCommand.InvalidReason.USAGE
                    ? Component.translatable("trustedserver.command.password.usage", invalid.kind().usage())
                    : Component.translatable("trustedserver.error.password_mismatch");
            display(reason, ChatFormatting.RED);
            return false;
        }
        Minecraft client = Minecraft.getInstance();
        if (client.getConnection() == null) {
            display(Component.translatable("trustedserver.password_channel.unavailable"), ChatFormatting.RED);
            return false;
        }
        PlayPasswordClient passwordClient = playPasswords.get(client.getConnection().getConnection());
        if (passwordClient == null) {
            display(Component.translatable("trustedserver.password_channel.not_established"), ChatFormatting.RED);
            return false;
        }
        if (passwordClient.awaitingResult()) {
            display(Component.translatable("trustedserver.password_channel.pending"), ChatFormatting.YELLOW);
            return false;
        }
        try {
            byte[] payload = passwordClient.request((PasswordCommand.Set) command);
            PlayPasswordNetworking.sendClient(payload);
            display(Component.translatable("trustedserver.password_channel.submitting"), ChatFormatting.GRAY);
            return true;
        } catch (CryptoException | IllegalArgumentException | IllegalStateException e) {
            TrustedServerFabric.LOGGER.warn("Cannot send play password request: {}", e.getClass().getSimpleName());
            display(Component.translatable("trustedserver.password_channel.send_failed"), ChatFormatting.RED);
            return false;
        }
    }

    private void onPasswordResult(Connection connection, byte[] payload) {
        PlayPasswordClient passwordClient = playPasswords.get(connection);
        if (passwordClient == null) {
            connection.disconnect(Component.translatable("trustedserver.disconnect.password_channel_state"));
            return;
        }
        try {
            PasswordResult result = passwordClient.onPayload(payload);
            ChatFormatting color = result.status() == PasswordResult.Status.OK
                    ? ChatFormatting.GREEN : ChatFormatting.RED;
            display(passwordResultMessage(result.message()), color);
        } catch (CryptoException | MalformedMessageException e) {
            playPasswords.remove(connection);
            connection.disconnect(Component.translatable("trustedserver.disconnect.password_channel_verification"));
        }
    }

    private static void display(Component text, ChatFormatting color) {
        Minecraft client = Minecraft.getInstance();
        if (client.player != null) {
            client.player.displayClientMessage(
                    Component.literal("[TrustedServer] ").append(text).withStyle(color), false);
        }
    }

    /** 兼容当前 v3 协议中的服务端文本，同时在客户端按所选语言展示内置结果。 */
    private static Component passwordResultMessage(String message) {
        String key = switch (message) {
            case "此密码验证层未启用" -> "trustedserver.result.password_layer_disabled";
            case "操作过于频繁，请稍后再试" -> "trustedserver.result.too_frequent";
            case "服务器内部错误" -> "trustedserver.result.server_error";
            case "账号不存在" -> "trustedserver.result.account_missing";
            case "登录密码与找回密码不能相同" -> "trustedserver.result.passwords_must_differ";
            case "登录密码已设定" -> "trustedserver.result.login_password_set";
            case "找回密码已设定" -> "trustedserver.result.recovery_password_set";
            case "服务器繁忙，请稍后再试" -> "trustedserver.result.server_busy";
            default -> null;
        };
        if (key != null) {
            return Component.translatable(key);
        }
        Matcher min = MIN_LENGTH.matcher(message);
        if (min.matches()) {
            return Component.translatable("trustedserver.result.password_too_short", min.group(1));
        }
        Matcher max = MAX_LENGTH.matcher(message);
        if (max.matches()) {
            return Component.translatable("trustedserver.result.password_too_long", max.group(1));
        }
        return Component.literal(message);
    }

    /** 服务端配置仍可发送任意文本；仅把内置默认通知换成客户端语言。 */
    private static Component noticeMessage(String notice) {
        return switch (notice) {
            case "设定密码后解除新用户限制（使用 /passwd）" ->
                    Component.translatable("trustedserver.notice.new_player_restricted");
            case "尚未设置找回密码，可使用 /recoverypasswd 设置" ->
                    Component.translatable("trustedserver.notice.recovery_not_set");
            case "检测到新设备，已把本服务器的认证绑定更新为这台电脑" ->
                    Component.translatable("trustedserver.notice.device_rebound");
            default -> Component.literal(notice);
        };
    }

    private CompletableFuture<FriendlyByteBuf> onQuery(Channel channel, Minecraft client,
            ClientHandshakePacketListenerImpl handler, FriendlyByteBuf buf) {
        byte[] payload = new byte[buf.readableBytes()];
        buf.readBytes(payload);
        ClientAuthSession session = sessions.computeIfAbsent(handler, h -> new ClientAuthSession(
                serverAddress(client, h), client.getUser().getName(), wantTunnel, environment, random));
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
                Connection connection = connection(handler);
                try {
                    TunnelPipeline.prepareClientSwitch(connection, complete.result().handover());
                } catch (RuntimeException e) {
                    complete.result().handover().close();
                    return fail(handler, new ClientFailure(ClientFailure.Kind.INTERNAL_ERROR,
                            "cannot install tunnel: " + e.getClass().getSimpleName()));
                }
                completed.put(connection, complete.result());
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
        return switch (failure.kind()) {
            case VERSION_MISMATCH -> Component.translatable(
                    "trustedserver.disconnect.version_mismatch", failure.detail());
            case SERVER_SIGNATURE_INVALID -> Component.translatable(
                    "trustedserver.disconnect.server_signature_invalid");
            case SERVER_KEY_REJECTED -> Component.translatable(
                    "trustedserver.disconnect.server_key_rejected");
            case USER_CANCELLED -> Component.translatable("trustedserver.disconnect.user_cancelled");
            case CRYPTO_FAILURE, PROTOCOL_ERROR -> Component.translatable(
                    "trustedserver.disconnect.authentication_failed", failure.kind().name());
            case INTERNAL_ERROR -> Component.translatable("trustedserver.disconnect.local_error", failure.detail());
        };
    }
}
