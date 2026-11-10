package com.mtmrails.trustedserver.fabric.server;

import com.mojang.brigadier.CommandDispatcher;
import com.mojang.brigadier.arguments.StringArgumentType;
import com.mojang.brigadier.context.CommandContext;
import com.mtmrails.trustedserver.server.account.AdminResult;
import com.mtmrails.trustedserver.server.account.AccountService;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiFunction;
import java.io.IOException;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;
import net.minecraft.network.chat.Component;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;

/**
 * 控制台管理员命令（PROTOCOL.md 第 6 节）。只允许控制台使用：来源不能是实体，且须有最高权限等级。
 *
 * <pre>
 * trustedserver fingerprint
 * trustedserver reset key &lt;玩家&gt;
 * trustedserver reset password|all &lt;玩家&gt;
 * trustedserver trust &lt;玩家&gt;
 * </pre>
 */
final class AdminCommands {
    private enum OnSuccess { KEEP_SESSION, RECONNECT, LIFT_RESTRICTION }

    private AdminCommands() {
    }

    static void register(CommandDispatcher<CommandSourceStack> dispatcher) {
        dispatcher.register(Commands.literal("trustedserver")
                .requires(source -> source.getEntity() == null && source.hasPermission(4))
                .then(Commands.literal("fingerprint").executes(ctx -> {
                    TrustedServerRuntime runtime = TrustedServerRuntime.get();
                    ctx.getSource().sendSuccess(() -> Component.literal("Server identity fingerprint: "
                            + (runtime == null ? "unavailable" : runtime.fingerprint())), false);
                    return 1;
                }))
                .then(Commands.literal("clear-online-claim")
                        .then(Commands.argument("player", StringArgumentType.word()).executes(ctx -> {
                            TrustedServerRuntime runtime = TrustedServerRuntime.get();
                            String player = StringArgumentType.getString(ctx, "player");
                            if (runtime == null) {
                                ctx.getSource().sendFailure(Component.literal("TrustedServer is not active"));
                                return 0;
                            }
                            try {
                                if (!runtime.onlineTokens().clearClaim(player)) {
                                    ctx.getSource().sendFailure(Component.literal("No online claim for " + player));
                                    return 0;
                                }
                                ctx.getSource().sendSuccess(() -> Component.literal(
                                        "Cleared online claim and tokens for " + player), true);
                                return 1;
                            } catch (IOException e) {
                                ctx.getSource().sendFailure(Component.literal("clear online claim failed"));
                                return 0;
                            }
                        })))
                .then(Commands.literal("reset")
                        .then(Commands.literal("key").then(Commands.argument("player", StringArgumentType.word())
                                .executes(ctx -> run(ctx, "reset key", AccountService::resetKey, OnSuccess.KEEP_SESSION))))
                        .then(Commands.literal("password").then(Commands.argument("player", StringArgumentType.word())
                                .executes(ctx -> run(ctx, "reset password", AccountService::resetPassword,
                                        OnSuccess.RECONNECT))))
                        .then(Commands.literal("all").then(Commands.argument("player", StringArgumentType.word())
                                .executes(ctx -> run(ctx, "reset all", AccountService::resetAll, OnSuccess.RECONNECT)))))
                .then(Commands.literal("trust").then(Commands.argument("player", StringArgumentType.word())
                        .executes(ctx -> run(ctx, "trust", AccountService::trust, OnSuccess.LIFT_RESTRICTION)))));
    }

    private static int run(CommandContext<CommandSourceStack> ctx, String action,
            BiFunction<AccountService, String, CompletableFuture<AdminResult>> operation, OnSuccess onSuccess) {
        TrustedServerRuntime runtime = TrustedServerRuntime.get();
        CommandSourceStack source = ctx.getSource();
        if (runtime == null) {
            source.sendFailure(Component.literal("TrustedServer is not active"));
            return 0;
        }
        String player = StringArgumentType.getString(ctx, "player");
        MinecraftServer server = source.getServer();
        String accountId = accountId(runtime, server, player);
        operation.apply(runtime.accounts(), accountId).whenComplete((result, error) -> server.execute(() -> {
            if (error != null) {
                source.sendFailure(Component.literal(action + " failed: " + error.getMessage()));
            } else if (result == AdminResult.NO_SUCH_ACCOUNT) {
                source.sendFailure(Component.literal("No TrustedServer account for " + player));
            } else {
                if (onSuccess == OnSuccess.RECONNECT) {
                    runtime.disconnectResetAccount(server, accountId);
                } else if (onSuccess == OnSuccess.LIFT_RESTRICTION) {
                    runtime.trustOnlinePlayer(server, accountId);
                }
                source.sendSuccess(() -> Component.literal(action + " done for " + player), true);
            }
        }));
        return 1;
    }

    /** 正版服务器上按 UUID 或名字（经本地玩家缓存）解析；离线服务器用小写名字。 */
    private static String accountId(TrustedServerRuntime runtime, MinecraftServer server, String player) {
        ServerPlayer online = server.getPlayerList().getPlayerByName(player);
        if (online != null) {
            String accountId = runtime.playAccountId(online);
            if (accountId != null) {
                return accountId;
            }
        }
        if (!server.usesAuthentication()) {
            return player.toLowerCase(Locale.ROOT);
        }
        try {
            return UUID.fromString(player).toString();
        } catch (IllegalArgumentException notUuid) {
            Optional<UUID> id = server.getProfileCache() == null ? Optional.empty()
                    : server.getProfileCache().get(player).map(p -> p.getId());
            return id.map(UUID::toString).orElse(player.toLowerCase(Locale.ROOT));
        }
    }
}
