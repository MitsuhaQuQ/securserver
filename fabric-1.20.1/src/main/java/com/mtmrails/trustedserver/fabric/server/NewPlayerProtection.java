package com.mtmrails.trustedserver.fabric.server;

import com.mtmrails.trustedserver.fabric.TrustedServerFabric;
import com.mtmrails.trustedserver.server.policy.NewPlayerGuard;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerTickEvents;
import net.fabricmc.fabric.api.event.player.PlayerBlockBreakEvents;
import net.minecraft.Util;
import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.stats.Stats;

final class NewPlayerProtection {
    private NewPlayerProtection() {
    }

    static void register(NewPlayerGuard.Config config) {
        if (!config.enabled()) {
            return;
        }
        NewPlayerGuard guard = new NewPlayerGuard(config);
        PlayerBlockBreakEvents.BEFORE.register((world, player, pos, state, blockEntity) -> {
            if (!(player instanceof ServerPlayer serverPlayer) || serverPlayer.hasPermissions(2)) {
                return true;
            }
            int playTicks = serverPlayer.getStats().getValue(Stats.CUSTOM.get(Stats.PLAY_TIME));
            NewPlayerGuard.Verdict verdict = guard.beforeBreak(player.getUUID(), playTicks, Util.getMillis());
            if (verdict == NewPlayerGuard.Verdict.START_COOLDOWN) {
                player.sendSystemMessage(Component.translatable("trustedserver.guard.block_break_cooldown",
                        config.cooldownSeconds()));
                TrustedServerFabric.LOGGER.info("New player block-break cooldown for {} at {} ({} seconds)",
                        player.getUUID(), pos, config.cooldownSeconds());
            }
            return verdict == NewPlayerGuard.Verdict.ALLOW;
        });
        ServerTickEvents.END_SERVER_TICK.register(server -> {
            if (server.getTickCount() % 200 == 0) {
                guard.prune(Util.getMillis());
            }
        });
    }
}
