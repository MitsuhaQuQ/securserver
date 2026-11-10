package com.mtmrails.trustedserver.fabric.mixin;

import com.mtmrails.trustedserver.fabric.server.TrustedServerRuntime;
import net.minecraft.network.Connection;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.players.PlayerList;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

@Mixin(PlayerList.class)
abstract class PlayerListPlayAccessMixin {
    @Inject(method = "placeNewPlayer", at = @At("HEAD"), cancellable = true)
    private void trustedserver$beginPlay(Connection connection, ServerPlayer player, CallbackInfo ci) {
        TrustedServerRuntime runtime = TrustedServerRuntime.get();
        if (runtime != null && !runtime.beginPlay(connection, player)) {
            ci.cancel();
        }
    }
}
