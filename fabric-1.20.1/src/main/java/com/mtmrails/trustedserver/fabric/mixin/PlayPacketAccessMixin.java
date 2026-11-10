package com.mtmrails.trustedserver.fabric.mixin;

import com.mojang.authlib.GameProfile;
import com.mojang.brigadier.suggestion.Suggestions;
import com.mtmrails.trustedserver.fabric.server.TrustedServerRuntime;
import net.minecraft.network.protocol.game.ClientboundCommandSuggestionsPacket;
import net.minecraft.network.protocol.game.ServerboundCommandSuggestionPacket;
import net.minecraft.network.protocol.game.ServerboundChatCommandPacket;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ServerGamePacketListenerImpl;
import net.minecraft.server.players.PlayerList;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.Redirect;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

@Mixin(ServerGamePacketListenerImpl.class)
abstract class PlayPacketAccessMixin {
    @Shadow public ServerPlayer player;

    @Inject(method = "handleChatCommand", at = @At("HEAD"), cancellable = true)
    private void trustedserver$discardDisconnectedCommand(ServerboundChatCommandPacket packet, CallbackInfo ci) {
        if (TrustedServerRuntime.get() != null && !player.connection.isAcceptingMessages()) {
            ci.cancel();
        }
    }

    @Inject(method = "handleCustomCommandSuggestions", at = @At("HEAD"), cancellable = true)
    private void trustedserver$hideCommandSuggestions(ServerboundCommandSuggestionPacket packet, CallbackInfo ci) {
        TrustedServerRuntime runtime = TrustedServerRuntime.get();
        if (runtime != null && runtime.restricted(player)) {
            player.connection.send(new ClientboundCommandSuggestionsPacket(packet.getId(), Suggestions.empty().join()));
            ci.cancel();
        }
    }

    @Redirect(method = "detectRateSpam", at = @At(value = "INVOKE",
            target = "Lnet/minecraft/server/players/PlayerList;isOp(Lcom/mojang/authlib/GameProfile;)Z"))
    private boolean trustedserver$applySpamLimit(PlayerList list, GameProfile profile) {
        TrustedServerRuntime runtime = TrustedServerRuntime.get();
        return (runtime == null || !runtime.opSuspended(profile.getId())) && list.isOp(profile);
    }
}
