package com.mtmrails.trustedserver.fabric.mixin;

import com.mtmrails.trustedserver.fabric.server.TrustedServerRuntime;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.level.ServerPlayerGameMode;
import net.minecraft.world.level.GameType;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.ModifyVariable;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

@Mixin(ServerPlayerGameMode.class)
abstract class RestrictedGameModeMixin {
    @Shadow @Final protected ServerPlayer player;

    @Inject(method = "changeGameModeForPlayer", at = @At("HEAD"), cancellable = true)
    private void trustedserver$denyGameModeChange(GameType requested, CallbackInfoReturnable<Boolean> cir) {
        if (requested != GameType.SURVIVAL && trustedserver$isRestricted()) {
            cir.setReturnValue(false);
        }
    }

    /** 同样覆盖原版从存档加载模式及重生时复制模式的内部调用。 */
    @ModifyVariable(method = "setGameModeForPlayer", at = @At("HEAD"), argsOnly = true, ordinal = 0)
    private GameType trustedserver$forceSurvival(GameType requested) {
        return trustedserver$isRestricted() ? GameType.SURVIVAL : requested;
    }

    @Unique
    private boolean trustedserver$isRestricted() {
        TrustedServerRuntime runtime = TrustedServerRuntime.get();
        return runtime != null && runtime.restricted(player);
    }
}
