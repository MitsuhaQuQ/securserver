package com.mtmrails.trustedserver.fabric.mixin;

import com.mojang.authlib.GameProfile;
import com.mtmrails.trustedserver.fabric.server.TrustedServerRuntime;
import net.minecraft.server.MinecraftServer;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

@Mixin(MinecraftServer.class)
abstract class ServerPermissionMixin {
    @Inject(method = "getProfilePermissions", at = @At("HEAD"), cancellable = true)
    private void trustedserver$maskOpLevel(GameProfile profile, CallbackInfoReturnable<Integer> cir) {
        TrustedServerRuntime runtime = TrustedServerRuntime.get();
        if (runtime != null && runtime.opSuspended(profile.getId())) {
            cir.setReturnValue(0);
        }
    }
}
