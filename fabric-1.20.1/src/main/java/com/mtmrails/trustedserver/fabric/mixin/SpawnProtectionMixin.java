package com.mtmrails.trustedserver.fabric.mixin;

import com.mojang.authlib.GameProfile;
import com.mtmrails.trustedserver.fabric.server.TrustedServerRuntime;
import net.minecraft.server.dedicated.DedicatedPlayerList;
import net.minecraft.server.dedicated.DedicatedServer;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

@Mixin(DedicatedServer.class)
abstract class SpawnProtectionMixin {
    @Redirect(method = "isUnderSpawnProtection", at = @At(value = "INVOKE",
            target = "Lnet/minecraft/server/dedicated/DedicatedPlayerList;isOp(Lcom/mojang/authlib/GameProfile;)Z"))
    private boolean trustedserver$enforceSpawnProtection(DedicatedPlayerList list, GameProfile profile) {
        TrustedServerRuntime runtime = TrustedServerRuntime.get();
        return (runtime == null || !runtime.opSuspended(profile.getId())) && list.isOp(profile);
    }
}
