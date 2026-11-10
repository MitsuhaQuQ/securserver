package com.mtmrails.trustedserver.fabric.mixin;

import com.mojang.authlib.GameProfile;
import com.mtmrails.trustedserver.fabric.MinecraftAccess;
import com.mtmrails.trustedserver.fabric.server.LoginFlow;
import com.mtmrails.trustedserver.fabric.server.TrustedServerRuntime;
import net.minecraft.core.UUIDUtil;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.contents.TranslatableContents;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** 原版 session 失败时不立即断开，而是切成离线 UUID 后进入 TrustedServer PSK 门禁。 */
@Mixin(ServerLoginPacketListenerImpl.class)
abstract class ServerLoginSessionFallbackMixin {
    @Inject(method = "disconnect", at = @At("HEAD"), cancellable = true)
    private void trustedserver$offlineFallback(Component reason, CallbackInfo ci) {
        if (!(reason.getContents() instanceof TranslatableContents translated)
                || !(translated.getKey().equals("multiplayer.disconnect.unverified_username")
                || translated.getKey().equals("multiplayer.disconnect.authservers_down"))) {
            return;
        }
        TrustedServerRuntime runtime = TrustedServerRuntime.get();
        LoginFlow flow = runtime == null ? null
                : runtime.loginFlow((ServerLoginPacketListenerImpl) (Object) this);
        String name = flow == null ? null : flow.beginOfflineFallback();
        if (name == null) return;
        ServerLoginPacketListenerImpl self = (ServerLoginPacketListenerImpl) (Object) this;
        GameProfile offline = new GameProfile(UUIDUtil.createOfflinePlayerUUID(name), name);
        if (!MinecraftAccess.resumeOfflineLogin(self, offline)) return;
        ci.cancel();
    }
}
