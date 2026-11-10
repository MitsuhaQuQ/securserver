package com.mtmrails.trustedserver.fabric.mixin;

import com.mojang.authlib.GameProfile;
import com.mtmrails.trustedserver.fabric.server.LoginFlow;
import com.mtmrails.trustedserver.fabric.server.TrustedServerRuntime;
import net.minecraft.core.UUIDUtil;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.contents.TranslatableContents;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import java.lang.reflect.Field;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** 原版 session 失败时不立即断开，而是切成离线 UUID 后进入 TrustedServer PSK 门禁。 */
@Mixin(ServerLoginPacketListenerImpl.class)
abstract class ServerLoginSessionFallbackMixin {
    @Shadow GameProfile gameProfile;

    @Unique private static volatile Field trustedserver$stateField;

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
        if (!trustedserver$setReadyToAccept(self)) return;
        gameProfile = new GameProfile(UUIDUtil.createOfflinePlayerUUID(name), name);
        ci.cancel();
    }

    /**
     * 1.20.1 的 State 是原版私有枚举，Java 源码不能在 mixin 中安全声明其类型。这里按本版本适配层
     * 唯一的七值状态枚举和 READY_TO_ACCEPT 的固定 ordinal=4 定位，避免依赖生产环境的混淆字段名。
     */
    @Unique
    private static boolean trustedserver$setReadyToAccept(ServerLoginPacketListenerImpl listener) {
        try {
            Field field = trustedserver$stateField;
            if (field == null) {
                for (Field candidate : ServerLoginPacketListenerImpl.class.getDeclaredFields()) {
                    Object[] constants = candidate.getType().getEnumConstants();
                    if (constants != null && constants.length == 7) {
                        candidate.setAccessible(true);
                        field = candidate;
                        trustedserver$stateField = candidate;
                        break;
                    }
                }
            }
            if (field == null) return false;
            Object[] constants = field.getType().getEnumConstants();
            field.set(listener, constants[4]);
            return true;
        } catch (ReflectiveOperationException | RuntimeException e) {
            return false;
        }
    }
}
