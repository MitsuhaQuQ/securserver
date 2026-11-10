package com.mtmrails.trustedserver.fabric.mixin;

import com.mtmrails.trustedserver.fabric.server.TrustedServerRuntime;
import net.minecraft.network.protocol.login.ServerboundHelloPacket;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * 收到登录 Hello 时（Mojang 验证之前）做限流与 IP 封禁检查（PROTOCOL.md 第 7 节），使所有登录连接——
 * 包括之后在 Mojang 验证处失败的——都计入限流。被拒绝时已断开，不再继续原版流程。
 */
@Mixin(ServerLoginPacketListenerImpl.class)
abstract class ServerLoginHelloMixin {
    @Shadow
    @Final
    MinecraftServer server;

    @Inject(method = "handleHello", at = @At("HEAD"), cancellable = true)
    private void trustedserver$gateHello(ServerboundHelloPacket packet, CallbackInfo ci) {
        TrustedServerRuntime runtime = TrustedServerRuntime.get();
        if (runtime != null && runtime.beginLogin((ServerLoginPacketListenerImpl) (Object) this, server) == null) {
            ci.cancel();
        }
    }

    @Inject(method = "handleHello", at = @At("TAIL"))
    private void trustedserver$rememberHelloName(ServerboundHelloPacket packet, CallbackInfo ci) {
        TrustedServerRuntime runtime = TrustedServerRuntime.get();
        if (runtime != null) {
            var flow = runtime.loginFlow((ServerLoginPacketListenerImpl) (Object) this);
            if (flow != null) {
                flow.recordHelloName(packet.name());
            }
        }
    }
}
