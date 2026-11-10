package com.mtmrails.trustedserver.fabric.mixin;

import com.mtmrails.trustedserver.fabric.server.TrustedServerRuntime;
import net.minecraft.network.Connection;
import net.minecraft.network.chat.Component;
import net.minecraft.network.protocol.status.ServerStatus;
import net.minecraft.network.protocol.status.ServerboundStatusRequestPacket;
import net.minecraft.server.network.ServerStatusPacketListenerImpl;
import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.ModifyArg;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** 服务器列表 Ping：限流（超出时直接断开不回应），清空玩家样本，人数按配置（PROTOCOL.md 第 8 节）。 */
@Mixin(ServerStatusPacketListenerImpl.class)
abstract class ServerStatusPacketListenerMixin {
    @Shadow
    @Final
    private Connection connection;

    @Inject(method = "handleStatusRequest", at = @At("HEAD"), cancellable = true)
    private void trustedserver$rateLimit(ServerboundStatusRequestPacket packet, CallbackInfo ci) {
        TrustedServerRuntime runtime = TrustedServerRuntime.get();
        if (runtime != null && (runtime.statusPingDisabled()
                || !runtime.allowPing(connection.getRemoteAddress()))) {
            connection.disconnect(Component.empty());
            ci.cancel();
        }
    }

    @ModifyArg(method = "handleStatusRequest", at = @At(value = "INVOKE",
            target = "Lnet/minecraft/network/protocol/status/ClientboundStatusResponsePacket;<init>(Lnet/minecraft/network/protocol/status/ServerStatus;)V"))
    private ServerStatus trustedserver$sanitize(ServerStatus status) {
        TrustedServerRuntime runtime = TrustedServerRuntime.get();
        return runtime == null ? status : runtime.sanitize(status);
    }
}
