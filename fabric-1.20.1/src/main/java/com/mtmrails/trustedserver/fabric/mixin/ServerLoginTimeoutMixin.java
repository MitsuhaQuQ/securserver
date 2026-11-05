package com.mtmrails.trustedserver.fabric.mixin;

import com.mtmrails.trustedserver.fabric.server.TrustedServerRuntime;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.Constant;
import org.spongepowered.asm.mixin.injection.ModifyConstant;

/** 把原版 600 tick 的登录超时放宽到不短于认证总超时（PROTOCOL.md 第 7 节）；真正的超时由我们计时。 */
@Mixin(ServerLoginPacketListenerImpl.class)
abstract class ServerLoginTimeoutMixin {
    @ModifyConstant(method = "tick", constant = @Constant(intValue = 600))
    private int trustedserver$extendLoginTimeout(int original) {
        TrustedServerRuntime runtime = TrustedServerRuntime.get();
        return runtime == null ? original : Math.max(original, runtime.loginTimeoutTicks());
    }
}
