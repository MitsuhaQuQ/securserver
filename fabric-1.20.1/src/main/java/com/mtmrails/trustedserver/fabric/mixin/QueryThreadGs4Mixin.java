package com.mtmrails.trustedserver.fabric.mixin;

import com.mtmrails.trustedserver.fabric.TrustedServerFabric;
import com.mtmrails.trustedserver.fabric.server.TrustedServerRuntime;
import net.minecraft.server.ServerInterface;
import net.minecraft.server.rcon.thread.QueryThreadGs4;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

/** 强制关闭 GameSpy4 query 协议：它会公开在线玩家名单（PROTOCOL.md 第 8 节）。原版本就处理 create 返回 null 的情况。 */
@Mixin(QueryThreadGs4.class)
abstract class QueryThreadGs4Mixin {
    @Inject(method = "create", at = @At("HEAD"), cancellable = true)
    private static void trustedserver$disableQuery(ServerInterface server, CallbackInfoReturnable<QueryThreadGs4> cir) {
        if (TrustedServerRuntime.get() != null) {
            TrustedServerFabric.LOGGER.warn("enable-query is set in server.properties; TrustedServer keeps the query "
                    + "protocol disabled because it exposes the player list");
            cir.setReturnValue(null);
        }
    }
}
