package com.mtmrails.trustedserver.fabric.mixin;

import com.mtmrails.trustedserver.fabric.server.TrustedServerRuntime;
import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.LegacyQueryHandler;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

/**
 * 旧版（1.6 及以前格式）服务器列表 Ping：人数按配置显示；只在真正回复旧版 Ping 时限流。
 * 每个新连接的第一次读取都会经过本处理器，因此不能在入口处计数，否则会误耗正常登录连接的额度。
 */
@Mixin(LegacyQueryHandler.class)
abstract class LegacyQueryHandlerMixin {
    @Shadow
    private void sendFlushAndClose(ChannelHandlerContext ctx, ByteBuf buf) {
    }

    @Redirect(method = "channelRead", at = @At(value = "INVOKE",
            target = "Lnet/minecraft/server/MinecraftServer;getPlayerCount()I"))
    private int trustedserver$playerCount(MinecraftServer server) {
        TrustedServerRuntime runtime = TrustedServerRuntime.get();
        return runtime == null ? server.getPlayerCount()
                : runtime.displayedPlayerCount(server.getPlayerCount(), server.getMaxPlayers());
    }

    @Redirect(method = "channelRead", at = @At(value = "INVOKE",
            target = "Lnet/minecraft/server/network/LegacyQueryHandler;sendFlushAndClose(Lio/netty/channel/ChannelHandlerContext;Lio/netty/buffer/ByteBuf;)V"))
    private void trustedserver$rateLimit(LegacyQueryHandler self, ChannelHandlerContext ctx, ByteBuf buf) {
        TrustedServerRuntime runtime = TrustedServerRuntime.get();
        if (runtime != null && (runtime.legacyPingDisabled()
                || !runtime.allowPing(ctx.channel().remoteAddress()))) {
            buf.release();
            ctx.close();
            return;
        }
        sendFlushAndClose(ctx, buf);
    }
}
