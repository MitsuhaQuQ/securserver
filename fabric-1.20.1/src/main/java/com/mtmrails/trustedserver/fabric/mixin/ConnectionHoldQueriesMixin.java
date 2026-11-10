package com.mtmrails.trustedserver.fabric.mixin;

import com.mtmrails.trustedserver.core.message.Channel;
import com.mtmrails.trustedserver.fabric.MinecraftAccess;
import com.mtmrails.trustedserver.fabric.server.LoginFlow;
import com.mtmrails.trustedserver.fabric.server.TrustedServerRuntime;
import net.minecraft.network.Connection;
import net.minecraft.network.PacketListener;
import net.minecraft.network.PacketSendListener;
import net.minecraft.network.protocol.Packet;
import net.minecraft.network.protocol.login.ClientboundCustomQueryPacket;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * 认证通过之前扣下所有非本 mod 的登录 query（例如 Fabric API 的 early_registration），
 * 机器人在第一阶段门禁前只能看到 {@code trustedserver:psk}，无从判断服务器的加载器与其他 mod。
 * 见 {@link LoginFlow#holdOutgoing}。
 */
@Mixin(Connection.class)
abstract class ConnectionHoldQueriesMixin {
    private static final String OWN_NAMESPACE = Channel.AUTH.id().substring(0, Channel.AUTH.id().indexOf(':'));

    @Shadow
    public abstract PacketListener getPacketListener();

    @Inject(method = "send(Lnet/minecraft/network/protocol/Packet;Lnet/minecraft/network/PacketSendListener;)V",
            at = @At("HEAD"), cancellable = true)
    private void trustedserver$holdForeignQueries(Packet<?> packet, PacketSendListener listener, CallbackInfo ci) {
        if (!(packet instanceof ClientboundCustomQueryPacket query)
                || MinecraftAccess.loginQueryId(query).getNamespace().equals(OWN_NAMESPACE)) {
            return;
        }
        TrustedServerRuntime runtime = TrustedServerRuntime.get();
        if (runtime == null || !(getPacketListener() instanceof ServerLoginPacketListenerImpl login)) {
            return;
        }
        LoginFlow flow = runtime.loginFlow(login);
        if (flow != null && flow.holdOutgoing((Connection) (Object) this, packet, listener)) {
            ci.cancel();
        }
    }
}
