package com.mtmrails.trustedserver.fabric.mixin;

import net.minecraft.client.multiplayer.ClientHandshakePacketListenerImpl;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.network.Connection;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

/** 读取客户端登录处理器的私有字段：连接，以及玩家连接时选择的服务器（可能为 null）。 */
@Mixin(ClientHandshakePacketListenerImpl.class)
public interface ClientHandshakePacketListenerAccessor {
    @Accessor("connection")
    Connection trustedserver$connection();

    @Accessor("serverData")
    ServerData trustedserver$serverData();
}
