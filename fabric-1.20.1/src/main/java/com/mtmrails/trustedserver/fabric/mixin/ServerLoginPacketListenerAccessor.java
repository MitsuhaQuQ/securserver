package com.mtmrails.trustedserver.fabric.mixin;

import com.mojang.authlib.GameProfile;
import net.minecraft.network.Connection;
import net.minecraft.server.network.ServerLoginPacketListenerImpl;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

/** 读取登录处理器的包内字段。 */
@Mixin(ServerLoginPacketListenerImpl.class)
public interface ServerLoginPacketListenerAccessor {
    @Accessor("connection")
    Connection trustedserver$connection();

    @Accessor("gameProfile")
    GameProfile trustedserver$gameProfile();
}
