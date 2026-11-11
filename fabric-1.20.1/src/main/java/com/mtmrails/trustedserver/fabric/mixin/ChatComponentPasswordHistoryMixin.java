package com.mtmrails.trustedserver.fabric.mixin;

import com.mtmrails.trustedserver.client.PasswordCommand;
import net.minecraft.client.gui.components.ChatComponent;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

@Mixin(ChatComponent.class)
public abstract class ChatComponentPasswordHistoryMixin {
    /** 原版在发送事件之前记录输入，因此须在历史记录入口拦截密码命令。 */
    @Inject(method = "addRecentChat", at = @At("HEAD"), cancellable = true)
    private void trustedserver$skipPasswordHistory(String input, CallbackInfo ci) {
        // Fabric 客户端命令 API 写入历史时不带开头的“/”，原版聊天界面路径则可能带上。
        String commandLine = input.startsWith("/") ? input : "/" + input;
        if (!(PasswordCommand.parse(commandLine) instanceof PasswordCommand.NotOurs)) {
            ci.cancel();
        }
    }
}
