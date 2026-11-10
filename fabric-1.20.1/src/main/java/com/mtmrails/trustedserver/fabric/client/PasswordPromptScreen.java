package com.mtmrails.trustedserver.fabric.client;

import com.mtmrails.trustedserver.core.message.PasswordRequest;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import net.minecraft.Util;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.Style;
import net.minecraft.util.FormattedCharSequence;

/** 正式认证密码通道的登录 / 找回 / 首次设定界面。 */
final class PasswordPromptScreen extends Screen {
    private final Screen parent;
    private final PasswordRequest request;
    private final CompletableFuture<Optional<String>> result;
    private final long deadlineMillis;
    private EditBox password;
    private EditBox confirm;
    private Component error;
    private boolean completed;

    PasswordPromptScreen(Screen parent, PasswordRequest request,
            CompletableFuture<Optional<String>> result) {
        super(Component.literal(titleFor(request.kind())));
        this.parent = parent;
        this.request = request;
        this.result = result;
        this.deadlineMillis = Util.getMillis() + request.timeoutSec() * 1000L;
    }

    @Override
    protected void init() {
        int center = width / 2;
        int firstY = hasConfirmation() ? height / 2 - 34 : height / 2 - 20;
        password = new EditBox(font, center - 150, firstY, 300, 20, Component.literal("密码"));
        password.setMaxLength(256);
        mask(password);
        addRenderableWidget(password);
        if (hasConfirmation()) {
            confirm = new EditBox(font, center - 150, firstY + 28, 300, 20, Component.literal("确认密码"));
            confirm.setMaxLength(256);
            mask(confirm);
            addRenderableWidget(confirm);
        }

        int buttonY = height / 2 + 42;
        addRenderableWidget(Button.builder(Component.literal(submitLabel(request.kind())), b -> submit())
                .bounds(center - 150, buttonY, 95, 20).build());
        if (hasConfirmation()) {
            String alternate = request.kind() == PasswordRequest.Kind.SET ? "跳过" : "清除密码";
            addRenderableWidget(Button.builder(Component.literal(alternate), b -> finish(Optional.of(""), true))
                    .bounds(center - 48, buttonY, 95, 20).build());
        }
        addRenderableWidget(Button.builder(Component.literal("取消"), b -> onClose())
                .bounds(hasConfirmation() ? center + 54 : center + 5,
                        buttonY, 95, 20).build());
        setInitialFocus(password);
    }

    private static void mask(EditBox box) {
        box.setFormatter((text, offset) ->
                FormattedCharSequence.forward("•".repeat(text.length()), Style.EMPTY));
    }

    private void submit() {
        String secret = password.getValue();
        if (secret.isEmpty()) {
            error = Component.literal("密码不能为空");
            return;
        }
        if (hasConfirmation() && !secret.equals(confirm.getValue())) {
            error = Component.literal("两次输入的密码不一致");
            return;
        }
        finish(Optional.of(secret), true);
    }

    private void finish(Optional<String> value, boolean restoreParent) {
        if (completed) return;
        completed = true;
        result.complete(value);
        if (password != null) password.setValue("");
        if (confirm != null) confirm.setValue("");
        if (restoreParent && minecraft.screen == this) minecraft.setScreen(parent);
    }

    @Override
    public void tick() {
        if (Util.getMillis() >= deadlineMillis) {
            error = Component.literal("输入已超时");
            finish(Optional.empty(), true);
        }
    }

    @Override
    public boolean keyPressed(int keyCode, int scanCode, int modifiers) {
        if (keyCode == 257 || keyCode == 335) {
            submit();
            return true;
        }
        return super.keyPressed(keyCode, scanCode, modifiers);
    }

    @Override
    public void onClose() {
        finish(Optional.empty(), true);
    }

    @Override
    public void removed() {
        // 网络断开或其他界面替换本界面时，不能让登录 query 的 future 永久悬挂。
        finish(Optional.empty(), false);
        super.removed();
    }

    @Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        renderBackground(graphics);
        int remaining = (int) Math.max(0, (deadlineMillis - Util.getMillis() + 999) / 1000);
        graphics.drawCenteredString(font, title, width / 2, height / 2 - 88, 0xFFFFFF);
        graphics.drawCenteredString(font, Component.literal(descriptionFor(request.kind())),
                width / 2, height / 2 - 68, 0xA0A0A0);
        if (!hasConfirmation()) {
            graphics.drawCenteredString(font,
                    Component.literal("剩余尝试次数：" + request.attemptsLeft()),
                    width / 2, height / 2 - 50, 0xFFFF55);
        }
        graphics.drawString(font, "剩余时间：" + remaining + " 秒", width / 2 - 150,
                hasConfirmation() ? height / 2 - 50 : height / 2 - 36, 0xA0A0A0);
        if (error != null) graphics.drawCenteredString(font, error, width / 2, height / 2 + 20, 0xFF5555);
        super.render(graphics, mouseX, mouseY, partialTick);
    }

    private static String titleFor(PasswordRequest.Kind kind) {
        return switch (kind) {
            case LOGIN -> "TrustedServer 登录密码";
            case RECOVERY -> "TrustedServer 找回认证";
            case SET -> "设置 TrustedServer 登录密码";
            case RESET -> "重设 TrustedServer 登录密码";
        };
    }

    private static String descriptionFor(PasswordRequest.Kind kind) {
        return switch (kind) {
            case LOGIN -> "输入此服务器账号的登录密码";
            case RECOVERY -> "设备密钥不匹配；输入找回密码以重新绑定这台设备";
            case SET -> "新账号可现在设置密码，也可以跳过";
            case RESET -> "设置新密码，或明确选择清除登录密码";
        };
    }

    private static String submitLabel(PasswordRequest.Kind kind) {
        return switch (kind) {
            case LOGIN -> "登录";
            case RECOVERY -> "找回并改绑";
            case SET -> "设置密码";
            case RESET -> "重设密码";
        };
    }

    private boolean hasConfirmation() {
        return request.kind() == PasswordRequest.Kind.SET || request.kind() == PasswordRequest.Kind.RESET;
    }
}
