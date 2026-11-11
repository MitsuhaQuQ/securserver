package com.mtmrails.trustedserver.fabric.client;

import com.mtmrails.trustedserver.core.message.PasswordRequest;
import com.mtmrails.trustedserver.core.message.PasswordAnswer;
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
    private final CompletableFuture<Optional<PasswordAnswer>> result;
    private final long deadlineMillis;
    private EditBox password;
    private EditBox confirm;
    private Component error;
    private boolean confirmingClear;
    private boolean completed;

    PasswordPromptScreen(Screen parent, PasswordRequest request,
            CompletableFuture<Optional<PasswordAnswer>> result) {
        super(titleFor(request.kind()));
        this.parent = parent;
        this.request = request;
        this.result = result;
        this.deadlineMillis = Util.getMillis() + request.timeoutSec() * 1000L;
    }

    @Override
    protected void init() {
        int center = width / 2;
        if (confirmingClear) {
            int buttonY = height / 2 + 42;
            addRenderableWidget(Button.builder(Component.translatable("trustedserver.button.confirm_clear"),
                    b -> finish(Optional.of(PasswordAnswer.clear()), true))
                    .bounds(center - 105, buttonY, 100, 20).build());
            addRenderableWidget(Button.builder(Component.translatable("gui.back"), b -> showClearConfirmation(false))
                    .bounds(center + 5, buttonY, 100, 20).build());
            return;
        }
        int firstY = hasConfirmation() ? height / 2 - 34 : height / 2 - 20;
        password = new EditBox(font, center - 150, firstY, 300, 20,
                Component.translatable("trustedserver.field.password"));
        password.setMaxLength(256);
        mask(password);
        addRenderableWidget(password);
        if (hasConfirmation()) {
            confirm = new EditBox(font, center - 150, firstY + 28, 300, 20,
                    Component.translatable("trustedserver.field.confirm_password"));
            confirm.setMaxLength(256);
            mask(confirm);
            addRenderableWidget(confirm);
        }

        int buttonY = height / 2 + 42;
        addRenderableWidget(Button.builder(submitLabel(request.kind()), b -> submit())
                .bounds(center - 150, buttonY, 95, 20).build());
        if (hasConfirmation()) {
            Component alternate = request.kind() == PasswordRequest.Kind.SET
                    ? Component.translatable("trustedserver.button.skip")
                    : Component.translatable("trustedserver.button.clear_password");
            addRenderableWidget(Button.builder(alternate, b -> alternateAction())
                    .bounds(center - 48, buttonY, 95, 20).build());
        } else if (request.kind() == PasswordRequest.Kind.LOGIN
                || request.kind() == PasswordRequest.Kind.RECOVERY) {
            Component alternate = request.kind() == PasswordRequest.Kind.LOGIN
                    ? Component.translatable("trustedserver.button.forgot_password")
                    : Component.translatable("trustedserver.button.verify_and_reset");
            addRenderableWidget(Button.builder(alternate, b -> requestReset())
                    .bounds(center - 48, buttonY, 95, 20).build());
        }
        addRenderableWidget(Button.builder(Component.translatable("gui.cancel"), b -> onClose())
                .bounds(center + 54,
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
            error = Component.translatable("trustedserver.error.password_empty");
            return;
        }
        if (hasConfirmation() && !secret.equals(confirm.getValue())) {
            error = Component.translatable("trustedserver.error.password_mismatch");
            return;
        }
        finish(Optional.of(new PasswordAnswer(secret)), true);
    }

    private void alternateAction() {
        if (request.kind() == PasswordRequest.Kind.SET) {
            finish(Optional.of(new PasswordAnswer("")), true);
        } else {
            showClearConfirmation(true);
        }
    }

    private void showClearConfirmation(boolean showing) {
        password.setValue("");
        confirm.setValue("");
        confirmingClear = showing;
        error = null;
        clearWidgets();
        init();
    }

    private void requestReset() {
        String secret = request.kind() == PasswordRequest.Kind.RECOVERY ? password.getValue() : "";
        if (request.kind() == PasswordRequest.Kind.RECOVERY && secret.isEmpty()) {
            error = Component.translatable("trustedserver.error.recovery_password_empty");
            return;
        }
        finish(Optional.of(new PasswordAnswer(PasswordAnswer.Action.REQUEST_RESET, secret)), true);
    }

    private void finish(Optional<PasswordAnswer> value, boolean restoreParent) {
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
            error = Component.translatable("trustedserver.error.input_timeout");
            finish(Optional.empty(), true);
        }
    }

    @Override
    public boolean keyPressed(int keyCode, int scanCode, int modifiers) {
        if (!confirmingClear && (keyCode == 257 || keyCode == 335)) {
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
        graphics.fill(0, 0, width, height, 0xC0101010);
        int remaining = (int) Math.max(0, (deadlineMillis - Util.getMillis() + 999) / 1000);
        graphics.drawCenteredString(font, title, width / 2, height / 2 - 88, 0xFFFFFF);
        Component description = confirmingClear
                ? Component.translatable("trustedserver.password.description.confirm_clear")
                : descriptionFor(request.kind());
        graphics.drawCenteredString(font, description,
                width / 2, height / 2 - 68, 0xA0A0A0);
        if (!hasConfirmation()) {
            graphics.drawCenteredString(font,
                    Component.translatable("trustedserver.password.attempts_left", request.attemptsLeft()),
                    width / 2, height / 2 - 50, 0xFFFF55);
        }
        graphics.drawString(font, Component.translatable("trustedserver.password.time_left", remaining), width / 2 - 150,
                hasConfirmation() ? height / 2 - 50 : height / 2 - 36, 0xA0A0A0);
        if (error != null) graphics.drawCenteredString(font, error, width / 2, height / 2 + 20, 0xFF5555);
        super.render(graphics, mouseX, mouseY, partialTick);
    }

    private static Component titleFor(PasswordRequest.Kind kind) {
        return switch (kind) {
            case LOGIN -> Component.translatable("trustedserver.password.title.login");
            case RECOVERY -> Component.translatable("trustedserver.password.title.recovery");
            case SET -> Component.translatable("trustedserver.password.title.set");
            case RESET -> Component.translatable("trustedserver.password.title.reset");
        };
    }

    private static Component descriptionFor(PasswordRequest.Kind kind) {
        return switch (kind) {
            case LOGIN -> Component.translatable("trustedserver.password.description.login");
            case RECOVERY -> Component.translatable("trustedserver.password.description.recovery");
            case SET -> Component.translatable("trustedserver.password.description.set");
            case RESET -> Component.translatable("trustedserver.password.description.reset");
        };
    }

    private static Component submitLabel(PasswordRequest.Kind kind) {
        return switch (kind) {
            case LOGIN -> Component.translatable("trustedserver.button.login");
            case RECOVERY -> Component.translatable("trustedserver.button.keep_password");
            case SET -> Component.translatable("trustedserver.button.set_password");
            case RESET -> Component.translatable("trustedserver.button.reset_password");
        };
    }

    private boolean hasConfirmation() {
        return request.kind() == PasswordRequest.Kind.SET || request.kind() == PasswordRequest.Kind.RESET;
    }
}
