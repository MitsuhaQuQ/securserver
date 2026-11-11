package com.mtmrails.trustedserver.fabric.client;

import java.util.Optional;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.Style;
import net.minecraft.util.FormattedCharSequence;

/** 登录期间缺少服务器 PSK 时显示的本地输入框。 */
final class PskPromptScreen extends Screen {
    @FunctionalInterface
    interface Submitter {
        Optional<Component> submit(String encoded);
    }

    private final Screen parent;
    private final String address;
    private final Submitter submitter;
    private final Runnable cancelled;
    private EditBox input;
    private Component error;
    private boolean finished;

    PskPromptScreen(Screen parent, String address, Submitter submitter, Runnable cancelled) {
        super(Component.translatable("trustedserver.psk.title"));
        this.parent = parent;
        this.address = address;
        this.submitter = submitter;
        this.cancelled = cancelled;
    }

    @Override
    protected void init() {
        int center = width / 2;
        input = new EditBox(font, center - 150, height / 2 - 10, 300, 20,
                Component.translatable("trustedserver.psk.field"));
        input.setMaxLength(128);
        input.setFormatter((text, offset) -> FormattedCharSequence.forward("•".repeat(text.length()), Style.EMPTY));
        addRenderableWidget(input);
        addRenderableWidget(Button.builder(Component.translatable("trustedserver.button.save_and_connect"), button -> submit())
                .bounds(center - 150, height / 2 + 24, 145, 20).build());
        addRenderableWidget(Button.builder(Component.translatable("gui.cancel"), button -> onClose())
                .bounds(center + 5, height / 2 + 24, 145, 20).build());
        setInitialFocus(input);
    }

    private void submit() {
        Optional<Component> result = submitter.submit(input.getValue().trim());
        if (result.isPresent()) {
            error = result.orElseThrow();
            return;
        }
        finished = true;
        minecraft.setScreen(parent);
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
        if (!finished) {
            finished = true;
            cancelled.run();
        }
        minecraft.setScreen(parent);
    }

    @Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        graphics.fill(0, 0, width, height, 0xC0101010);
        graphics.drawCenteredString(font, title, width / 2, height / 2 - 72, 0xFFFFFF);
        graphics.drawCenteredString(font, Component.translatable("trustedserver.psk.server", address), width / 2,
                height / 2 - 52, 0xA0A0A0);
        graphics.drawCenteredString(font, Component.translatable("trustedserver.psk.description"), width / 2,
                height / 2 - 34, 0xFFFFFF);
        if (error != null) {
            graphics.drawCenteredString(font, error, width / 2, height / 2 + 52, 0xFF5555);
        }
        super.render(graphics, mouseX, mouseY, partialTick);
    }

    @Override
    public boolean isPauseScreen() {
        return false;
    }
}
