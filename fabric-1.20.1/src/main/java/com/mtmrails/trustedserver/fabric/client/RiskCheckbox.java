package com.mtmrails.trustedserver.fabric.client;

import java.util.function.Consumer;
import net.minecraft.client.gui.Font;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.AbstractButton;
import net.minecraft.client.gui.narration.NarrationElementOutput;
import net.minecraft.network.chat.Component;

/** 不依赖原版 Checkbox 构造器的跨版本复选框。 */
final class RiskCheckbox extends AbstractButton {
    private static final int BOX_SIZE = 16;

    private final Font font;
    private final Consumer<Boolean> onChange;
    private boolean selected;

    RiskCheckbox(int x, int y, int width, Component message, Font font, boolean selected,
            Consumer<Boolean> onChange) {
        super(x, y, width, 20, message);
        this.font = font;
        this.selected = selected;
        this.onChange = onChange;
    }

    @Override
    public void onPress() {
        selected = !selected;
        onChange.accept(selected);
    }

    @Override
    protected void renderWidget(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        int x = getX();
        int y = getY() + 2;
        int border = isHoveredOrFocused() ? 0xFFFFFFFF : 0xFFAAAAAA;
        graphics.fill(x, y, x + BOX_SIZE, y + BOX_SIZE, border);
        graphics.fill(x + 1, y + 1, x + BOX_SIZE - 1, y + BOX_SIZE - 1, 0xFF101010);
        if (selected) {
            graphics.fill(x + 3, y + 7, x + 7, y + 11, 0xFFFFFFFF);
            graphics.fill(x + 6, y + 5, x + 10, y + 12, 0xFFFFFFFF);
            graphics.fill(x + 9, y + 3, x + 13, y + 8, 0xFFFFFFFF);
        }
        graphics.drawString(font, getMessage(), x + BOX_SIZE + 6, getY() + 6, 0xFFFFFF);
    }

    @Override
    protected void updateWidgetNarration(NarrationElementOutput output) {
        defaultButtonNarrationText(output);
    }
}
