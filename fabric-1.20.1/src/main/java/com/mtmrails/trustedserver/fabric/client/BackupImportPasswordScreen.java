package com.mtmrails.trustedserver.fabric.client;

import com.mtmrails.trustedserver.client.BackupException;
import com.mtmrails.trustedserver.client.PlayerKeyBackupManager;
import java.nio.file.Path;
import java.util.Optional;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.Style;
import net.minecraft.util.FormattedCharSequence;

/** 导入前读取可选备份密码并进行不落盘预检。 */
final class BackupImportPasswordScreen extends Screen {
    private final KeyBackupScreen parent;
    private final PlayerKeyBackupManager manager;
    private final Path source;
    private EditBox password;
    private Component error;

    BackupImportPasswordScreen(KeyBackupScreen parent, PlayerKeyBackupManager manager, Path source) {
        super(Component.literal("导入认证密钥"));
        this.parent = parent;
        this.manager = manager;
        this.source = source;
    }

    @Override
    protected void init() {
        int center = width / 2;
        password = new EditBox(font, center - 150, height / 2 - 20, 300, 20, Component.literal("备份密码"));
        password.setMaxLength(256);
        password.setFormatter((text, offset) -> FormattedCharSequence.forward("•".repeat(text.length()), Style.EMPTY));
        addRenderableWidget(password);
        addRenderableWidget(Button.builder(Component.literal("检查备份"), b -> preview())
                .bounds(center - 150, height / 2 + 20, 145, 20).build());
        addRenderableWidget(Button.builder(Component.literal("取消"), b -> onClose())
                .bounds(center + 5, height / 2 + 20, 145, 20).build());
        setInitialFocus(password);
    }

    private void preview() {
        String secret = password.getValue();
        try {
            PlayerKeyBackupManager.ImportPreview preview = manager.preview(source,
                    secret.isEmpty() ? Optional.empty() : Optional.of(secret));
            minecraft.setScreen(new BackupImportConfirmScreen(parent, manager, preview));
        } catch (BackupException e) {
            error = Component.literal(switch (e.kind()) {
                case PASSWORD_REQUIRED -> "此备份需要密码";
                case WRONG_PASSWORD_OR_CORRUPTED -> "密码错误或备份已损坏";
                case CORRUPTED -> "备份已损坏";
                case UNSUPPORTED_FORMAT -> "不是受支持的 TrustedServer 备份";
            });
        } catch (Exception e) {
            error = Component.literal("读取失败：" + e.getMessage());
        }
    }

    @Override
    public void onClose() {
        minecraft.setScreen(parent);
    }

    @Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        graphics.fill(0, 0, width, height, 0xC0101010);
        graphics.drawCenteredString(font, title, width / 2, height / 2 - 70, 0xFFFFFF);
        graphics.drawCenteredString(font, Component.literal(source.getFileName().toString()),
                width / 2, height / 2 - 52, 0xA0A0A0);
        graphics.drawString(font, "备份密码（明文备份留空）", width / 2 - 150, height / 2 - 32, 0xA0A0A0);
        if (error != null) graphics.drawCenteredString(font, error, width / 2, height / 2 + 50, 0xFF5555);
        super.render(graphics, mouseX, mouseY, partialTick);
    }
}
