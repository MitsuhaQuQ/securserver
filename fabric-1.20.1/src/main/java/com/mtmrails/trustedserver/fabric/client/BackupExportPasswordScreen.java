package com.mtmrails.trustedserver.fabric.client;

import com.mtmrails.trustedserver.client.PlayerKeyBackupManager;
import com.mtmrails.trustedserver.client.StoredKey;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.Style;
import net.minecraft.util.FormattedCharSequence;
import org.lwjgl.util.tinyfd.TinyFileDialogs;

/** 导出密码与明文风险确认。 */
final class BackupExportPasswordScreen extends Screen {
    private final KeyBackupScreen parent;
    private final PlayerKeyBackupManager manager;
    private final List<StoredKey> selected;
    private EditBox password;
    private EditBox confirm;
    private boolean plaintextConfirmed;
    private Component error;

    BackupExportPasswordScreen(KeyBackupScreen parent, PlayerKeyBackupManager manager, List<StoredKey> selected) {
        super(Component.literal("导出认证密钥"));
        this.parent = parent;
        this.manager = manager;
        this.selected = List.copyOf(selected);
    }

    @Override
    protected void init() {
        int center = width / 2;
        password = new EditBox(font, center - 150, height / 2 - 42, 300, 20, Component.literal("备份密码"));
        confirm = new EditBox(font, center - 150, height / 2 - 14, 300, 20, Component.literal("确认密码"));
        password.setMaxLength(256);
        confirm.setMaxLength(256);
        password.setFormatter((text, offset) -> FormattedCharSequence.forward("•".repeat(text.length()), Style.EMPTY));
        confirm.setFormatter((text, offset) -> FormattedCharSequence.forward("•".repeat(text.length()), Style.EMPTY));
        addRenderableWidget(password);
        addRenderableWidget(confirm);
        addRenderableWidget(new RiskCheckbox(center - 150, height / 2 + 12, 300,
                Component.literal("我了解风险，允许明文导出"), font, plaintextConfirmed,
                selected -> plaintextConfirmed = selected));
        addRenderableWidget(Button.builder(Component.literal("导出"), b -> export())
                .bounds(center - 150, height / 2 + 58, 145, 20).build());
        addRenderableWidget(Button.builder(Component.literal("取消"), b -> onClose())
                .bounds(center + 5, height / 2 + 58, 145, 20).build());
        setInitialFocus(password);
    }

    private void export() {
        if (selected.isEmpty()) {
            error = Component.literal("没有勾选要导出的认证密钥，请返回后至少选择一项");
            return;
        }
        String secret = password.getValue();
        if (!secret.equals(confirm.getValue())) {
            error = Component.literal("两次输入的备份密码不一致");
            return;
        }
        if (secret.isEmpty() && !plaintextConfirmed) {
            error = Component.literal("明文导出前必须明确确认风险");
            return;
        }
        String chosen = TinyFileDialogs.tinyfd_saveFileDialog("导出 TrustedServer 认证",
                "trustedserver-keys.tskb", null, "TrustedServer key backup");
        if (chosen == null) return;
        try {
            manager.export(Path.of(chosen), selected, secret.isEmpty() ? Optional.empty() : Optional.of(secret));
            minecraft.setScreen(new KeyBackupScreen(parent.rootParent(), manager,
                    "已导出 " + selected.size() + " 份认证密钥"));
        } catch (Exception e) {
            error = Component.literal("导出失败：" + e.getMessage());
        }
    }

    @Override
    public void onClose() {
        minecraft.setScreen(parent);
    }

    @Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        graphics.fill(0, 0, width, height, 0xC0101010);
        graphics.drawCenteredString(font, title, width / 2, height / 2 - 90, 0xFFFFFF);
        graphics.drawCenteredString(font, Component.literal("密码可留空，但拿到明文文件的人可以冒充你登录这些服务器"),
                width / 2, height / 2 - 68, 0xFF5555);
        graphics.drawString(font, "备份密码（可选）", width / 2 - 150, height / 2 - 54, 0xA0A0A0);
        graphics.drawString(font, "再次输入", width / 2 - 150, height / 2 - 26, 0xA0A0A0);
        if (error != null) graphics.drawCenteredString(font, error, width / 2, height / 2 + 40, 0xFF5555);
        super.render(graphics, mouseX, mouseY, partialTick);
    }
}
