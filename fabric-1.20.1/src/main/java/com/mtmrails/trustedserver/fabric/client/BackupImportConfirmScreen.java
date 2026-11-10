package com.mtmrails.trustedserver.fabric.client;

import com.mtmrails.trustedserver.client.PlayerKeyBackupManager;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;

/** 导入预检摘要；覆盖本机不同密钥必须使用单独的明确按钮。 */
final class BackupImportConfirmScreen extends Screen {
    private final KeyBackupScreen parent;
    private final PlayerKeyBackupManager manager;
    private final PlayerKeyBackupManager.ImportPreview preview;
    private Component error;

    BackupImportConfirmScreen(KeyBackupScreen parent, PlayerKeyBackupManager manager,
            PlayerKeyBackupManager.ImportPreview preview) {
        super(Component.literal("确认导入认证"));
        this.parent = parent;
        this.manager = manager;
        this.preview = preview;
    }

    @Override
    protected void init() {
        int center = width / 2;
        addRenderableWidget(Button.builder(Component.literal("导入且跳过冲突"), b -> apply(false))
                .bounds(center - 190, height / 2 + 36, 120, 20).build());
        Button overwrite = Button.builder(Component.literal("确认覆盖冲突"), b -> apply(true))
                .bounds(center - 60, height / 2 + 36, 120, 20).build();
        overwrite.active = preview.conflicts() > 0;
        addRenderableWidget(overwrite);
        addRenderableWidget(Button.builder(Component.literal("取消"), b -> onClose())
                .bounds(center + 70, height / 2 + 36, 120, 20).build());
    }

    private void apply(boolean overwrite) {
        try {
            PlayerKeyBackupManager.ImportResult result = manager.apply(preview, overwrite);
            minecraft.setScreen(new KeyBackupScreen(parent.rootParent(), manager,
                    "导入完成：新增 " + result.added() + "，相同 " + result.identical()
                            + "，覆盖 " + result.replaced() + "，跳过冲突 " + result.conflictsSkipped()));
        } catch (Exception e) {
            error = Component.literal("导入失败：" + e.getMessage());
        }
    }

    @Override
    public void onClose() {
        minecraft.setScreen(parent);
    }

    @Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        graphics.fill(0, 0, width, height, 0xC0101010);
        long missing = preview.entries().stream()
                .filter(e -> e.disposition() == PlayerKeyBackupManager.Disposition.MISSING).count();
        long identical = preview.entries().stream()
                .filter(e -> e.disposition() == PlayerKeyBackupManager.Disposition.IDENTICAL).count();
        graphics.drawCenteredString(font, title, width / 2, height / 2 - 70, 0xFFFFFF);
        graphics.drawCenteredString(font, Component.literal("新增 " + missing + "，已有相同 " + identical
                + "，本机不同密钥冲突 " + preview.conflicts()), width / 2, height / 2 - 42, 0xFFFFFF);
        if (preview.conflicts() > 0) {
            graphics.drawCenteredString(font, Component.literal("覆盖会替换本机设备密钥，必须明确确认"),
                    width / 2, height / 2 - 20, 0xFF5555);
        }
        if (error != null) graphics.drawCenteredString(font, error, width / 2, height / 2 + 66, 0xFF5555);
        super.render(graphics, mouseX, mouseY, partialTick);
    }
}
