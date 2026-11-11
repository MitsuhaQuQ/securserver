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
        super(Component.translatable("trustedserver.backup.import.confirm_title"));
        this.parent = parent;
        this.manager = manager;
        this.preview = preview;
    }

    @Override
    protected void init() {
        int center = width / 2;
        addRenderableWidget(Button.builder(Component.translatable("trustedserver.button.import_skip_conflicts"), b -> apply(false))
                .bounds(center - 190, height / 2 + 36, 120, 20).build());
        Button overwrite = Button.builder(Component.translatable("trustedserver.button.overwrite_conflicts"), b -> apply(true))
                .bounds(center - 60, height / 2 + 36, 120, 20).build();
        overwrite.active = preview.conflicts() > 0;
        addRenderableWidget(overwrite);
        addRenderableWidget(Button.builder(Component.translatable("gui.cancel"), b -> onClose())
                .bounds(center + 70, height / 2 + 36, 120, 20).build());
    }

    private void apply(boolean overwrite) {
        try {
            PlayerKeyBackupManager.ImportResult result = manager.apply(preview, overwrite);
            minecraft.setScreen(new KeyBackupScreen(parent.rootParent(), manager,
                    Component.translatable("trustedserver.backup.import.success", result.added(),
                            result.identical(), result.replaced(), result.conflictsSkipped())));
        } catch (Exception e) {
            error = Component.translatable("trustedserver.backup.error.import", e.getMessage());
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
        graphics.drawCenteredString(font, Component.translatable("trustedserver.backup.import.summary",
                missing, identical, preview.conflicts()), width / 2, height / 2 - 42, 0xFFFFFF);
        if (preview.conflicts() > 0) {
            graphics.drawCenteredString(font, Component.translatable("trustedserver.backup.overwrite_warning"),
                    width / 2, height / 2 - 20, 0xFF5555);
        }
        if (error != null) graphics.drawCenteredString(font, error, width / 2, height / 2 + 66, 0xFF5555);
        super.render(graphics, mouseX, mouseY, partialTick);
    }
}
