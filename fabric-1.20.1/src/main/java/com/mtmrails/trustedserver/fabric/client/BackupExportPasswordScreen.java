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
import net.minecraft.client.resources.language.I18n;
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
        super(Component.translatable("trustedserver.backup.export.title"));
        this.parent = parent;
        this.manager = manager;
        this.selected = List.copyOf(selected);
    }

    @Override
    protected void init() {
        int center = width / 2;
        password = new EditBox(font, center - 150, height / 2 - 42, 300, 20,
                Component.translatable("trustedserver.backup.field.password"));
        confirm = new EditBox(font, center - 150, height / 2 - 14, 300, 20,
                Component.translatable("trustedserver.field.confirm_password"));
        password.setMaxLength(256);
        confirm.setMaxLength(256);
        password.setFormatter((text, offset) -> FormattedCharSequence.forward("•".repeat(text.length()), Style.EMPTY));
        confirm.setFormatter((text, offset) -> FormattedCharSequence.forward("•".repeat(text.length()), Style.EMPTY));
        addRenderableWidget(password);
        addRenderableWidget(confirm);
        addRenderableWidget(new RiskCheckbox(center - 150, height / 2 + 12, 300,
                Component.translatable("trustedserver.backup.allow_plaintext"), font, plaintextConfirmed,
                selected -> plaintextConfirmed = selected));
        addRenderableWidget(Button.builder(Component.translatable("trustedserver.button.export"), b -> export())
                .bounds(center - 150, height / 2 + 58, 145, 20).build());
        addRenderableWidget(Button.builder(Component.translatable("gui.cancel"), b -> onClose())
                .bounds(center + 5, height / 2 + 58, 145, 20).build());
        setInitialFocus(password);
    }

    private void export() {
        if (selected.isEmpty()) {
            error = Component.translatable("trustedserver.backup.error.select_one");
            return;
        }
        String secret = password.getValue();
        if (!secret.equals(confirm.getValue())) {
            error = Component.translatable("trustedserver.backup.error.password_mismatch");
            return;
        }
        if (secret.isEmpty() && !plaintextConfirmed) {
            error = Component.translatable("trustedserver.backup.error.confirm_plaintext");
            return;
        }
        String chosen = TinyFileDialogs.tinyfd_saveFileDialog(
                I18n.get("trustedserver.backup.dialog.export"), "trustedserver-keys.tskb", null,
                I18n.get("trustedserver.backup.dialog.filter"));
        if (chosen == null) return;
        try {
            manager.export(Path.of(chosen), selected, secret.isEmpty() ? Optional.empty() : Optional.of(secret));
            minecraft.setScreen(new KeyBackupScreen(parent.rootParent(), manager,
                    Component.translatable("trustedserver.backup.export.success", selected.size())));
        } catch (Exception e) {
            error = Component.translatable("trustedserver.backup.error.export", e.getMessage());
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
        graphics.drawCenteredString(font, Component.translatable("trustedserver.backup.plaintext_warning"),
                width / 2, height / 2 - 68, 0xFF5555);
        graphics.drawString(font, Component.translatable("trustedserver.backup.password_optional"),
                width / 2 - 150, height / 2 - 54, 0xA0A0A0);
        graphics.drawString(font, Component.translatable("trustedserver.field.enter_again"),
                width / 2 - 150, height / 2 - 26, 0xA0A0A0);
        if (error != null) graphics.drawCenteredString(font, error, width / 2, height / 2 + 40, 0xFF5555);
        super.render(graphics, mouseX, mouseY, partialTick);
    }
}
