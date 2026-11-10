package com.mtmrails.trustedserver.fabric.client;

import com.mtmrails.trustedserver.client.BackupException;
import com.mtmrails.trustedserver.client.PlayerKeyBackupManager;
import com.mtmrails.trustedserver.client.StoredKey;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import net.minecraft.client.gui.GuiGraphics;
import net.minecraft.client.gui.components.Button;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.network.chat.Component;
import org.lwjgl.util.tinyfd.TinyFileDialogs;

/** Mod 设置中的玩家认证密钥导入 / 导出入口。 */
final class KeyBackupScreen extends Screen {
    private static final int PAGE_SIZE = 7;

    private final Screen parent;
    private final PlayerKeyBackupManager manager;
    private final List<StoredKey> keys = new ArrayList<>();
    private boolean[] selected = new boolean[0];
    private int page;
    private Component status;
    private Button exportButton;

    KeyBackupScreen(Screen parent, PlayerKeyBackupManager manager, String status) {
        super(Component.literal("TrustedServer 认证密钥"));
        this.parent = parent;
        this.manager = manager;
        this.status = status == null ? null : Component.literal(status);
        try {
            keys.addAll(manager.list());
            selected = new boolean[keys.size()];
            java.util.Arrays.fill(selected, true);
        } catch (IOException e) {
            this.status = Component.literal("无法读取本地密钥：" + e.getMessage());
        }
    }

    @Override
    protected void init() {
        int center = width / 2;
        int start = page * PAGE_SIZE;
        int end = Math.min(keys.size(), start + PAGE_SIZE);
        for (int i = start; i < end; i++) {
            int index = i;
            Button row = Button.builder(rowLabel(index), button -> {
                selected[index] = !selected[index];
                button.setMessage(rowLabel(index));
                updateExportButton();
            }).bounds(center - 190, 48 + (i - start) * 22, 380, 20).build();
            addRenderableWidget(row);
        }

        Button previous = Button.builder(Component.literal("上一页"), b -> {
            page--;
            rebuildWidgets();
        }).bounds(center - 190, height - 76, 80, 20).build();
        previous.active = page > 0;
        addRenderableWidget(previous);
        Button next = Button.builder(Component.literal("下一页"), b -> {
            page++;
            rebuildWidgets();
        }).bounds(center - 105, height - 76, 80, 20).build();
        next.active = (page + 1) * PAGE_SIZE < keys.size();
        addRenderableWidget(next);
        addRenderableWidget(Button.builder(Component.literal("全选/全不选"), b -> {
            boolean choose = selectedCount() != selected.length;
            java.util.Arrays.fill(selected, choose);
            rebuildWidgets();
        }).bounds(center + 25, height - 76, 165, 20).build());

        exportButton = Button.builder(Component.literal("导出所选认证"), b -> exportSelected())
                .bounds(center - 190, height - 50, 120, 20).build();
        updateExportButton();
        addRenderableWidget(exportButton);
        addRenderableWidget(Button.builder(Component.literal("导入认证"), b -> importBackup())
                .bounds(center - 60, height - 50, 120, 20).build());
        addRenderableWidget(Button.builder(Component.literal("完成"), b -> onClose())
                .bounds(center + 70, height - 50, 120, 20).build());
    }

    private Component rowLabel(int index) {
        StoredKey key = keys.get(index);
        String fingerprint = key.target().serverFingerprint();
        if (fingerprint.length() > 16) fingerprint = fingerprint.substring(0, 16);
        return Component.literal((selected[index] ? "[✓] " : "[ ] ") + key.target().username()
                + "  服务器 " + fingerprint + "…");
    }

    private int selectedCount() {
        int count = 0;
        for (boolean value : selected) if (value) count++;
        return count;
    }

    private void updateExportButton() {
        if (exportButton != null) {
            exportButton.active = selectedCount() > 0;
        }
    }

    private void exportSelected() {
        List<StoredKey> chosen = new ArrayList<>();
        for (int i = 0; i < keys.size(); i++) if (selected[i]) chosen.add(keys.get(i));
        if (chosen.isEmpty()) {
            status = Component.literal("请至少勾选一项认证密钥后再导出");
            updateExportButton();
            return;
        }
        minecraft.setScreen(new BackupExportPasswordScreen(this, manager, chosen));
    }

    private void importBackup() {
        String chosen = TinyFileDialogs.tinyfd_openFileDialog("导入 TrustedServer 认证", "", null,
                "TrustedServer key backup", false);
        if (chosen != null) {
            minecraft.setScreen(new BackupImportPasswordScreen(this, manager, Path.of(chosen)));
        }
    }

    Screen rootParent() {
        return parent;
    }

    @Override
    public void onClose() {
        minecraft.setScreen(parent);
    }

    @Override
    public void render(GuiGraphics graphics, int mouseX, int mouseY, float partialTick) {
        graphics.fill(0, 0, width, height, 0xC0101010);
        graphics.drawCenteredString(font, title, width / 2, 20, 0xFFFFFF);
        graphics.drawCenteredString(font, Component.literal("默认全选；备份不包含登录密码或服务器私钥"),
                width / 2, 33, 0xA0A0A0);
        if (keys.isEmpty() && status == null) {
            graphics.drawCenteredString(font, Component.literal("本机还没有玩家认证密钥"),
                    width / 2, height / 2, 0xA0A0A0);
        }
        if (status != null) {
            graphics.drawCenteredString(font, status, width / 2, height - 92, 0xFFFF55);
        }
        super.render(graphics, mouseX, mouseY, partialTick);
    }
}
