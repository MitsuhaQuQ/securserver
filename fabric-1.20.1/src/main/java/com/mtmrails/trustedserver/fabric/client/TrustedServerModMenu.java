package com.mtmrails.trustedserver.fabric.client;

import com.terraformersmc.modmenu.api.ConfigScreenFactory;
import com.terraformersmc.modmenu.api.ModMenuApi;

/** Mod Menu 可选入口；未安装 Mod Menu 不影响认证功能。 */
public final class TrustedServerModMenu implements ModMenuApi {
    @Override
    public ConfigScreenFactory<?> getModConfigScreenFactory() {
        return parent -> new KeyBackupScreen(parent, TrustedServerClient.backups(), null);
    }
}
