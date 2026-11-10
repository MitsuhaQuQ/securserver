package com.mtmrails.trustedserver.fabric.client;

import com.mtmrails.trustedserver.client.PresharedKeys;
import com.mtmrails.trustedserver.client.OnlineTokens;
import com.mtmrails.trustedserver.client.PlayerKeyBackupManager;
import com.mtmrails.trustedserver.fabric.TrustedServerFabric;
import java.io.IOException;
import java.nio.file.Path;
import java.security.SecureRandom;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.loader.api.FabricLoader;

/** 客户端入口：应答服务端的认证握手（第一阶段，见 docs/ADAPTER.md 第 4 节）。 */
public final class TrustedServerClient implements ClientModInitializer {
    private static PlayerKeyBackupManager backups;

    @Override
    public void onInitializeClient() {
        Path dataDir = FabricLoader.getInstance().getConfigDir().resolve("trustedserver");
        PresharedKeys keys = new PresharedKeys(dataDir.resolve("psk.txt"));
        try {
            keys.createTemplateIfMissing();
        } catch (IOException e) {
            throw new IllegalStateException("Cannot create TrustedServer PSK configuration", e);
        }
        new PskLoginHandler(keys).register();
        new OnlineTokenLoginHandler(new OnlineTokens(dataDir.resolve("online_tokens.txt"))).register();
        FabricClientEnvironment environment = new FabricClientEnvironment(dataDir);
        backups = new PlayerKeyBackupManager(environment.keyStore(), new SecureRandom());
        new ClientLoginHandler(environment).register();
        TrustedServerFabric.LOGGER.info(
                "TrustedServer client ready (PSK / online token gate + Ed25519 player authentication)");
    }

    static PlayerKeyBackupManager backups() {
        if (backups == null) throw new IllegalStateException("TrustedServer client is not initialized");
        return backups;
    }
}
