package com.mtmrails.trustedserver.fabric.client;

import com.mtmrails.trustedserver.fabric.TrustedServerFabric;
import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.loader.api.FabricLoader;

/** 客户端入口：应答服务端的认证握手（第一阶段，见 docs/ADAPTER.md 第 4 节）。 */
public final class TrustedServerClient implements ClientModInitializer {
    @Override
    public void onInitializeClient() {
        FabricClientEnvironment environment =
                new FabricClientEnvironment(FabricLoader.getInstance().getConfigDir().resolve("trustedserver"));
        new ClientLoginHandler(environment).register();
        TrustedServerFabric.LOGGER.info("TrustedServer client ready");
    }
}
