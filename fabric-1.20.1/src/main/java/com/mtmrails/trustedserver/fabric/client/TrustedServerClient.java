package com.mtmrails.trustedserver.fabric.client;

import com.mtmrails.trustedserver.fabric.TrustedServerFabric;
import net.fabricmc.api.ClientModInitializer;

/** 客户端入口。登录接入在步骤 C 实现。 */
public final class TrustedServerClient implements ClientModInitializer {
    @Override
    public void onInitializeClient() {
        TrustedServerFabric.LOGGER.info("TrustedServer client side initialising");
    }
}
