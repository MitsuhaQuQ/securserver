package com.mtmrails.trustedserver.fabric.server;

import com.mtmrails.trustedserver.fabric.TrustedServerFabric;
import net.fabricmc.api.DedicatedServerModInitializer;

/**
 * 独立服务端入口。内置服务器（单人游戏、局域网）不会调用它，因此认证只在独立服务端生效（AGENTS.md）。
 * 登录接入在步骤 B 实现。
 */
public final class TrustedServerDedicated implements DedicatedServerModInitializer {
    @Override
    public void onInitializeServer() {
        TrustedServerFabric.LOGGER.info("TrustedServer dedicated-server side initialising");
    }
}
