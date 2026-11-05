package com.mtmrails.trustedserver.fabric;

import com.mtmrails.trustedserver.core.ProtocolVersion;
import net.fabricmc.api.ModInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 两端共用的入口：只做与环境无关的初始化。 */
public final class TrustedServerFabric implements ModInitializer {
    public static final String MOD_ID = "trustedserver";
    public static final Logger LOGGER = LoggerFactory.getLogger(MOD_ID);

    @Override
    public void onInitialize() {
        LOGGER.info("TrustedServer loaded (auth protocol v{})", ProtocolVersion.CURRENT);
        // 仅开发时使用：立即应用全部 mixin，注入点写错会在这里直接报错，而不是等到对应的类被加载时
        if (Boolean.getBoolean("trustedserver.auditMixins")) {
            org.spongepowered.asm.mixin.MixinEnvironment.getCurrentEnvironment().audit();
            LOGGER.info("Mixin audit finished");
        }
    }
}
