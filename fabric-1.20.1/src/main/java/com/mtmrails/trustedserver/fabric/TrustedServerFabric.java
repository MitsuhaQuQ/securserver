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
    }
}
