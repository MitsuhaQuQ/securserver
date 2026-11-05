package com.mtmrails.trustedserver.client;

import com.mtmrails.trustedserver.core.crypto.Ed25519;
import java.util.Objects;

/** 一把玩家认证密钥及其定位。 */
public record StoredKey(KeyTarget target, Ed25519.KeyPairData key) {
    public StoredKey {
        Objects.requireNonNull(target, "target");
        Objects.requireNonNull(key, "key");
    }

    @Override
    public String toString() {
        return "StoredKey[" + target + "]";
    }
}
