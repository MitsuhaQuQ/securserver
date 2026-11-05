package com.mtmrails.trustedserver.client;

import com.mtmrails.trustedserver.core.crypto.CryptoException;
import com.mtmrails.trustedserver.core.crypto.Ed25519;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;

/** 单条密钥记录的编解码：服务端身份公钥 32 | 用户名 string | 玩家公钥 32 | 私钥种子 32。 */
final class KeyRecordCodec {
    private KeyRecordCodec() {
    }

    static void write(WireWriter out, StoredKey stored) {
        out.fixed(stored.target().serverIdPub())
                .string(stored.target().username(), KeyTarget.MAX_USERNAME_BYTES)
                .fixed(stored.key().publicKey())
                .fixed(stored.key().seed());
    }

    /** 读取并校验：用户名合法、种子与公钥匹配。 */
    static StoredKey read(WireReader in) throws MalformedMessageException {
        byte[] serverIdPub = in.fixed(Ed25519.PUBLIC_KEY_LENGTH);
        String username = in.string(KeyTarget.MAX_USERNAME_BYTES);
        byte[] playerPub = in.fixed(Ed25519.PUBLIC_KEY_LENGTH);
        byte[] seed = in.fixed(Ed25519.SEED_LENGTH);
        KeyTarget target;
        try {
            target = new KeyTarget(serverIdPub, username);
        } catch (IllegalArgumentException e) {
            throw new MalformedMessageException(e.getMessage(), e);
        }
        try {
            return new StoredKey(target, Ed25519.fromSeed(seed, playerPub));
        } catch (CryptoException e) {
            throw new MalformedMessageException("private key does not match public key for " + target, e);
        } finally {
            java.util.Arrays.fill(seed, (byte) 0);
        }
    }
}
