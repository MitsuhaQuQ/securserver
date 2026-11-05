package com.mtmrails.trustedserver.core.session;

import com.mtmrails.trustedserver.core.crypto.Ed25519;
import com.mtmrails.trustedserver.core.message.PasswordRequest;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * 客户端状态机依赖的本地能力，由 core-client（存储）和 common 层（界面）实现。
 */
public interface ClientEnvironment {
    /** 该服务器地址已记住的服务端身份公钥（TOFU）。 */
    Optional<byte[]> pinnedServerKey(String serverAddress);

    /** 记住服务端身份公钥。只会在签名验证通过后、首次连接或玩家确认变更后调用。 */
    void pinServerKey(String serverAddress, byte[] serverIdPub);

    /** 服务端身份公钥与记录不一致时，明确警告并询问玩家；默认应拒绝。 */
    CompletableFuture<Boolean> confirmServerKeyChange(String serverAddress, byte[] pinnedKey, byte[] presentedKey);

    /** 取出（或首次生成并保存）该“服务端身份公钥 + 用户名”对应的玩家密钥。 */
    CompletableFuture<Ed25519.KeyPairData> playerKey(byte[] serverIdPub, String username);

    /**
     * 弹出密码输入框。返回空表示玩家取消；对 SET 而言空串或空结果都表示“跳过”。
     * SET 的两次输入一致性由界面在本地校验，这里只返回最终密码。
     */
    CompletableFuture<Optional<String>> promptPassword(PasswordRequest request);
}
