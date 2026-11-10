package com.mtmrails.trustedserver.core.session;

import com.mtmrails.trustedserver.core.crypto.Ed25519;
import com.mtmrails.trustedserver.core.message.PasswordRequest;
import com.mtmrails.trustedserver.core.message.PasswordAnswer;
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
     * 弹出密码输入框。Optional.empty 表示取消；SET 的取消由状态机兼容为 SKIP。
     * 两次输入一致性与 REQUEST_RESET / CLEAR 等显式动作由界面在本地确定。
     */
    CompletableFuture<Optional<PasswordAnswer>> promptPassword(PasswordRequest request);
}
