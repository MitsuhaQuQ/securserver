package com.mtmrails.trustedserver.fabric.client;

import com.mtmrails.trustedserver.client.KeyTarget;
import com.mtmrails.trustedserver.client.KnownServers;
import com.mtmrails.trustedserver.client.PlayerKeyStore;
import com.mtmrails.trustedserver.core.crypto.Ed25519;
import com.mtmrails.trustedserver.core.message.PasswordRequest;
import com.mtmrails.trustedserver.core.session.ClientEnvironment;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import net.minecraft.Util;

/**
 * 第一阶段的客户端环境（docs/ADAPTER.md 第 4 节）：TOFU 记录与玩家密钥落盘；密码界面与公钥变更确认尚未实现——
 * SET 一律按“跳过”回答，其余密码请求按取消处理，服务端公钥变化一律拒绝。
 *
 * <p>本地存储损坏时抛出异常，状态机按内部错误失败并断开，绝不静默放弃已有的信任记录或密钥。
 */
final class FabricClientEnvironment implements ClientEnvironment {
    private final KnownServers knownServers;
    private final PlayerKeyStore keyStore;
    private final SecureRandom random = new SecureRandom();

    FabricClientEnvironment(Path dataDir) {
        this.knownServers = new KnownServers(dataDir.resolve("known_servers.txt"));
        this.keyStore = new PlayerKeyStore(dataDir.resolve("keys"));
    }

    PlayerKeyStore keyStore() {
        return keyStore;
    }

    @Override
    public Optional<byte[]> pinnedServerKey(String serverAddress) {
        try {
            return knownServers.get(serverAddress);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public void pinServerKey(String serverAddress, byte[] serverIdPub) {
        try {
            knownServers.put(serverAddress, serverIdPub);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public CompletableFuture<Boolean> confirmServerKeyChange(String serverAddress, byte[] pinnedKey,
            byte[] presentedKey) {
        return CompletableFuture.completedFuture(false);
    }

    @Override
    public CompletableFuture<Ed25519.KeyPairData> playerKey(byte[] serverIdPub, String username) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return keyStore.getOrCreate(new KeyTarget(serverIdPub, username), random);
            } catch (IOException e) {
                throw new CompletionException(e);
            }
        }, Util.ioPool());
    }

    @Override
    public CompletableFuture<Optional<String>> promptPassword(PasswordRequest request) {
        return CompletableFuture.completedFuture(Optional.empty());
    }
}
