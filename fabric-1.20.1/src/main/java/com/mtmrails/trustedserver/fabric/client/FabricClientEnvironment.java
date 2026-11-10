package com.mtmrails.trustedserver.fabric.client;

import com.mtmrails.trustedserver.client.KeyTarget;
import com.mtmrails.trustedserver.client.KnownServers;
import com.mtmrails.trustedserver.client.PlayerKeyStore;
import com.mtmrails.trustedserver.core.crypto.Ed25519;
import com.mtmrails.trustedserver.core.message.PasswordRequest;
import com.mtmrails.trustedserver.core.message.PasswordAnswer;
import com.mtmrails.trustedserver.core.session.ClientEnvironment;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import net.minecraft.Util;
import net.minecraft.client.Minecraft;

/**
 * Fabric 客户端环境：TOFU 记录、玩家密钥落盘和登录阶段密码界面。服务端公钥变化仍默认拒绝，
 * 等待后续明确确认界面。
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
    public CompletableFuture<Optional<PasswordAnswer>> promptPassword(PasswordRequest request) {
        CompletableFuture<Optional<PasswordAnswer>> result = new CompletableFuture<>();
        Minecraft client = Minecraft.getInstance();
        client.execute(() -> client.setScreen(new PasswordPromptScreen(client.screen, request, result)));
        return result;
    }
}
