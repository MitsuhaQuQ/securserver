package com.mtmrails.trustedserver.core.session;

import com.mtmrails.trustedserver.core.crypto.Ed25519;
import com.mtmrails.trustedserver.core.message.PasswordRequest;
import com.mtmrails.trustedserver.core.message.PasswordAnswer;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/** 测试用客户端环境：内存 TOFU 与玩家密钥，密码弹框按脚本作答。 */
final class TestClientEnvironment implements ClientEnvironment {
    final Map<String, byte[]> pinned = new HashMap<>();
    final Map<String, Ed25519.KeyPairData> playerKeys = new HashMap<>();
    /** 依次作答；{@code null} 表示取消 / 跳过。 */
    final Deque<Optional<PasswordAnswer>> answers = new ArrayDeque<>();
    final List<PasswordRequest> prompts = new ArrayList<>();
    boolean acceptKeyChange;
    int keyChangePrompts;
    Consumer<PasswordRequest> onPrompt = request -> { };

    TestClientEnvironment answer(String... passwords) {
        for (String password : passwords) {
            answers.add(password == null ? Optional.empty() : Optional.of(new PasswordAnswer(password)));
        }
        return this;
    }

    TestClientEnvironment respond(PasswordAnswer... responses) {
        for (PasswordAnswer response : responses) {
            answers.add(Optional.of(response));
        }
        return this;
    }

    @Override
    public Optional<byte[]> pinnedServerKey(String serverAddress) {
        return Optional.ofNullable(pinned.get(serverAddress)).map(byte[]::clone);
    }

    @Override
    public void pinServerKey(String serverAddress, byte[] serverIdPub) {
        pinned.put(serverAddress, serverIdPub.clone());
    }

    @Override
    public CompletableFuture<Boolean> confirmServerKeyChange(String serverAddress, byte[] pinnedKey,
            byte[] presentedKey) {
        keyChangePrompts++;
        return CompletableFuture.completedFuture(acceptKeyChange);
    }

    @Override
    public CompletableFuture<Ed25519.KeyPairData> playerKey(byte[] serverIdPub, String username) {
        String id = HexFormat.of().formatHex(serverIdPub) + "/" + username;
        return CompletableFuture.completedFuture(
                playerKeys.computeIfAbsent(id, k -> Ed25519.generate(new SecureRandom())));
    }

    Ed25519.KeyPairData keyFor(byte[] serverIdPub, String username) {
        return playerKeys.get(HexFormat.of().formatHex(serverIdPub) + "/" + username);
    }

    @Override
    public CompletableFuture<Optional<PasswordAnswer>> promptPassword(PasswordRequest request) {
        prompts.add(request);
        onPrompt.accept(request);
        if (answers.isEmpty()) {
            throw new AssertionError("unexpected password prompt: " + request);
        }
        return CompletableFuture.completedFuture(answers.poll());
    }
}
