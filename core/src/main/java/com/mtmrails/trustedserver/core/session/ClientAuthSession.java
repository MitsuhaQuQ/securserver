package com.mtmrails.trustedserver.core.session;

import com.mtmrails.trustedserver.core.ProtocolVersion;
import com.mtmrails.trustedserver.core.crypto.CryptoException;
import com.mtmrails.trustedserver.core.crypto.Ed25519;
import com.mtmrails.trustedserver.core.crypto.HandshakeSignatures;
import com.mtmrails.trustedserver.core.crypto.SecureMessageChannel;
import com.mtmrails.trustedserver.core.crypto.SessionHandover;
import com.mtmrails.trustedserver.core.crypto.SessionKeys;
import com.mtmrails.trustedserver.core.crypto.Side;
import com.mtmrails.trustedserver.core.crypto.Transcript;
import com.mtmrails.trustedserver.core.crypto.X25519;
import com.mtmrails.trustedserver.core.message.Challenge;
import com.mtmrails.trustedserver.core.message.Channel;
import com.mtmrails.trustedserver.core.message.ClientHello;
import com.mtmrails.trustedserver.core.message.ClientProof;
import com.mtmrails.trustedserver.core.message.Finish;
import com.mtmrails.trustedserver.core.message.FinishAck;
import com.mtmrails.trustedserver.core.message.Message;
import com.mtmrails.trustedserver.core.message.MessageCodec;
import com.mtmrails.trustedserver.core.message.PasswordAnswer;
import com.mtmrails.trustedserver.core.message.PasswordRequest;
import com.mtmrails.trustedserver.core.message.ServerHello;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * 客户端认证状态机：一个连接一个实例。
 *
 * <pre>
 * ServerHello → ClientHello
 * Challenge → 验签 → TOFU 核对 → ClientProof
 * PasswordRequest → 弹框 → PasswordAnswer     （可出现多次，只在 ClientProof 之后）
 * Finish → FinishAck，完成
 * </pre>
 *
 * <p>服务端身份通过检查之前，不会弹出密码输入框，也不会发送任何密码（PROTOCOL.md 4.4）。
 * 每次只能有一个 {@link #onQuery} 在途。
 */
public final class ClientAuthSession {
    private enum State {
        AWAIT_SERVER_HELLO,
        AWAIT_CHALLENGE,
        AWAIT_SERVER_DECISION,
        DONE
    }

    private final String serverAddress;
    private final String username;
    private final boolean wantTunnel;
    private final ClientEnvironment environment;
    private final SecureRandom random;

    private State state = State.AWAIT_SERVER_HELLO;
    private boolean busy;
    private byte[] transcript;
    private SessionKeys keys;
    private SecureMessageChannel auth;
    private SecureMessageChannel password;
    private boolean tunnelAvailable;
    private boolean tunnelRequired;

    /**
     * @param serverAddress 用于 TOFU 记录的服务器地址
     * @param username 原版登录 Hello 中发送的原始用户名
     * @param wantTunnel 客户端配置是否希望开启隧道
     */
    public ClientAuthSession(String serverAddress, String username, boolean wantTunnel,
            ClientEnvironment environment, SecureRandom random) {
        this.serverAddress = Objects.requireNonNull(serverAddress, "serverAddress");
        this.username = Objects.requireNonNull(username, "username");
        this.wantTunnel = wantTunnel;
        this.environment = Objects.requireNonNull(environment, "environment");
        this.random = Objects.requireNonNull(random, "random");
    }

    public CompletableFuture<ClientStep> onQuery(Channel channel, byte[] payload) {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(payload, "payload");
        if (state == State.DONE) {
            throw new IllegalStateException("session already finished");
        }
        if (busy) {
            throw new IllegalStateException("previous query still in progress");
        }
        busy = true;
        CompletableFuture<ClientStep> step;
        try {
            step = dispatch(channel, payload);
        } catch (MalformedMessageException e) {
            step = fail(ClientFailure.Kind.PROTOCOL_ERROR, e.getMessage());
        } catch (CryptoException e) {
            step = fail(ClientFailure.Kind.CRYPTO_FAILURE, e.getMessage());
        } catch (RuntimeException e) {
            step = fail(ClientFailure.Kind.INTERNAL_ERROR, String.valueOf(e.getMessage()));
        }
        return step
                .exceptionally(t -> failNow(ClientFailure.Kind.INTERNAL_ERROR, String.valueOf(t.getMessage())))
                .thenApply(s -> {
                    busy = false;
                    return s;
                });
    }

    /** 连接被关闭或超时：废弃所有通道与密钥。 */
    public void abort() {
        cleanup();
        state = State.DONE;
    }

    private CompletableFuture<ClientStep> dispatch(Channel channel, byte[] payload)
            throws MalformedMessageException, CryptoException {
        switch (state) {
            case AWAIT_SERVER_HELLO:
                return channel == Channel.AUTH ? onServerHello(payload) : protocolError("expected ServerHello");
            case AWAIT_CHALLENGE:
                return channel == Channel.AUTH ? onChallenge(payload) : protocolError("expected Challenge");
            case AWAIT_SERVER_DECISION:
                return channel == Channel.PASSWORD ? onPasswordRequest(payload) : onFinish(payload);
            default:
                throw new IllegalStateException("unreachable");
        }
    }

    private CompletableFuture<ClientStep> onServerHello(byte[] payload)
            throws MalformedMessageException, CryptoException {
        Message message = MessageCodec.decodePlain(Channel.AUTH, payload);
        if (!(message instanceof ServerHello hello)) {
            return protocolError("expected ServerHello, got " + message.type());
        }
        int version = ProtocolVersion.negotiate(hello.versions());
        X25519.Ephemeral ephemeral = X25519.generate(random);
        byte[] clientNonce = new byte[32];
        random.nextBytes(clientNonce);
        byte[] clientHello = MessageCodec.encodePlain(
                new ClientHello(version, ephemeral.publicKey(), clientNonce, wantTunnel));
        if (version == ProtocolVersion.NONE) {
            cleanup();
            state = State.DONE;
            return CompletableFuture.completedFuture(new ClientStep.Fail(new ClientFailure(
                    ClientFailure.Kind.VERSION_MISMATCH,
                    "server supports " + Arrays.toString(hello.versions())
                            + ", client supports " + Arrays.toString(ProtocolVersion.supported())),
                    Optional.of(clientHello)));
        }
        transcript = Transcript.compute(payload, clientHello, username);
        keys = SessionKeys.derive(ephemeral.agree(hello.serverEphPub()), hello.serverNonce(), clientNonce, transcript);
        auth = keys.authChannel(Side.CLIENT);
        password = keys.passwordChannel(Side.CLIENT);
        tunnelAvailable = hello.tunnelAvailable();
        tunnelRequired = hello.tunnelRequired();
        state = State.AWAIT_CHALLENGE;
        return CompletableFuture.completedFuture(new ClientStep.Reply(clientHello));
    }

    private CompletableFuture<ClientStep> onChallenge(byte[] payload)
            throws MalformedMessageException, CryptoException {
        Message message = auth.open(payload);
        if (!(message instanceof Challenge challenge)) {
            return protocolError("expected Challenge, got " + message.type());
        }
        byte[] serverIdPub = challenge.serverIdPub();
        if (!HandshakeSignatures.verifyServer(serverIdPub, transcript, challenge.serverSig())) {
            return fail(ClientFailure.Kind.SERVER_SIGNATURE_INVALID, "server identity signature is invalid");
        }
        Optional<byte[]> pinned = environment.pinnedServerKey(serverAddress);
        CompletableFuture<Boolean> trusted;
        if (pinned.isEmpty()) {
            environment.pinServerKey(serverAddress, serverIdPub);
            trusted = CompletableFuture.completedFuture(true);
        } else if (Arrays.equals(pinned.get(), serverIdPub)) {
            trusted = CompletableFuture.completedFuture(true);
        } else {
            trusted = environment.confirmServerKeyChange(serverAddress, pinned.get(), serverIdPub)
                    .thenApply(accepted -> {
                        if (accepted) {
                            environment.pinServerKey(serverAddress, serverIdPub);
                        }
                        return accepted;
                    });
        }
        return trusted.thenCompose(accepted -> {
            if (!accepted) {
                return fail(ClientFailure.Kind.SERVER_KEY_REJECTED, "server identity key changed");
            }
            return environment.playerKey(serverIdPub, username).thenApply(this::sendProof);
        });
    }

    private ClientStep sendProof(Ed25519.KeyPairData playerKey) {
        try {
            byte[] proof = auth.seal(new ClientProof(playerKey.publicKey(),
                    HandshakeSignatures.signClient(playerKey, transcript)));
            state = State.AWAIT_SERVER_DECISION;
            return new ClientStep.Reply(proof);
        } catch (CryptoException e) {
            return failNow(ClientFailure.Kind.CRYPTO_FAILURE, e.getMessage());
        }
    }

    private CompletableFuture<ClientStep> onPasswordRequest(byte[] payload)
            throws MalformedMessageException, CryptoException {
        Message message = password.open(payload);
        if (!(message instanceof PasswordRequest request)) {
            return protocolError("expected PasswordRequest, got " + message.type());
        }
        return environment.promptPassword(request).thenApply(entered -> {
            if (entered.isEmpty() && request.kind() != PasswordRequest.Kind.SET) {
                return failNow(ClientFailure.Kind.USER_CANCELLED, "password entry cancelled");
            }
            try {
                PasswordAnswer answer = entered.orElseGet(() -> new PasswordAnswer(""));
                if (!validAction(request.kind(), answer)) {
                    return failNow(ClientFailure.Kind.INTERNAL_ERROR,
                            "invalid password action " + answer.action() + " for " + request.kind());
                }
                return new ClientStep.Reply(password.seal(answer));
            } catch (IllegalArgumentException e) {
                return failNow(ClientFailure.Kind.INTERNAL_ERROR, "password rejected locally: " + e.getMessage());
            } catch (CryptoException e) {
                return failNow(ClientFailure.Kind.CRYPTO_FAILURE, e.getMessage());
            }
        });
    }

    private static boolean validAction(PasswordRequest.Kind kind, PasswordAnswer answer) {
        return switch (kind) {
            case LOGIN -> answer.action() == PasswordAnswer.Action.SUBMIT
                    || (answer.action() == PasswordAnswer.Action.REQUEST_RESET && answer.password().isEmpty());
            case RECOVERY -> answer.action() == PasswordAnswer.Action.SUBMIT
                    || (answer.action() == PasswordAnswer.Action.REQUEST_RESET && !answer.password().isEmpty());
            case SET -> answer.action() == PasswordAnswer.Action.SUBMIT
                    || answer.action() == PasswordAnswer.Action.SKIP;
            case RESET -> answer.action() == PasswordAnswer.Action.SUBMIT
                    || answer.action() == PasswordAnswer.Action.CLEAR;
        };
    }

    private CompletableFuture<ClientStep> onFinish(byte[] payload)
            throws MalformedMessageException, CryptoException {
        Message message = auth.open(payload);
        if (!(message instanceof Finish finish)) {
            return protocolError("expected Finish, got " + message.type());
        }
        boolean expectedTunnel = tunnelRequired || (tunnelAvailable && wantTunnel);
        if (finish.tunnel() != expectedTunnel) {
            return protocolError("unexpected tunnel decision");
        }
        byte[] ack = auth.seal(new FinishAck());
        SessionHandover handover = SessionHandover.create(keys, Side.CLIENT, password, finish.tunnel());
        state = State.DONE;
        auth.close();
        keys.destroy();
        return CompletableFuture.completedFuture(
                new ClientStep.Complete(ack, new ClientResult(finish.tunnel(), finish.notices(), handover)));
    }

    private CompletableFuture<ClientStep> protocolError(String detail) {
        return fail(ClientFailure.Kind.PROTOCOL_ERROR, detail);
    }

    private CompletableFuture<ClientStep> fail(ClientFailure.Kind kind, String detail) {
        return CompletableFuture.completedFuture(failNow(kind, detail));
    }

    private ClientStep failNow(ClientFailure.Kind kind, String detail) {
        cleanup();
        state = State.DONE;
        return new ClientStep.Fail(new ClientFailure(kind, String.valueOf(detail)), Optional.empty());
    }

    private void cleanup() {
        if (auth != null) {
            auth.close();
            password.close();
        }
        if (keys != null) {
            keys.destroy();
        }
    }
}
