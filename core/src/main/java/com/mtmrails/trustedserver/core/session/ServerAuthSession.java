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
import java.time.Clock;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.RejectedExecutionException;

/**
 * 服务端认证状态机：一个连接一个实例（PROTOCOL.md 第 1、4 节）。
 *
 * <pre>
 * start() → ServerHello
 * ClientHello → Challenge
 * ClientProof → [PasswordRequest ↔ PasswordAnswer]* → Finish
 * FinishAck → Accepted
 * </pre>
 *
 * <p>使用约定：
 * <ul>
 *   <li>每次只能有一个 {@link #onAnswer} 在途；上一个 future 完成前再次调用抛出 {@link IllegalStateException}
 *   <li>{@code channel} 传入该回答所对应 query 的频道；{@code payload} 为 {@code null} 表示对方回答“不理解”
 *   <li>超时由上层计时，到点调用 {@link #timeout()}
 * </ul>
 *
 * <p>任何协议、密码学或账号存储失败都会废弃本连接的所有通道并返回 {@link AuthOutcome.Rejected}。
 *
 * <p>公钥与绑定不一致时：本连接已通过 Mojang session 验证（{@code mojangVerified}）时视为连接可信，
 * 直接改绑到新设备；离线模式，或正版服务器上 session 无效而回退为无验证的连接，须输对找回密码。
 * 保留原登录密码时，改绑须等到登录密码验证通过。通过找回密码取得重设授权后，也可原子地更新绑定和登录密码。
 */
public final class ServerAuthSession {
    private enum State {
        NEW,
        AWAIT_CLIENT_HELLO,
        AWAIT_PROOF,
        AWAIT_PASSWORD,
        AWAIT_FINISH_ACK,
        DONE
    }

    private final String accountId;
    private final String username;
    private final boolean onlineMode;
    private final boolean mojangVerified;
    private final ServerAuthConfig config;
    private final Ed25519.KeyPairData identity;
    private final AccountGateway accounts;
    private final SecureRandom random;
    private final Clock clock;

    private record ResetGrant(RecoveryOrigin origin, byte[] expectedOldPub, byte[] newPub,
            byte[] transcript, long expiresAt) {
        private ResetGrant {
            expectedOldPub = expectedOldPub.clone();
            newPub = newPub.clone();
            transcript = transcript.clone();
        }
        @Override public byte[] expectedOldPub() { return expectedOldPub.clone(); }
        @Override public byte[] newPub() { return newPub.clone(); }
        @Override public byte[] transcript() { return transcript.clone(); }
    }

    private State state = State.NEW;
    private Channel expectedChannel;
    private boolean busy;
    private volatile boolean timedOut;
    private AuthOutcome outcome;

    private X25519.Ephemeral ephemeral;
    private byte[] serverNonce;
    private byte[] serverHelloPayload;
    private byte[] transcript;
    private SessionKeys keys;
    private SecureMessageChannel auth;
    private SecureMessageChannel password;
    private boolean clientWantsTunnel;
    private boolean tunnel;

    private boolean trusted;
    private byte[] playerPub;
    private AccountView account;
    private RebindReason pendingRebind;
    private RebindReason rebound;
    private boolean verifiedOriginalKey;
    private PasswordRequest.Kind pendingKind;
    private int attemptsLeft;
    private int setRejections;
    private ResetGrant resetGrant;
    private boolean recoveryForPasswordReset;

    /**
     * @param accountId 账号 ID：正版为 UUID，离线为小写用户名
     * @param username 原版登录 Hello 中的原始用户名（参与 transcript）
     * @param onlineMode 服务端实际的 online-mode（写入 ServerHello）
     * @param mojangVerified 本连接是否通过了 Mojang session 验证；正版服务器上 session 无效时为 {@code false}，
     *        按无验证回退处理。离线模式下必须为 {@code false}
     */
    public ServerAuthSession(String accountId, String username, boolean onlineMode, boolean mojangVerified,
            ServerAuthConfig config, Ed25519.KeyPairData identity, AccountGateway accounts, SecureRandom random) {
        this(accountId, username, onlineMode, mojangVerified, config, identity, accounts, random, Clock.systemUTC());
    }

    ServerAuthSession(String accountId, String username, boolean onlineMode, boolean mojangVerified,
            ServerAuthConfig config, Ed25519.KeyPairData identity, AccountGateway accounts, SecureRandom random,
            Clock clock) {
        this.accountId = Objects.requireNonNull(accountId, "accountId");
        this.username = Objects.requireNonNull(username, "username");
        this.onlineMode = onlineMode;
        if (mojangVerified && !onlineMode) {
            throw new IllegalArgumentException("an offline-mode server cannot have Mojang-verified connections");
        }
        this.mojangVerified = mojangVerified;
        this.config = Objects.requireNonNull(config, "config");
        this.identity = Objects.requireNonNull(identity, "identity");
        this.accounts = Objects.requireNonNull(accounts, "accounts");
        this.random = Objects.requireNonNull(random, "random");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /** 生成 ServerHello。只能调用一次。 */
    public Outbound start() {
        if (state != State.NEW) {
            throw new IllegalStateException("session already started");
        }
        ephemeral = X25519.generate(random);
        serverNonce = new byte[32];
        random.nextBytes(serverNonce);
        serverHelloPayload = MessageCodec.encodePlain(new ServerHello(ProtocolVersion.supported(),
                ephemeral.publicKey(), serverNonce, config.features(), onlineMode));
        state = State.AWAIT_CLIENT_HELLO;
        expectedChannel = Channel.AUTH;
        return new Outbound(Channel.AUTH, serverHelloPayload);
    }

    /** 处理对方对上一条 query 的回答。 */
    public CompletableFuture<ServerStep> onAnswer(Channel channel, byte[] payload) {
        if (state == State.NEW) {
            throw new IllegalStateException("session not started");
        }
        if (state == State.DONE) {
            throw new IllegalStateException("session already finished");
        }
        if (busy) {
            throw new IllegalStateException("previous answer still in progress");
        }
        busy = true;
        CompletableFuture<ServerStep> step;
        try {
            step = dispatch(channel, payload);
        } catch (MalformedMessageException e) {
            step = done(RejectReason.PROTOCOL_ERROR);
        } catch (CryptoException e) {
            step = done(RejectReason.CRYPTO_FAILURE);
        } catch (RuntimeException e) {
            // 账号存储的线程池排满时，可能同步抛出 RejectedExecutionException 而不是返回失败的 future
            step = done(isBusy(e) ? RejectReason.SERVER_BUSY : RejectReason.INTERNAL_ERROR);
        }
        return step
                .exceptionally(t -> reject(isBusy(t) ? RejectReason.SERVER_BUSY : RejectReason.INTERNAL_ERROR))
                .thenApply(s -> {
                    busy = false;
                    return timedOut ? enforceTimeout(s) : s;
                });
    }

    private static boolean isBusy(Throwable t) {
        Throwable cause = t instanceof CompletionException && t.getCause() != null ? t.getCause() : t;
        return cause instanceof RejectedExecutionException;
    }

    /** 处理期间已超时：除已拒绝外一律改判超时，连同可能已生成的移交对象一起废弃。 */
    private ServerStep enforceTimeout(ServerStep step) {
        if (step instanceof ServerStep.Done done && done.outcome() instanceof AuthOutcome.Rejected) {
            return step;
        }
        if (step instanceof ServerStep.Done done && done.outcome() instanceof AuthOutcome.Accepted accepted) {
            accepted.handover().close();
            outcome = new AuthOutcome.Rejected(RejectReason.TIMEOUT, trusted);
            return new ServerStep.Done(outcome);
        }
        return reject(RejectReason.TIMEOUT);
    }

    /**
     * 认证总超时。若有回答仍在处理，清理工作推迟到它完成时进行，避免与其他线程争用通道。
     */
    public AuthOutcome timeout() {
        if (state == State.DONE) {
            return outcome;
        }
        timedOut = true;
        if (busy) {
            return new AuthOutcome.Rejected(RejectReason.TIMEOUT, trusted);
        }
        return ((ServerStep.Done) reject(RejectReason.TIMEOUT)).outcome();
    }

    private CompletableFuture<ServerStep> dispatch(Channel channel, byte[] payload)
            throws MalformedMessageException, CryptoException {
        if (channel != expectedChannel) {
            return done(RejectReason.PROTOCOL_ERROR);
        }
        if (payload == null) {
            return done(state == State.AWAIT_CLIENT_HELLO ? RejectReason.NO_MOD : RejectReason.PROTOCOL_ERROR);
        }
        return switch (state) {
            case AWAIT_CLIENT_HELLO -> onClientHello(payload);
            case AWAIT_PROOF -> onClientProof(payload);
            case AWAIT_PASSWORD -> onPasswordAnswer(payload);
            case AWAIT_FINISH_ACK -> onFinishAck(payload);
            case NEW, DONE -> throw new IllegalStateException("unreachable");
        };
    }

    private CompletableFuture<ServerStep> onClientHello(byte[] payload)
            throws MalformedMessageException, CryptoException {
        Message message = MessageCodec.decodePlain(Channel.AUTH, payload);
        if (!(message instanceof ClientHello hello)) {
            return done(RejectReason.PROTOCOL_ERROR);
        }
        if (!ProtocolVersion.isSupported(hello.version())) {
            return done(RejectReason.VERSION_MISMATCH);
        }
        transcript = Transcript.compute(serverHelloPayload, payload, username);
        byte[] shared = ephemeral.agree(hello.clientEphPub());
        ephemeral = null;
        keys = SessionKeys.derive(shared, serverNonce, hello.clientNonce(), transcript);
        auth = keys.authChannel(Side.SERVER);
        password = keys.passwordChannel(Side.SERVER);
        clientWantsTunnel = hello.wantTunnel();

        byte[] signature = HandshakeSignatures.signServer(identity, transcript);
        state = State.AWAIT_PROOF;
        expectedChannel = Channel.AUTH;
        return send(Channel.AUTH, auth.seal(new Challenge(identity.publicKey(), signature)));
    }

    private CompletableFuture<ServerStep> onClientProof(byte[] payload)
            throws MalformedMessageException, CryptoException {
        Message message = auth.open(payload);
        if (!(message instanceof ClientProof proof)) {
            return done(RejectReason.PROTOCOL_ERROR);
        }
        if (!HandshakeSignatures.verifyClient(proof.playerPub(), transcript, proof.playerSig())) {
            return done(RejectReason.INVALID_PROOF);
        }
        // 模型 A 的可信协议握手到此完成；账号、密码仍未验证
        trusted = true;
        playerPub = proof.playerPub();
        return accounts.find(accountId).thenCompose(this::afterLookup);
    }

    private CompletableFuture<ServerStep> afterLookup(Optional<AccountView> found) {
        if (found.isEmpty()) {
            return accounts.bindNew(accountId, username, playerPub).thenApply(bound -> {
                if (!bound) {
                    return reject(RejectReason.ACCOUNT_CONFLICT);
                }
                account = new AccountView(playerPub, true, false, false);
                return config.validation().loginPassword() ? beginPassword(PasswordRequest.Kind.SET) : finish();
            });
        }
        account = found.get();
        if (!account.keyBound()) {
            return identityVerified(RebindReason.KEY_RESET);
        }
        if (Arrays.equals(account.playerPub(), playerPub)) {
            verifiedOriginalKey = mojangVerified;
            return CompletableFuture.completedFuture(afterKeyMatched());
        }
        if (mojangVerified) {
            return identityVerified(RebindReason.ONLINE_MODE_IDENTITY);
        }
        if (config.validation().recoveryPassword() && account.hasRecoveryPassword()) {
            return CompletableFuture.completedFuture(beginPassword(PasswordRequest.Kind.RECOVERY));
        }
        return done(RejectReason.KEY_MISMATCH);
    }

    /** 公钥与绑定一致（或已找回）后的判定，PROTOCOL.md 4.6。 */
    private ServerStep afterKeyMatched() {
        if (config.validation().loginPassword() && account.hasLoginPassword()) {
            return beginPassword(PasswordRequest.Kind.LOGIN);
        }
        if (config.validation().loginPassword() && config.validation().newPlayerRestriction()
                && account.restricted()) {
            return beginPassword(PasswordRequest.Kind.SET);
        }
        return finish();
    }

    private ServerStep beginPassword(PasswordRequest.Kind kind) {
        pendingKind = kind;
        attemptsLeft = kind == PasswordRequest.Kind.SET || kind == PasswordRequest.Kind.RESET
                ? 0 : config.maxPasswordAttempts();
        return sendPasswordRequest();
    }

    private ServerStep sendPasswordRequest() {
        state = State.AWAIT_PASSWORD;
        expectedChannel = Channel.PASSWORD;
        try {
            int timeout = pendingKind == PasswordRequest.Kind.RESET
                    ? Math.min(60, config.passwordTimeoutSec()) : config.passwordTimeoutSec();
            return new ServerStep.Send(new Outbound(Channel.PASSWORD,
                    password.seal(new PasswordRequest(pendingKind, attemptsLeft, timeout))));
        } catch (CryptoException e) {
            return reject(RejectReason.CRYPTO_FAILURE);
        }
    }

    private CompletableFuture<ServerStep> onPasswordAnswer(byte[] payload)
            throws MalformedMessageException, CryptoException {
        Message message = password.open(payload);
        if (!(message instanceof PasswordAnswer answer)) {
            return done(RejectReason.PROTOCOL_ERROR);
        }
        String secret = answer.password();
        switch (pendingKind) {
            case SET:
                if (answer.action() != PasswordAnswer.Action.SUBMIT
                        && answer.action() != PasswordAnswer.Action.SKIP) {
                    return done(RejectReason.PROTOCOL_ERROR);
                }
                if (answer.skipped()) {
                    return CompletableFuture.completedFuture(finish());
                }
                return accounts.setLoginPassword(accountId, secret).thenApply(accepted -> {
                    if (accepted) {
                        account = account.withLoginPassword();
                        return finish();
                    }
                    // 不符合密码规则：重新弹出设定框；连续不符合达到上限时按跳过处理
                    setRejections++;
                    return setRejections >= config.maxPasswordAttempts() ? finish() : sendPasswordRequest();
                });
            case LOGIN:
                if (answer.action() == PasswordAnswer.Action.REQUEST_RESET) {
                    if (!answer.password().isEmpty()) {
                        return done(RejectReason.PROTOCOL_ERROR);
                    }
                    if (mojangVerified && Arrays.equals(account.playerPub(), playerPub)) {
                        return CompletableFuture.completedFuture(beginReset(RecoveryOrigin.ONLINE_SESSION_AND_KEY));
                    }
                    if (config.validation().recoveryPassword() && account.hasRecoveryPassword()) {
                        recoveryForPasswordReset = true;
                        return CompletableFuture.completedFuture(beginPassword(PasswordRequest.Kind.RECOVERY));
                    }
                    return done(RejectReason.KEY_MISMATCH);
                }
                if (answer.action() != PasswordAnswer.Action.SUBMIT) {
                    return done(RejectReason.PROTOCOL_ERROR);
                }
                return accounts.verifyLoginPassword(accountId, secret)
                        .thenCompose(ok -> ok ? loginSucceeded() : passwordFailed());
            case RECOVERY:
                if (answer.action() != PasswordAnswer.Action.SUBMIT
                        && answer.action() != PasswordAnswer.Action.REQUEST_RESET) {
                    return done(RejectReason.PROTOCOL_ERROR);
                }
                return accounts.verifyRecoveryPassword(accountId, secret)
                        .thenCompose(ok -> {
                            if (!ok) return passwordFailed();
                            return answer.action() == PasswordAnswer.Action.REQUEST_RESET || recoveryForPasswordReset
                                    ? CompletableFuture.completedFuture(beginReset(RecoveryOrigin.RECOVERY_PASSWORD))
                                    : identityVerified(RebindReason.RECOVERY);
                        });
            case RESET:
                if (answer.action() != PasswordAnswer.Action.SUBMIT
                        && answer.action() != PasswordAnswer.Action.CLEAR) {
                    return done(RejectReason.PROTOCOL_ERROR);
                }
                return applyReset(answer);
        }
        throw new IllegalStateException("unreachable password kind: " + pendingKind);
    }

    private ServerStep beginReset(RecoveryOrigin origin) {
        if (!account.keyBound()) {
            return reject(RejectReason.ACCOUNT_CONFLICT);
        }
        resetGrant = new ResetGrant(origin, account.playerPub(), playerPub, transcript,
                clock.millis() + 60_000L);
        recoveryForPasswordReset = false;
        setRejections = 0;
        pendingKind = PasswordRequest.Kind.RESET;
        attemptsLeft = 0;
        return sendPasswordRequest();
    }

    private CompletableFuture<ServerStep> applyReset(PasswordAnswer answer) {
        ResetGrant grant = resetGrant;
        if (grant == null || clock.millis() >= grant.expiresAt()
                || !Arrays.equals(grant.newPub(), playerPub)
                || !Arrays.equals(grant.transcript(), transcript)) {
            resetGrant = null;
            return done(RejectReason.TIMEOUT);
        }
        PasswordChange change = answer.action() == PasswordAnswer.Action.CLEAR
                ? PasswordChange.CLEAR : PasswordChange.SET;
        return accounts.recoverAccount(accountId, grant.expectedOldPub(), grant.newPub(), change,
                answer.password(), grant.origin()).thenApply(result -> {
                    if (result == RecoveryResult.ACCOUNT_CONFLICT) {
                        resetGrant = null;
                        return reject(RejectReason.ACCOUNT_CONFLICT);
                    }
                    if (result == RecoveryResult.PASSWORD_REJECTED) {
                        setRejections++;
                        if (setRejections >= config.maxPasswordAttempts()) {
                            resetGrant = null;
                            return reject(RejectReason.PASSWORD_ATTEMPTS_EXHAUSTED);
                        }
                        return sendPasswordRequest();
                    }
                    resetGrant = null;
                    account = account.withPlayerPub(playerPub);
                    account = change == PasswordChange.SET
                            ? account.withLoginPassword() : account.withoutLoginPassword();
                    if (grant.origin() == RecoveryOrigin.RECOVERY_PASSWORD
                            && !Arrays.equals(grant.expectedOldPub(), grant.newPub())) {
                        rebound = RebindReason.RECOVERY;
                    }
                    return finish();
                });
    }

    /**
     * 身份已确认（找回密码正确，或正版 session），准备改绑到本次的公钥。
     * 已设登录密码时先验证登录密码，改绑推迟到它通过之后。
     */
    private CompletableFuture<ServerStep> identityVerified(RebindReason reason) {
        if (config.validation().loginPassword() && account.hasLoginPassword()) {
            pendingRebind = reason;
            return CompletableFuture.completedFuture(beginPassword(PasswordRequest.Kind.LOGIN));
        }
        return commitRebind(reason).thenApply(bound -> bound ? afterKeyMatched() : reject(RejectReason.ACCOUNT_CONFLICT));
    }

    private CompletableFuture<ServerStep> loginSucceeded() {
        if (pendingRebind == null) {
            return CompletableFuture.completedFuture(finish());
        }
        RebindReason reason = pendingRebind;
        pendingRebind = null;
        return commitRebind(reason).thenApply(bound -> bound ? finish() : reject(RejectReason.ACCOUNT_CONFLICT));
    }

    /** 提交改绑；管理员重置和找回路径需要确认绑定仍与开始认证时一致。 */
    private CompletableFuture<Boolean> commitRebind(RebindReason reason) {
        CompletableFuture<Boolean> committed = switch (reason) {
            case KEY_RESET -> accounts.claimUnboundKey(accountId, playerPub);
            case RECOVERY -> accounts.rebindRecoveredKey(accountId, account.playerPub(), playerPub);
            case ONLINE_MODE_IDENTITY -> accounts.rebindOnline(accountId, playerPub).thenApply(v -> true);
        };
        return committed.thenApply(bound -> {
            if (bound) {
                account = account.withPlayerPub(playerPub);
                rebound = reason;
            }
            return bound;
        });
    }

    private CompletableFuture<ServerStep> passwordFailed() {
        attemptsLeft--;
        boolean exhausted = attemptsLeft == 0;
        return accounts.passwordFailed(accountId, pendingKind, exhausted)
                .thenApply(v -> exhausted ? reject(RejectReason.PASSWORD_ATTEMPTS_EXHAUSTED) : sendPasswordRequest());
    }

    private ServerStep finish() {
        tunnel = config.tunnelFor(clientWantsTunnel);
        state = State.AWAIT_FINISH_ACK;
        expectedChannel = Channel.AUTH;
        try {
            return new ServerStep.Send(new Outbound(Channel.AUTH,
                    auth.seal(new Finish(tunnel, config.noticesFor(account, rebound != null)))));
        } catch (CryptoException e) {
            return reject(RejectReason.CRYPTO_FAILURE);
        }
    }

    private CompletableFuture<ServerStep> onFinishAck(byte[] payload)
            throws MalformedMessageException, CryptoException {
        Message message = auth.open(payload);
        if (!(message instanceof FinishAck)) {
            return done(RejectReason.PROTOCOL_ERROR);
        }
        SessionHandover handover = SessionHandover.create(keys, Side.SERVER, password, tunnel);
        outcome = new AuthOutcome.Accepted(accountId, username, playerPub,
                config.validation().newPlayerRestriction() && account.restricted(),
                account.hasLoginPassword(), account.hasRecoveryPassword(), verifiedOriginalKey,
                config.noticesFor(account, rebound != null),
                Optional.ofNullable(rebound), handover);
        state = State.DONE;
        resetGrant = null;
        auth.close();
        keys.destroy();
        return CompletableFuture.completedFuture(new ServerStep.Done(outcome));
    }

    private CompletableFuture<ServerStep> send(Channel channel, byte[] payload) {
        return CompletableFuture.completedFuture(new ServerStep.Send(new Outbound(channel, payload)));
    }

    private CompletableFuture<ServerStep> done(RejectReason reason) {
        return CompletableFuture.completedFuture(reject(reason));
    }

    /** 拒绝并废弃本连接的所有通道与密钥。已结束时返回原结果。 */
    private ServerStep reject(RejectReason reason) {
        if (state != State.DONE) {
            outcome = new AuthOutcome.Rejected(reason, trusted);
            state = State.DONE;
            ephemeral = null;
            if (auth != null) {
                auth.close();
                password.close();
            }
            if (keys != null) {
                keys.destroy();
            }
            resetGrant = null;
        }
        return new ServerStep.Done(outcome);
    }
}
