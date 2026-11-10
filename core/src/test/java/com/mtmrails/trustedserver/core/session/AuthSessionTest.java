package com.mtmrails.trustedserver.core.session;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mtmrails.trustedserver.core.ProtocolVersion;
import com.mtmrails.trustedserver.core.crypto.Ed25519;
import com.mtmrails.trustedserver.core.crypto.HandshakeSignatures;
import com.mtmrails.trustedserver.core.crypto.SecureMessageChannel;
import com.mtmrails.trustedserver.core.crypto.SessionKeys;
import com.mtmrails.trustedserver.core.crypto.Side;
import com.mtmrails.trustedserver.core.crypto.Transcript;
import com.mtmrails.trustedserver.core.crypto.X25519;
import com.mtmrails.trustedserver.core.message.Channel;
import com.mtmrails.trustedserver.core.message.ClientHello;
import com.mtmrails.trustedserver.core.message.ClientProof;
import com.mtmrails.trustedserver.core.message.Message;
import com.mtmrails.trustedserver.core.message.MessageCodec;
import com.mtmrails.trustedserver.core.message.PasswordRequest;
import com.mtmrails.trustedserver.core.message.PasswordAnswer;
import com.mtmrails.trustedserver.core.message.PasswordResult;
import com.mtmrails.trustedserver.core.message.ServerHello;
import com.mtmrails.trustedserver.core.message.SetPassword;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuthSessionTest {
    private static final ServerAuthConfig CONFIG = ServerAuthConfig.allValidationDefaults();
    private Ed25519.KeyPairData serverIdentity;
    private InMemoryAccounts accounts;
    private TestClientEnvironment env;

    @BeforeEach
    void setUp() {
        serverIdentity = Ed25519.generate(new SecureRandom());
        accounts = new InMemoryAccounts();
        env = new TestClientEnvironment();
    }

    private Handshake handshake() {
        return new Handshake(serverIdentity, accounts, env);
    }

    /** 预先生成客户端在本服务器上的玩家公钥，用于构造已存在的账号。 */
    private byte[] clientKey() {
        return env.playerKey(serverIdentity.publicKey(), "Steve").join().publicKey();
    }

    private static List<PasswordRequest.Kind> kinds(TestClientEnvironment env) {
        return env.prompts.stream().map(PasswordRequest::kind).toList();
    }

    // ================= 新用户 =================

    @Test
    void newUserSettingPasswordBeforeEnteringIsNotRestricted() {
        env.answer("hunter2");
        Handshake h = handshake().run();

        AuthOutcome.Accepted accepted = h.accepted();
        assertFalse(accepted.restricted());
        assertTrue(accepted.hasLoginPassword());
        assertEquals(List.of(PasswordRequest.Kind.SET), kinds(env));
        assertEquals(0, env.prompts.get(0).attemptsLeft());
        assertEquals("hunter2", accounts.accounts.get("steve").loginPassword);
        assertFalse(accounts.accounts.get("steve").restricted);
        assertArrayEquals(h.clientPublicKey(), accounts.accounts.get("steve").playerPub);
        // 只剩“未设找回密码”提醒
        assertEquals(List.of(CONFIG.recoveryReminderNotice()), accepted.notices());
        assertEquals(accepted.notices(), h.clientResult().notices());
    }

    @Test
    void newUserSkippingStaysRestricted() {
        env.answer((String) null);
        Handshake h = handshake().run();

        AuthOutcome.Accepted accepted = h.accepted();
        assertTrue(accepted.restricted());
        assertFalse(accepted.hasLoginPassword());
        assertTrue(accounts.accounts.get("steve").restricted);
        assertEquals(List.of(CONFIG.restrictedNotice(), CONFIG.recoveryReminderNotice()), h.clientResult().notices());
    }

    @Test
    void ed25519OnlySkipsAllOptionalAccountChecks() {
        Handshake h = handshake();
        h.config = new ServerAuthConfig(ServerAuthConfig.TunnelPolicy.DISABLED,
                new ServerAuthConfig.ValidationLevels(true, false, false, false),
                3, 60, CONFIG.restrictedNotice(), CONFIG.recoveryReminderNotice(), CONFIG.rebindNotice());
        h.run();

        assertFalse(h.accepted().restricted());
        assertTrue(env.prompts.isEmpty());
        assertTrue(h.accepted().notices().isEmpty());
        assertArrayEquals(h.clientPublicKey(), accounts.accounts.get("steve").playerPub);
    }

    @Test
    void restrictedUserIsPromptedToSetPasswordOnEveryLogin() {
        env.answer((String) null);
        handshake().run().accepted();
        env.answer("now-set");
        Handshake second = handshake().run();
        assertFalse(second.accepted().restricted());
        assertEquals(List.of(PasswordRequest.Kind.SET, PasswordRequest.Kind.SET), kinds(env));
    }

    @Test
    void lostBindRaceIsRejected() {
        accounts.loseBindRace = true;
        Handshake h = handshake().run();
        assertEquals(new AuthOutcome.Rejected(RejectReason.ACCOUNT_CONFLICT, true), h.rejected());
    }

    // ================= 老用户 =================

    @Test
    void unrestrictedUserWithoutPasswordEntersDirectly() {
        accounts.put("steve", clientKey(), false, null, "recovery");
        Handshake h = handshake().run();
        AuthOutcome.Accepted accepted = h.accepted();
        assertTrue(env.prompts.isEmpty());
        assertEquals(List.of(), accepted.notices());
        assertEquals(List.of(Channel.AUTH, Channel.AUTH, Channel.AUTH), h.queryChannels);
    }

    @Test
    void optionalLoginPasswordDoesNotRejectAccountWithoutPassword() {
        accounts.put("steve", clientKey(), true, null, null);
        Handshake h = handshake();
        h.config = new ServerAuthConfig(ServerAuthConfig.TunnelPolicy.DISABLED,
                new ServerAuthConfig.ValidationLevels(true, true, false, false),
                3, 60, CONFIG.restrictedNotice(), CONFIG.recoveryReminderNotice(), CONFIG.rebindNotice());
        h.run();

        assertTrue(env.prompts.isEmpty());
        assertFalse(h.accepted().hasLoginPassword());
        assertFalse(h.accepted().restricted());
    }

    @Test
    void correctLoginPassword() {
        accounts.put("steve", clientKey(), false, "pw", null);
        env.answer("pw");
        Handshake h = handshake().run();
        assertTrue(h.accepted().hasLoginPassword());
        assertEquals(List.of(PasswordRequest.Kind.LOGIN), kinds(env));
        assertEquals(CONFIG.maxPasswordAttempts(), env.prompts.get(0).attemptsLeft());
        assertEquals(CONFIG.passwordTimeoutSec(), env.prompts.get(0).timeoutSec());
        assertTrue(accounts.failures.isEmpty());
    }

    @Test
    void wrongThenCorrectLoginPassword() {
        accounts.put("steve", clientKey(), false, "pw", null);
        env.answer("nope", "pw");
        handshake().run().accepted();
        assertEquals(List.of(3, 2), env.prompts.stream().map(PasswordRequest::attemptsLeft).toList());
        assertEquals(List.of(new InMemoryAccounts.Failure("steve", PasswordRequest.Kind.LOGIN, false)),
                accounts.failures);
    }

    @Test
    void loginAttemptsExhaustedLocksAndRejects() {
        accounts.put("steve", clientKey(), false, "pw", null);
        env.answer("a", "b", "c");
        Handshake h = handshake().run();
        assertEquals(new AuthOutcome.Rejected(RejectReason.PASSWORD_ATTEMPTS_EXHAUSTED, true), h.rejected());
        assertEquals(3, accounts.failures.size());
        assertTrue(accounts.failures.get(2).exhausted());
        assertFalse(accounts.failures.get(1).exhausted());
    }

    @Test
    void cancellingLoginPromptAbortsOnClient() {
        accounts.put("steve", clientKey(), false, "pw", null);
        env.answer((String) null);
        Handshake h = handshake().run();
        assertEquals(ClientFailure.Kind.USER_CANCELLED, h.clientFailure().kind());
        assertEquals(RejectReason.TIMEOUT, h.rejected().reason());
    }

    // ================= 密钥不匹配与找回 =================

    private byte[] otherKey() {
        return Ed25519.generate(new SecureRandom()).publicKey();
    }

    @Test
    void keyMismatchWithoutRecoveryIsRejectedAfterTrustedHandshake() {
        byte[] original = otherKey();
        accounts.put("steve", original, false, "pw", null);
        Handshake h = handshake().run();
        assertEquals(new AuthOutcome.Rejected(RejectReason.KEY_MISMATCH, true), h.rejected());
        assertTrue(env.prompts.isEmpty());
        assertArrayEquals(original, accounts.accounts.get("steve").playerPub);
    }

    @Test
    void recoveryRebindsWhenNoLoginPassword() {
        accounts.put("steve", otherKey(), false, null, "rec");
        env.answer("rec");
        Handshake h = handshake().run();
        h.accepted();
        assertEquals(List.of(PasswordRequest.Kind.RECOVERY), kinds(env));
        assertArrayEquals(h.clientPublicKey(), accounts.accounts.get("steve").playerPub);
    }

    @Test
    void recoveryThenLoginPasswordRebinds() {
        accounts.put("steve", otherKey(), false, "pw", "rec");
        env.answer("rec", "pw");
        Handshake h = handshake().run();
        h.accepted();
        assertEquals(List.of(PasswordRequest.Kind.RECOVERY, PasswordRequest.Kind.LOGIN), kinds(env));
        assertArrayEquals(h.clientPublicKey(), accounts.accounts.get("steve").playerPub);
        assertEquals(List.of("steve"), accounts.rebinds);
        assertEquals(List.of(RebindReason.RECOVERY), accounts.rebindReasons);
        assertEquals(java.util.Optional.of(RebindReason.RECOVERY), h.accepted().reboundBy());
        assertEquals(CONFIG.rebindNotice(), h.clientResult().notices().get(0));
    }

    @Test
    void recoveryKeepingPasswordRejectsConcurrentRebind() {
        byte[] original = otherKey();
        accounts.put("steve", original, false, "pw", "rec");
        accounts.loseRecoveryRace = true;
        env.answer("rec", "pw");
        assertEquals(RejectReason.ACCOUNT_CONFLICT, handshake().run().rejected().reason());
        assertArrayEquals(original, accounts.accounts.get("steve").playerPub);
    }

    @Test
    void recoveryWithWrongLoginPasswordDoesNotRebind() {
        byte[] original = otherKey();
        accounts.put("steve", original, false, "pw", "rec");
        env.answer("rec", "x", "y", "z");
        Handshake h = handshake().run();
        assertEquals(RejectReason.PASSWORD_ATTEMPTS_EXHAUSTED, h.rejected().reason());
        assertArrayEquals(original, accounts.accounts.get("steve").playerPub);
        assertTrue(accounts.rebinds.isEmpty());
        // 找回成功后登录密码重新获得完整次数
        assertEquals(List.of(3, 3, 2, 1), env.prompts.stream().map(PasswordRequest::attemptsLeft).toList());
    }

    @Test
    void offlineNewDeviceCanUseRecoveryPasswordToResetLoginPassword() {
        byte[] original = otherKey();
        accounts.put("steve", original, false, "old-password", "recovery-secret");
        env.respond(new PasswordAnswer(PasswordAnswer.Action.REQUEST_RESET, "recovery-secret"));
        env.answer("new-password");

        Handshake h = handshake().run();
        assertEquals(List.of(PasswordRequest.Kind.RECOVERY, PasswordRequest.Kind.RESET), kinds(env));
        assertArrayEquals(h.clientPublicKey(), accounts.accounts.get("steve").playerPub);
        assertEquals("new-password", accounts.accounts.get("steve").loginPassword);
        assertEquals(java.util.Optional.of(RebindReason.RECOVERY), h.accepted().reboundBy());
    }

    @Test
    void offlineRecoveryCanClearLoginPassword() {
        accounts.put("steve", otherKey(), false, "old-password", "recovery-secret");
        env.respond(new PasswordAnswer(PasswordAnswer.Action.REQUEST_RESET, "recovery-secret"),
                PasswordAnswer.clear());

        Handshake h = handshake().run();
        assertEquals(List.of(PasswordRequest.Kind.RECOVERY, PasswordRequest.Kind.RESET), kinds(env));
        assertNull(accounts.accounts.get("steve").loginPassword);
        assertTrue(accounts.accounts.get("steve").restricted);
        assertTrue(h.accepted().restricted());
    }

    @Test
    void offlineMatchingDeviceNeedsRecoveryPasswordBeforeReset() {
        accounts.put("steve", clientKey(), false, "old-password", "recovery-secret");
        env.respond(PasswordAnswer.requestReset());
        env.answer("recovery-secret", "new-password");

        Handshake h = handshake().run();
        assertEquals(List.of(PasswordRequest.Kind.LOGIN, PasswordRequest.Kind.RECOVERY,
                PasswordRequest.Kind.RESET), kinds(env));
        assertEquals("new-password", accounts.accounts.get("steve").loginPassword);
        assertTrue(h.accepted().reboundBy().isEmpty());
    }

    @Test
    void recoveryResetConflictKeepsOriginalAccount() {
        byte[] original = otherKey();
        accounts.put("steve", original, false, "old-password", "recovery-secret");
        accounts.loseRecoveryRace = true;
        env.respond(new PasswordAnswer(PasswordAnswer.Action.REQUEST_RESET, "recovery-secret"));
        env.answer("new-password");

        Handshake h = handshake().run();
        assertEquals(RejectReason.ACCOUNT_CONFLICT, h.rejected().reason());
        assertArrayEquals(original, accounts.accounts.get("steve").playerPub);
        assertEquals("old-password", accounts.accounts.get("steve").loginPassword);
    }

    @Test
    void resetGrantExpiresAfterSixtySeconds() {
        accounts.put("steve", otherKey(), false, "old-password", "recovery-secret");
        env.respond(new PasswordAnswer(PasswordAnswer.Action.REQUEST_RESET, "recovery-secret"));
        env.answer("new-password");
        AtomicLong now = new AtomicLong(1_000);
        Handshake h = handshake();
        h.clock = new Clock() {
            @Override public ZoneId getZone() { return ZoneId.of("UTC"); }
            @Override public Clock withZone(ZoneId zone) { return this; }
            @Override public Instant instant() { return Instant.ofEpochMilli(now.get()); }
            @Override public long millis() { return now.get(); }
        };
        env.onPrompt = request -> {
            if (request.kind() == PasswordRequest.Kind.RESET) now.addAndGet(60_001);
        };

        assertEquals(RejectReason.TIMEOUT, h.run().rejected().reason());
        assertEquals("old-password", accounts.accounts.get("steve").loginPassword);
    }

    @Test
    void wrongRecoveryPasswordExhausts() {
        byte[] original = otherKey();
        accounts.put("steve", original, false, null, "rec");
        env.answer("1", "2", "3");
        Handshake h = handshake().run();
        assertEquals(RejectReason.PASSWORD_ATTEMPTS_EXHAUSTED, h.rejected().reason());
        assertEquals(PasswordRequest.Kind.RECOVERY, accounts.failures.get(2).kind());
        assertArrayEquals(original, accounts.accounts.get("steve").playerPub);
    }

    @Test
    void recoveredRestrictedAccountIsAskedToSetPassword() {
        accounts.put("steve", otherKey(), true, null, "rec");
        env.answer("rec", "fresh");
        Handshake h = handshake().run();
        assertFalse(h.accepted().restricted());
        assertEquals(List.of(PasswordRequest.Kind.RECOVERY, PasswordRequest.Kind.SET), kinds(env));
    }

    // ================= 正版模式：Mojang 验证保证连接可信，玩家认证保留 =================

    private Handshake onlineHandshake() {
        Handshake h = handshake();
        h.onlineMode = true;
        h.mojangVerified = true;
        h.accountId = "069a79f4-44e9-4726-a5be-fca90e38aaf5"; // 正版按 UUID 记录
        return h;
    }

    /** 正版服务器上 session 无效，按无验证回退。 */
    private Handshake invalidSessionHandshake() {
        Handshake h = onlineHandshake();
        h.mojangVerified = false;
        return h;
    }

    @Test
    void invalidSessionFallsBackToUnverifiedRules() {
        byte[] original = otherKey();
        accounts.put(UUID, original, false, null, null);
        Handshake h = invalidSessionHandshake().run();
        assertEquals(new AuthOutcome.Rejected(RejectReason.KEY_MISMATCH, true), h.rejected());
        assertArrayEquals(original, accounts.accounts.get(UUID).playerPub);
    }

    @Test
    void invalidSessionCanStillRecoverWithRecoveryPassword() {
        accounts.put(UUID, otherKey(), false, null, "rec");
        env.answer("rec");
        Handshake h = invalidSessionHandshake().run();
        assertEquals(List.of(PasswordRequest.Kind.RECOVERY), kinds(env));
        assertEquals(java.util.Optional.of(RebindReason.RECOVERY), h.accepted().reboundBy());
    }

    @Test
    void invalidSessionWithMatchingKeyIsAccepted() {
        accounts.put(UUID, clientKey(), false, null, "rec");
        var accepted = invalidSessionHandshake().run().accepted();
        assertTrue(accepted.reboundBy().isEmpty());
        assertFalse(accepted.verifiedOriginalKey());
        assertTrue(ServerAuthConfig.ValidationLevels.DEFAULT.suspendOp(false, false, accepted.verifiedOriginalKey()));
    }

    @Test
    void offlineServerCannotClaimMojangVerification() {
        assertThrows(IllegalArgumentException.class, () -> new ServerAuthSession("steve", "Steve", false, true,
                CONFIG, serverIdentity, accounts, new SecureRandom()));
    }

    private static final String UUID = "069a79f4-44e9-4726-a5be-fca90e38aaf5";

    @Test
    void onlineModeNewDeviceIsRebasedWithoutRecoveryPassword() {
        byte[] original = otherKey();
        accounts.put(UUID, original, false, null, null); // 没有找回密码：离线模式下会被拒绝
        Handshake h = onlineHandshake().run();
        AuthOutcome.Accepted accepted = h.accepted();
        assertEquals(java.util.Optional.of(RebindReason.ONLINE_MODE_IDENTITY), accepted.reboundBy());
        assertFalse(accepted.verifiedOriginalKey());
        assertArrayEquals(h.clientPublicKey(), accounts.accounts.get(UUID).playerPub);
        assertEquals(List.of(RebindReason.ONLINE_MODE_IDENTITY), accounts.rebindReasons);
        assertTrue(env.prompts.isEmpty());
        // 下发更新认证：客户端在 Finish 中收到改绑提示
        assertEquals(CONFIG.rebindNotice(), h.clientResult().notices().get(0));
    }

    @Test
    void onlineModeStillRequiresLoginPasswordBeforeRebind() {
        accounts.put(UUID, otherKey(), false, "pw", null);
        env.answer("pw");
        Handshake h = onlineHandshake().run();
        assertEquals(List.of(PasswordRequest.Kind.LOGIN), kinds(env));
        assertArrayEquals(h.clientPublicKey(), accounts.accounts.get(UUID).playerPub);
        assertEquals(java.util.Optional.of(RebindReason.ONLINE_MODE_IDENTITY), h.accepted().reboundBy());
    }

    @Test
    void onlineModeWrongLoginPasswordKeepsOriginalBinding() {
        byte[] original = otherKey();
        accounts.put(UUID, original, false, "pw", null);
        env.answer("a", "b", "c");
        Handshake h = onlineHandshake().run();
        assertEquals(new AuthOutcome.Rejected(RejectReason.PASSWORD_ATTEMPTS_EXHAUSTED, true), h.rejected());
        assertArrayEquals(original, accounts.accounts.get(UUID).playerPub);
        assertTrue(accounts.rebinds.isEmpty());
    }

    @Test
    void onlineModeRestrictedAccountIsStillAskedToSetPassword() {
        accounts.put(UUID, otherKey(), true, null, null);
        env.answer((String) null);
        Handshake h = onlineHandshake().run();
        assertEquals(List.of(PasswordRequest.Kind.SET), kinds(env));
        assertTrue(h.accepted().restricted());
        assertEquals(List.of(CONFIG.rebindNotice(), CONFIG.restrictedNotice(), CONFIG.recoveryReminderNotice()),
                h.clientResult().notices());
    }

    @Test
    void onlineModeMatchingKeyIsNotRebound() {
        accounts.put(UUID, clientKey(), false, null, "rec");
        Handshake h = onlineHandshake().run();
        assertTrue(h.accepted().reboundBy().isEmpty());
        assertTrue(h.accepted().verifiedOriginalKey());
        assertFalse(ServerAuthConfig.ValidationLevels.DEFAULT.suspendOp(false, false, h.accepted().verifiedOriginalKey()));
        assertTrue(accounts.rebinds.isEmpty());
        assertEquals(List.of(), h.clientResult().notices());
    }

    @Test
    void opExemptionAppliesOnlyToTheAlreadyBoundKeyAndRespectsRestrictionAndStrictMode() {
        accounts.put(UUID, clientKey(), true, null, "rec");
        env.answer((String) null);
        var accepted = onlineHandshake().run().accepted();
        assertTrue(accepted.verifiedOriginalKey());
        assertTrue(accepted.restricted());
        var defaults = ServerAuthConfig.ValidationLevels.DEFAULT;
        assertTrue(defaults.suspendOp(accepted.restricted(), false, accepted.verifiedOriginalKey()));
        assertFalse(defaults.suspendOp(false, true, false));
        assertTrue(ServerAuthConfig.ValidationLevels.ALL.suspendOp(false, false, true));
        assertFalse(ServerAuthConfig.ValidationLevels.ALL.suspendOp(false, true, true));
    }

    @Test
    void onlineSessionAndOriginalKeyCanResetPassword() {
        accounts.put(UUID, clientKey(), false, "old-password", "recovery-secret");
        env.respond(PasswordAnswer.requestReset());
        env.answer("new-password");

        Handshake h = onlineHandshake().run();
        assertEquals(List.of(PasswordRequest.Kind.LOGIN, PasswordRequest.Kind.RESET), kinds(env));
        assertEquals("new-password", accounts.accounts.get(UUID).loginPassword);
        assertTrue(h.accepted().reboundBy().isEmpty());
        assertTrue(accounts.rebinds.isEmpty());
    }

    @Test
    void onlineSessionWithNewDeviceCannotUseFastPasswordReset() {
        byte[] original = otherKey();
        accounts.put(UUID, original, false, "old-password", null);
        env.respond(PasswordAnswer.requestReset());

        Handshake h = onlineHandshake().run();
        assertEquals(RejectReason.KEY_MISMATCH, h.rejected().reason());
        assertArrayEquals(original, accounts.accounts.get(UUID).playerPub);
        assertEquals("old-password", accounts.accounts.get(UUID).loginPassword);
    }

    @Test
    void offlineModeMismatchStillNeedsRecovery() {
        accounts.put("steve", otherKey(), false, null, null);
        Handshake h = handshake().run(); // 离线模式
        assertEquals(new AuthOutcome.Rejected(RejectReason.KEY_MISMATCH, true), h.rejected());
        assertTrue(accounts.rebinds.isEmpty());
    }

    // ================= 管理员清空绑定、密码规则、繁忙 =================

    @Test
    void resetKeyAccountBindsNewDeviceAndKeepsRestriction() {
        accounts.put("steve", null, true, null, "rec");
        env.answer((String) null);
        Handshake h = handshake().run();
        AuthOutcome.Accepted accepted = h.accepted();
        assertEquals(java.util.Optional.of(RebindReason.KEY_RESET), accepted.reboundBy());
        assertTrue(accepted.restricted());
        assertArrayEquals(h.clientPublicKey(), accounts.accounts.get("steve").playerPub);
        assertEquals(List.of(PasswordRequest.Kind.SET), kinds(env));
    }

    @Test
    void resetKeyAccountWithPasswordRequiresItBeforeBinding() {
        accounts.put("steve", null, false, "secret", null);
        env.answer("bad1", "bad2", "bad3");
        Handshake h = handshake().run();
        assertEquals(RejectReason.PASSWORD_ATTEMPTS_EXHAUSTED, h.rejected().reason());
        assertEquals(null, accounts.accounts.get("steve").playerPub);

        env.answer("secret");
        Handshake second = handshake().run();
        assertEquals(java.util.Optional.of(RebindReason.KEY_RESET), second.accepted().reboundBy());
        assertArrayEquals(second.clientPublicKey(), accounts.accounts.get("steve").playerPub);
    }

    @Test
    void resetKeyClaimLostToConcurrentConnection() {
        accounts.put("steve", null, false, null, null);
        accounts.loseBindRace = true;
        assertEquals(new AuthOutcome.Rejected(RejectReason.ACCOUNT_CONFLICT, true), handshake().run().rejected());
    }

    @Test
    void setPasswordViolatingPolicyIsPromptedAgain() {
        accounts.minPasswordLength = 6;
        env.answer("short", "long-enough");
        Handshake h = handshake().run();
        assertFalse(h.accepted().restricted());
        assertEquals(List.of(PasswordRequest.Kind.SET, PasswordRequest.Kind.SET), kinds(env));
        assertEquals("long-enough", accounts.accounts.get("steve").loginPassword);
    }

    @Test
    void repeatedPolicyViolationsFallBackToSkip() {
        accounts.minPasswordLength = 6;
        env.answer("a", "b", "c");
        Handshake h = handshake().run();
        assertTrue(h.accepted().restricted());
        assertEquals(3, env.prompts.size());
    }

    @Test
    void fullHashingQueueIsServerBusy() {
        accounts = new InMemoryAccounts(task -> {
            throw new java.util.concurrent.RejectedExecutionException("queue full");
        });
        Handshake h = handshake().run();
        assertEquals(new AuthOutcome.Rejected(RejectReason.SERVER_BUSY, true), h.rejected());
    }

    // ================= 版本协商 =================

    private static byte[] rewriteServerHello(byte[] payload, java.util.function.UnaryOperator<ServerHello> f) {
        try {
            return MessageCodec.encodePlain(f.apply((ServerHello) MessageCodec.decodePlain(Channel.AUTH, payload)));
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    @Test
    void noCommonVersion() {
        Handshake h = handshake();
        h.toClient = (c, p) -> h.queryChannels.size() == 1 ? rewriteServerHello(p,
                s -> new ServerHello(new int[] {99}, s.serverEphPub(), s.serverNonce(), s.features(), s.onlineMode()))
                : p;
        h.run();
        assertEquals(ClientFailure.Kind.VERSION_MISMATCH, h.clientFailure().kind());
        assertTrue(h.clientFailure().detail().contains("99"));
        assertEquals(new AuthOutcome.Rejected(RejectReason.VERSION_MISMATCH, false), h.rejected());
    }

    @Test
    void clientOfferingUnsupportedVersionIsRejected() {
        Handshake h = handshake();
        h.toServer = (c, p) -> {
            if (h.queryChannels.size() != 1) {
                return p;
            }
            try {
                ClientHello hello = (ClientHello) MessageCodec.decodePlain(Channel.AUTH, p);
                return MessageCodec.encodePlain(
                        new ClientHello(7, hello.clientEphPub(), hello.clientNonce(), hello.wantTunnel()));
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        };
        h.run();
        assertEquals(new AuthOutcome.Rejected(RejectReason.VERSION_MISMATCH, false), h.rejected());
    }

    // ================= 隧道协商 =================

    private Handshake tunnelCase(ServerAuthConfig.TunnelPolicy policy, boolean want) {
        accounts.put("steve", clientKey(), false, null, "rec");
        Handshake h = handshake();
        h.config = new ServerAuthConfig(policy, 3, 60, CONFIG.restrictedNotice(), CONFIG.recoveryReminderNotice(),
                CONFIG.rebindNotice());
        h.wantTunnel = want;
        return h.run();
    }

    @Test
    void tunnelNegotiation() {
        assertTrue(tunnelCase(ServerAuthConfig.TunnelPolicy.OPTIONAL, true).accepted().tunnel());
        setUp();
        assertFalse(tunnelCase(ServerAuthConfig.TunnelPolicy.OPTIONAL, false).accepted().tunnel());
        setUp();
        assertTrue(tunnelCase(ServerAuthConfig.TunnelPolicy.REQUIRED, false).accepted().tunnel());
        setUp();
        assertFalse(tunnelCase(ServerAuthConfig.TunnelPolicy.DISABLED, true).accepted().tunnel());
    }

    @Test
    void tunnelStreamsInteroperate() throws Exception {
        Handshake h = tunnelCase(ServerAuthConfig.TunnelPolicy.OPTIONAL, true);
        var serverHandover = h.accepted().handover();
        var clientHandover = h.clientResult().handover();
        assertTrue(h.clientResult().tunnel());
        byte[] aad = {1, 2};
        byte[] frame = serverHandover.tunnelSealer().orElseThrow().seal(aad, new byte[] {7});
        assertArrayEquals(new byte[] {7}, clientHandover.tunnelOpener().orElseThrow().open(aad, frame));
        byte[] back = clientHandover.tunnelSealer().orElseThrow().seal(aad, new byte[] {8});
        assertArrayEquals(new byte[] {8}, serverHandover.tunnelOpener().orElseThrow().open(aad, back));
    }

    @Test
    void noTunnelMeansNoTunnelStreams() {
        Handshake h = tunnelCase(ServerAuthConfig.TunnelPolicy.OPTIONAL, false);
        assertTrue(h.accepted().handover().tunnelSealer().isEmpty());
        assertTrue(h.clientResult().handover().tunnelOpener().isEmpty());
    }

    // ================= 密码通道移交到游戏阶段 =================

    @Test
    void passwordChannelContinuesIntoPlayPhase() throws Exception {
        env.answer("first");
        Handshake h = handshake().run();
        SecureMessageChannel server = h.accepted().handover().passwordChannel();
        SecureMessageChannel client = h.clientResult().handover().passwordChannel();
        assertEquals(new SetPassword("second"), server.open(client.seal(new SetPassword("second"))));
        PasswordResult result = (PasswordResult) client.open(server.seal(new PasswordResult(PasswordResult.Status.OK, "")));
        assertEquals(PasswordResult.Status.OK, result.status());
    }

    // ================= 中间人与篡改 =================

    @Test
    void mitmReplacingServerEphemeralKeyIsDetectedBeforeAnyPassword() {
        byte[] attackerEph = X25519.generate(new SecureRandom()).publicKey();
        Handshake h = handshake();
        h.toClient = (c, p) -> h.queryChannels.size() == 1 ? rewriteServerHello(p,
                s -> new ServerHello(s.versions(), attackerEph, s.serverNonce(), s.features(), s.onlineMode())) : p;
        h.run();
        assertEquals(ClientFailure.Kind.CRYPTO_FAILURE, h.clientFailure().kind());
        assertTrue(env.prompts.isEmpty());
        assertTrue(env.playerKeys.isEmpty());
        assertTrue(env.pinned.isEmpty());
        assertFalse(h.rejected().trusted());
    }

    @Test
    void mitmFlippingOnlineModeIsDetected() {
        Handshake h = handshake();
        h.toClient = (c, p) -> h.queryChannels.size() == 1 ? rewriteServerHello(p,
                s -> new ServerHello(s.versions(), s.serverEphPub(), s.serverNonce(), s.features(), !s.onlineMode()))
                : p;
        h.run();
        assertEquals(ClientFailure.Kind.CRYPTO_FAILURE, h.clientFailure().kind());
    }

    @Test
    void mitmStrippingTunnelFeatureIsDetected() {
        Handshake h = handshake();
        h.config = new ServerAuthConfig(ServerAuthConfig.TunnelPolicy.REQUIRED, 3, 60, "", "", "");
        h.toClient = (c, p) -> h.queryChannels.size() == 1 ? rewriteServerHello(p,
                s -> new ServerHello(s.versions(), s.serverEphPub(), s.serverNonce(), 0, s.onlineMode())) : p;
        h.run();
        assertEquals(ClientFailure.Kind.CRYPTO_FAILURE, h.clientFailure().kind());
    }

    @Test
    void usernameMismatchIsDetected() {
        Handshake h = handshake();
        h.clientUsername = "Alex"; // 服务端看到的用户名与客户端不同
        h.run();
        assertEquals(ClientFailure.Kind.CRYPTO_FAILURE, h.clientFailure().kind());
        assertTrue(accounts.accounts.isEmpty());
    }

    @Test
    void changedServerIdentityIsRefusedByDefault() {
        byte[] oldKey = Ed25519.generate(new SecureRandom()).publicKey();
        env.pinned.put(Handshake.ADDRESS, oldKey);
        Handshake h = handshake().run();
        assertEquals(ClientFailure.Kind.SERVER_KEY_REJECTED, h.clientFailure().kind());
        assertEquals(1, env.keyChangePrompts);
        assertArrayEquals(oldKey, env.pinned.get(Handshake.ADDRESS));
        assertTrue(env.prompts.isEmpty());
        assertTrue(accounts.accounts.isEmpty());
    }

    @Test
    void changedServerIdentityAcceptedByPlayerIsRepinned() {
        env.pinned.put(Handshake.ADDRESS, Ed25519.generate(new SecureRandom()).publicKey());
        env.acceptKeyChange = true;
        env.answer((String) null);
        handshake().run().accepted();
        assertArrayEquals(serverIdentity.publicKey(), env.pinned.get(Handshake.ADDRESS));
    }

    @Test
    void firstConnectionPinsServerKeyAfterSignatureCheck() {
        env.answer((String) null);
        handshake().run().accepted();
        assertArrayEquals(serverIdentity.publicKey(), env.pinned.get(Handshake.ADDRESS));
        assertEquals(0, env.keyChangePrompts);
    }

    @Test
    void serverAnswerOnWrongChannelIsProtocolError() {
        accounts.put("steve", clientKey(), false, "pw", null);
        // 手动驱动：服务端在等待密码回答时，从认证频道收到回答
        ManualClient m = new ManualClient();
        ServerAuthSession server = newServer();
        m.hello(server.start());
        server.onAnswer(Channel.AUTH, m.clientHello).join();
        ServerStep step = server.onAnswer(Channel.AUTH, m.proof(clientKeyPair(), m.transcript)).join();
        assertInstanceOf(ServerStep.Send.class, step);
        assertEquals(Channel.PASSWORD, ((ServerStep.Send) step).next().channel());
        ServerStep wrong = server.onAnswer(Channel.AUTH, new byte[] {1}).join();
        assertEquals(new AuthOutcome.Rejected(RejectReason.PROTOCOL_ERROR, true), ((ServerStep.Done) wrong).outcome());
    }

    @Test
    void clientRejectsPasswordRequestBeforeChallenge() {
        ServerAuthSession server = newServer();
        ClientAuthSession client = new ClientAuthSession(Handshake.ADDRESS, "Steve", false, env, new SecureRandom());
        Outbound hello = server.start();
        assertInstanceOf(ClientStep.Reply.class, client.onQuery(hello.channel(), hello.payload()).join());
        ClientStep step = client.onQuery(Channel.PASSWORD, new byte[] {'T', 'S', 'R', 'V', 5}).join();
        assertEquals(ClientFailure.Kind.PROTOCOL_ERROR, ((ClientStep.Fail) step).failure().kind());
        assertTrue(env.prompts.isEmpty());
    }

    // ================= 手动客户端：无效证明、重放 =================

    /** 绕过 ClientAuthSession，直接用密码学 API 构造消息的客户端。 */
    private final class ManualClient {
        byte[] clientHello;
        byte[] transcript;
        SecureMessageChannel auth;

        void hello(Outbound serverHello) {
            try {
                ServerHello sh = (ServerHello) MessageCodec.decodePlain(Channel.AUTH, serverHello.payload());
                X25519.Ephemeral eph = X25519.generate(new SecureRandom());
                byte[] nonce = new byte[32];
                new SecureRandom().nextBytes(nonce);
                clientHello = MessageCodec.encodePlain(
                        new ClientHello(ProtocolVersion.CURRENT, eph.publicKey(), nonce, false));
                transcript = Transcript.compute(serverHello.payload(), clientHello, "Steve");
                auth = SessionKeys.derive(eph.agree(sh.serverEphPub()), sh.serverNonce(), nonce, transcript)
                        .authChannel(Side.CLIENT);
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        }

        Message open(Outbound query) throws Exception {
            return auth.open(query.payload());
        }

        byte[] proof(Ed25519.KeyPairData key, byte[] signedTranscript) {
            try {
                return auth.seal(new ClientProof(key.publicKey(), HandshakeSignatures.signClient(key, signedTranscript)));
            } catch (Exception e) {
                throw new AssertionError(e);
            }
        }
    }

    private ServerAuthSession newServer() {
        return new ServerAuthSession("steve", "Steve", false, false, CONFIG, serverIdentity, accounts,
                new SecureRandom());
    }

    private Ed25519.KeyPairData clientKeyPair() {
        return env.playerKey(serverIdentity.publicKey(), "Steve").join();
    }

    @Test
    void proofSignedOverWrongTranscriptIsRejectedUntrusted() throws Exception {
        ServerAuthSession server = newServer();
        ManualClient m = new ManualClient();
        m.hello(server.start());
        ServerStep challenge = server.onAnswer(Channel.AUTH, m.clientHello).join();
        m.open(((ServerStep.Send) challenge).next());
        ServerStep step = server.onAnswer(Channel.AUTH, m.proof(clientKeyPair(), new byte[32])).join();
        assertEquals(new AuthOutcome.Rejected(RejectReason.INVALID_PROOF, false), ((ServerStep.Done) step).outcome());
        assertTrue(accounts.accounts.isEmpty());
    }

    @Test
    void replayedProofIsRejected() throws Exception {
        accounts.put("steve", clientKey(), false, null, "rec"); // 证明后直接 Finish
        ServerAuthSession server = newServer();
        ManualClient m = new ManualClient();
        m.hello(server.start());
        server.onAnswer(Channel.AUTH, m.clientHello).join();
        byte[] proof = m.proof(clientKeyPair(), m.transcript);
        assertInstanceOf(ServerStep.Send.class, server.onAnswer(Channel.AUTH, proof).join());
        ServerStep replay = server.onAnswer(Channel.AUTH, proof).join();
        assertEquals(new AuthOutcome.Rejected(RejectReason.CRYPTO_FAILURE, true), ((ServerStep.Done) replay).outcome());
    }

    @Test
    void plaintextHelloResentAfterKeyExchangeIsRejected() {
        ServerAuthSession server = newServer();
        ManualClient m = new ManualClient();
        m.hello(server.start());
        server.onAnswer(Channel.AUTH, m.clientHello).join();
        ServerStep step = server.onAnswer(Channel.AUTH, m.clientHello).join();
        assertEquals(RejectReason.PROTOCOL_ERROR, ((AuthOutcome.Rejected) ((ServerStep.Done) step).outcome()).reason());
    }

    // ================= 未装 mod、生命周期 =================

    @Test
    void notUnderstoodFirstAnswerMeansNoMod() {
        ServerAuthSession server = newServer();
        server.start();
        ServerStep step = server.onAnswer(Channel.AUTH, null).join();
        assertEquals(new AuthOutcome.Rejected(RejectReason.NO_MOD, false), ((ServerStep.Done) step).outcome());
        assertThrows(IllegalStateException.class, () -> server.onAnswer(Channel.AUTH, new byte[0]));
    }

    @Test
    void garbageFirstAnswerIsProtocolError() {
        ServerAuthSession server = newServer();
        server.start();
        ServerStep step = server.onAnswer(Channel.AUTH, new byte[] {1, 2, 3}).join();
        assertEquals(new AuthOutcome.Rejected(RejectReason.PROTOCOL_ERROR, false), ((ServerStep.Done) step).outcome());
    }

    @Test
    void lifecycleMisuseIsRejected() {
        ServerAuthSession server = newServer();
        assertThrows(IllegalStateException.class, () -> server.onAnswer(Channel.AUTH, new byte[0]));
        server.start();
        assertThrows(IllegalStateException.class, server::start);
    }

    @Test
    void storageFailureIsInternalError() {
        accounts.failNextCall = true;
        Handshake h = handshake().run();
        assertEquals(new AuthOutcome.Rejected(RejectReason.INTERNAL_ERROR, true), h.rejected());
    }

    @Test
    void timeoutWithoutPendingWork() {
        ServerAuthSession server = newServer();
        server.start();
        assertEquals(new AuthOutcome.Rejected(RejectReason.TIMEOUT, false), server.timeout());
        assertThrows(IllegalStateException.class, () -> server.onAnswer(Channel.AUTH, null));
    }

    /** 手动推进的执行器，用来让账号存储的 future 挂起。 */
    private static final class QueueExecutor implements Executor {
        final Deque<Runnable> tasks = new ArrayDeque<>();

        @Override
        public void execute(Runnable command) {
            tasks.add(command);
        }

        void runAll() {
            while (!tasks.isEmpty()) {
                tasks.poll().run();
            }
        }
    }

    @Test
    void concurrentAnswersAndTimeoutWhileBusy() {
        QueueExecutor executor = new QueueExecutor();
        accounts = new InMemoryAccounts(executor);
        ServerAuthSession server = newServer();
        ManualClient m = new ManualClient();
        m.hello(server.start());
        server.onAnswer(Channel.AUTH, m.clientHello).join();
        CompletableFuture<ServerStep> pending = server.onAnswer(Channel.AUTH, m.proof(clientKeyPair(), m.transcript));
        assertFalse(pending.isDone());
        assertThrows(IllegalStateException.class, () -> server.onAnswer(Channel.AUTH, new byte[0]));

        assertEquals(new AuthOutcome.Rejected(RejectReason.TIMEOUT, true), server.timeout());
        executor.runAll();
        assertEquals(new AuthOutcome.Rejected(RejectReason.TIMEOUT, true), ((ServerStep.Done) pending.join()).outcome());
        assertEquals(new AuthOutcome.Rejected(RejectReason.TIMEOUT, true), server.timeout());
    }

    @Test
    void worksWithAccountStorageOnAnotherThread() {
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            accounts = new InMemoryAccounts(pool);
            env.answer((String) null);
            new Handshake(serverIdentity, accounts, env).run().accepted();
            env.answer("pw");
            Handshake second = new Handshake(serverIdentity, accounts, env).run();
            assertFalse(second.accepted().restricted());
        } finally {
            pool.shutdownNow();
        }
    }

    // ================= 配置 =================

    @Test
    void configValidation() {
        assertThrows(IllegalArgumentException.class, () -> new ServerAuthConfig(
                ServerAuthConfig.TunnelPolicy.OPTIONAL, 0, 60, "", "", ""));
        assertThrows(IllegalArgumentException.class, () -> new ServerAuthConfig(
                ServerAuthConfig.TunnelPolicy.OPTIONAL, 3, 0, "", "", ""));
        String big = "x".repeat(1024);
        assertThrows(IllegalArgumentException.class, () -> new ServerAuthConfig(
                ServerAuthConfig.TunnelPolicy.OPTIONAL, 3, 60, big + "y", "", ""));
        new ServerAuthConfig(ServerAuthConfig.TunnelPolicy.OPTIONAL, 3, 60, big, big, big);
        // 三条提示合计超过 Finish 的消息体上限
        String bigger = "x".repeat(1020);
        assertThrows(IllegalArgumentException.class, () -> new ServerAuthConfig(
                ServerAuthConfig.TunnelPolicy.OPTIONAL, 3, 60, bigger + bigger, bigger, bigger));
        assertThrows(IllegalArgumentException.class, () -> new ServerAuthConfig(
                ServerAuthConfig.TunnelPolicy.DISABLED,
                new ServerAuthConfig.ValidationLevels(false, true, false, false), 3, 60, "", "", ""));
        assertThrows(IllegalArgumentException.class, () -> new ServerAuthConfig(
                ServerAuthConfig.TunnelPolicy.DISABLED,
                new ServerAuthConfig.ValidationLevels(true, false, false, true), 3, 60, "", "", ""));
        assertThrows(IllegalArgumentException.class, () -> new ServerAuthConfig(
                ServerAuthConfig.TunnelPolicy.OPTIONAL,
                new ServerAuthConfig.ValidationLevels(false, false, false, false), 3, 60, "", "", ""));
    }
}
