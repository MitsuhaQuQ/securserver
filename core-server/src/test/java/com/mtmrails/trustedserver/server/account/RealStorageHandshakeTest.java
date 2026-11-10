package com.mtmrails.trustedserver.server.account;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mtmrails.trustedserver.core.crypto.Ed25519;
import com.mtmrails.trustedserver.core.message.PasswordRequest;
import com.mtmrails.trustedserver.core.message.PasswordAnswer;
import com.mtmrails.trustedserver.core.session.AuthOutcome;
import com.mtmrails.trustedserver.core.session.ClientAuthSession;
import com.mtmrails.trustedserver.core.session.ClientEnvironment;
import com.mtmrails.trustedserver.core.session.ClientStep;
import com.mtmrails.trustedserver.core.session.Outbound;
import com.mtmrails.trustedserver.core.session.RebindReason;
import com.mtmrails.trustedserver.core.session.RejectReason;
import com.mtmrails.trustedserver.core.session.ServerAuthConfig;
import com.mtmrails.trustedserver.core.session.ServerAuthSession;
import com.mtmrails.trustedserver.core.session.ServerStep;
import com.mtmrails.trustedserver.server.store.AuditRecord;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** 用真实的 SQLite + Argon2id 账号服务跑完整握手。 */
class RealStorageHandshakeTest {
    private static final SecureRandom RANDOM = new SecureRandom();

    @TempDir
    Path dir;
    MutableClock clock;
    AccountService service;
    Ed25519.KeyPairData serverIdentity;
    com.mtmrails.trustedserver.core.session.ClientResult lastClientResult;

    /** 一台“电脑”：自己的 TOFU 记录和玩家密钥。 */
    static final class Device implements ClientEnvironment {
        final Map<String, byte[]> pinned = new HashMap<>();
        Ed25519.KeyPairData key = Ed25519.generate(RANDOM);
        final Deque<String> answers = new ArrayDeque<>();
        final Deque<PasswordRequest.Kind> prompts = new ArrayDeque<>();

        Device answer(String... values) {
            answers.addAll(List.of(values));
            return this;
        }

        @Override
        public Optional<byte[]> pinnedServerKey(String serverAddress) {
            return Optional.ofNullable(pinned.get(serverAddress));
        }

        @Override
        public void pinServerKey(String serverAddress, byte[] serverIdPub) {
            pinned.put(serverAddress, serverIdPub);
        }

        @Override
        public CompletableFuture<Boolean> confirmServerKeyChange(String a, byte[] b, byte[] c) {
            return CompletableFuture.completedFuture(false);
        }

        @Override
        public CompletableFuture<Ed25519.KeyPairData> playerKey(byte[] serverIdPub, String username) {
            return CompletableFuture.completedFuture(key);
        }

        @Override
        public CompletableFuture<Optional<PasswordAnswer>> promptPassword(PasswordRequest request) {
            prompts.add(request.kind());
            String next = answers.poll();
            return CompletableFuture.completedFuture(next == null
                    ? Optional.empty() : Optional.of(new PasswordAnswer(next)));
        }
    }

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        service = AccountService.open(dir.resolve("players.db"), AccountServiceTest.CONFIG, clock, RANDOM);
        serverIdentity = Ed25519.generate(RANDOM);
    }

    @AfterEach
    void tearDown() {
        service.close();
    }

    private AuthOutcome login(Device device, String accountId, boolean onlineMode, boolean mojangVerified) {
        ServerAuthSession server = new ServerAuthSession(accountId, "Steve", onlineMode, mojangVerified,
                ServerAuthConfig.allValidationDefaults(), serverIdentity, service, RANDOM);
        ClientAuthSession client = new ClientAuthSession("mc.test", "Steve", false, device, RANDOM);
        Outbound query = server.start();
        while (true) {
            ClientStep step = client.onQuery(query.channel(), query.payload()).join();
            byte[] answer;
            if (step instanceof ClientStep.Reply reply) {
                answer = reply.payload();
            } else if (step instanceof ClientStep.Complete complete) {
                answer = complete.payload();
                lastClientResult = complete.result();
            } else {
                return server.timeout();
            }
            ServerStep next = server.onAnswer(query.channel(), answer).join();
            if (next instanceof ServerStep.Done done) {
                if (done.outcome() instanceof AuthOutcome.Accepted accepted) {
                    service.recordLogin(accepted.accountId(), accepted.username(), "127.0.0.1").join();
                }
                return done.outcome();
            }
            query = ((ServerStep.Send) next).next();
        }
    }

    private List<String> events(String id) {
        return service.inspect(s -> s.auditFor(id)).join().stream().map(AuditRecord::event).toList();
    }

    @Test
    void newPlayerSetsPasswordThenLogsInAgain() {
        Device pc = new Device().answer("my password");
        AuthOutcome.Accepted first = (AuthOutcome.Accepted) login(pc, "steve", false, false);
        assertFalse(first.restricted());

        pc.answer("my password");
        AuthOutcome.Accepted second = (AuthOutcome.Accepted) login(pc, "steve", false, false);
        assertTrue(second.hasLoginPassword());
        assertEquals(List.of(PasswordRequest.Kind.SET, PasswordRequest.Kind.LOGIN), List.copyOf(pc.prompts));
        assertEquals(List.of("bind", "set_password", "login_ok", "login_ok"), events("steve"));
    }

    @Test
    void tooShortPasswordIsPromptedAgainWithRealPolicy() {
        Device pc = new Device().answer("12345", "123456");
        assertFalse(((AuthOutcome.Accepted) login(pc, "steve", false, false)).restricted());
        assertEquals(List.of(PasswordRequest.Kind.SET, PasswordRequest.Kind.SET), List.copyOf(pc.prompts));
    }

    @Test
    void wrongPasswordsLockTheAccountAcrossConnections() {
        Device pc = new Device().answer("right password");
        login(pc, "steve", false, false);

        pc.answer("w1", "w2", "w3");
        assertEquals(RejectReason.PASSWORD_ATTEMPTS_EXHAUSTED, ((AuthOutcome.Rejected) login(pc, "steve", false, false)).reason());
        // 锁定期内连正确密码也不行
        pc.answer("right password", "right password", "right password");
        assertEquals(RejectReason.PASSWORD_ATTEMPTS_EXHAUSTED, ((AuthOutcome.Rejected) login(pc, "steve", false, false)).reason());

        clock.advance(Duration.ofMinutes(16));
        pc.answer("right password");
        assertTrue(login(pc, "steve", false, false) instanceof AuthOutcome.Accepted);
    }

    @Test
    void newComputerOfflineNeedsRecoveryPassword() {
        Device oldPc = new Device().answer("login password");
        login(oldPc, "steve", false, false);
        service.setRecoveryPasswordInGame("steve", "recovery password").join();

        Device newPc = new Device();
        newPc.pinned.putAll(oldPc.pinned);
        newPc.answer("recovery password", "login password");
        AuthOutcome.Accepted accepted = (AuthOutcome.Accepted) login(newPc, "steve", false, false);
        assertEquals(Optional.of(RebindReason.RECOVERY), accepted.reboundBy());
        assertArrayEquals(newPc.key.publicKey(), service.find("steve").join().orElseThrow().playerPub());
    }

    @Test
    void newComputerOnlineModeRebindsAfterLoginPassword() {
        String uuid = "069a79f4-44e9-4726-a5be-fca90e38aaf5";
        Device oldPc = new Device().answer("login password");
        login(oldPc, uuid, true, true);

        Device newPc = new Device().answer("login password");
        AuthOutcome.Accepted accepted = (AuthOutcome.Accepted) login(newPc, uuid, true, true);
        assertEquals(Optional.of(RebindReason.ONLINE_MODE_IDENTITY), accepted.reboundBy());
        assertTrue(events(uuid).contains("online_rebind"));
    }

    @Test
    void passwdInGameUsesTheHandedOverChannel() throws Exception {
        Device pc = new Device().answer(""); // 登录时跳过设密码，保持受限
        AuthOutcome.Accepted accepted = (AuthOutcome.Accepted) login(pc, "steve", false, false);
        assertTrue(accepted.restricted());

        java.util.concurrent.BlockingQueue<byte[]> toClient = new java.util.concurrent.LinkedBlockingQueue<>();
        java.util.concurrent.BlockingQueue<Boolean> unrestricted = new java.util.concurrent.LinkedBlockingQueue<>();
        PlayPasswordEndpoint endpoint = new PlayPasswordEndpoint(accepted.accountId(),
                accepted.handover().passwordChannel(), service, new PlayPasswordEndpoint.Listener() {
                    @Override
                    public void send(byte[] payload) {
                        toClient.add(payload);
                    }

                    @Override
                    public void passwordSet(boolean login) {
                        unrestricted.add(login);
                    }

                    @Override
                    public void kick() {
                        throw new AssertionError("kicked");
                    }
                }, clock);
        com.mtmrails.trustedserver.client.PlayPasswordClient client =
                new com.mtmrails.trustedserver.client.PlayPasswordClient(lastClientResult.handover().passwordChannel());

        var command = (com.mtmrails.trustedserver.client.PasswordCommand.Set)
                com.mtmrails.trustedserver.client.PasswordCommand.parse("/passwd new-secret new-secret");
        endpoint.onPayload(client.request(command));
        byte[] reply = toClient.poll(5, java.util.concurrent.TimeUnit.SECONDS);
        assertEquals(com.mtmrails.trustedserver.core.message.PasswordResult.Status.OK, client.onPayload(reply).status());
        assertEquals(Boolean.TRUE, unrestricted.poll(5, java.util.concurrent.TimeUnit.SECONDS));

        pc.answer("new-secret");
        assertFalse(((AuthOutcome.Accepted) login(pc, "steve", false, false)).restricted());
    }

    @Test
    void adminResetKeyLetsPlayerBindNewComputer() {
        Device oldPc = new Device().answer("login password");
        login(oldPc, "steve", false, false);
        service.resetKey("steve").join();

        Device newPc = new Device().answer("login password");
        AuthOutcome.Accepted accepted = (AuthOutcome.Accepted) login(newPc, "steve", false, false);
        assertEquals(Optional.of(RebindReason.KEY_RESET), accepted.reboundBy());
        assertTrue(events("steve").contains("bind_after_reset"));

        // 旧电脑现在不匹配，且没有找回密码
        assertEquals(RejectReason.KEY_MISMATCH, ((AuthOutcome.Rejected) login(oldPc, "steve", false, false)).reason());
    }
}
