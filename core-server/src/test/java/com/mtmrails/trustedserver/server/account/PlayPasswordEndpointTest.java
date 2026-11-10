package com.mtmrails.trustedserver.server.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mtmrails.trustedserver.core.crypto.SecureMessageChannel;
import com.mtmrails.trustedserver.core.crypto.SessionKeys;
import com.mtmrails.trustedserver.core.crypto.Side;
import com.mtmrails.trustedserver.core.message.PasswordAnswer;
import com.mtmrails.trustedserver.core.message.PasswordResult;
import com.mtmrails.trustedserver.core.message.SetPassword;
import com.mtmrails.trustedserver.core.message.SetRecoveryPassword;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PlayPasswordEndpointTest {
    @TempDir
    Path dir;
    MutableClock clock;
    AccountService service;
    SecureMessageChannel client;
    PlayPasswordEndpoint endpoint;
    final BlockingQueue<byte[]> sent = new LinkedBlockingQueue<>();
    final BlockingQueue<Boolean> passwordSet = new LinkedBlockingQueue<>();
    final AtomicInteger kicks = new AtomicInteger();

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        service = AccountService.open(dir.resolve("players.db"), AccountServiceTest.CONFIG, clock, new SecureRandom());
        service.bindNew("steve", "Steve", new byte[32]).join();

        byte[] shared = new byte[32];
        new SecureRandom().nextBytes(shared);
        SessionKeys keys = SessionKeys.derive(shared, new byte[32], new byte[32], new byte[32]);
        client = keys.passwordChannel(Side.CLIENT);
        endpoint = new PlayPasswordEndpoint("steve", keys.passwordChannel(Side.SERVER), service,
                new PlayPasswordEndpoint.Listener() {
                    @Override
                    public void send(byte[] payload) {
                        sent.add(payload);
                    }

                    @Override
                    public void passwordSet(boolean login) {
                        passwordSet.add(login);
                    }

                    @Override
                    public void kick() {
                        kicks.incrementAndGet();
                    }
                }, clock);
    }

    @AfterEach
    void tearDown() {
        service.close();
    }

    private PasswordResult nextResult() throws Exception {
        byte[] payload = sent.poll(5, TimeUnit.SECONDS);
        if (payload == null) {
            throw new AssertionError("no result was sent");
        }
        return (PasswordResult) client.open(payload);
    }

    @Test
    void setLoginPasswordLiftsRestriction() throws Exception {
        endpoint.onPayload(client.seal(new SetPassword("in-game pw")));
        assertEquals(PasswordResult.Status.OK, nextResult().status());
        assertEquals(Boolean.TRUE, passwordSet.poll(5, TimeUnit.SECONDS));
        assertFalse(service.find("steve").join().orElseThrow().restricted());
        assertTrue(service.verifyLoginPassword("steve", "in-game pw").join());
    }

    @Test
    void setRecoveryPassword() throws Exception {
        endpoint.onPayload(client.seal(new SetRecoveryPassword("recovery pw")));
        assertEquals(PasswordResult.Status.OK, nextResult().status());
        assertEquals(Boolean.FALSE, passwordSet.poll(5, TimeUnit.SECONDS));
        assertTrue(service.find("steve").join().orElseThrow().restricted()); // 找回密码不解除受限
    }

    @Test
    void disabledValidationLayerIsRejected() throws Exception {
        byte[] shared = new byte[32];
        new SecureRandom().nextBytes(shared);
        SessionKeys keys = SessionKeys.derive(shared, new byte[32], new byte[32], new byte[32]);
        client = keys.passwordChannel(Side.CLIENT);
        endpoint = new PlayPasswordEndpoint("steve", keys.passwordChannel(Side.SERVER), service,
                new PlayPasswordEndpoint.Listener() {
                    @Override public void send(byte[] payload) { sent.add(payload); }
                    @Override public void passwordSet(boolean login) { passwordSet.add(login); }
                    @Override public void kick() { kicks.incrementAndGet(); }
                }, clock, true, false);
        endpoint.onPayload(client.seal(new SetRecoveryPassword("recovery pw")));
        assertEquals(PasswordResult.Status.REJECTED, nextResult().status());
        assertFalse(service.find("steve").join().orElseThrow().hasRecoveryPassword());
    }

    @Test
    void policyViolationIsRejectedWithReason() throws Exception {
        endpoint.onPayload(client.seal(new SetPassword("abc")));
        PasswordResult result = nextResult();
        assertEquals(PasswordResult.Status.REJECTED, result.status());
        assertTrue(result.message().contains("6"));
        assertNull(passwordSet.poll(200, TimeUnit.MILLISECONDS));
    }

    @Test
    void rateLimitedAfterFivePerMinute() throws Exception {
        for (int i = 0; i < 5; i++) {
            endpoint.onPayload(client.seal(new SetPassword("password " + i)));
            assertEquals(PasswordResult.Status.OK, nextResult().status());
        }
        endpoint.onPayload(client.seal(new SetPassword("password 6")));
        assertEquals(PasswordResult.Status.RATE_LIMITED, nextResult().status());
        clock.advance(Duration.ofMinutes(1));
        endpoint.onPayload(client.seal(new SetPassword("password 7")));
        assertEquals(PasswordResult.Status.OK, nextResult().status());
        assertEquals(0, kicks.get());
    }

    @Test
    void concurrentRequestIsRejectedAndResultsStayInOrder() throws Exception {
        endpoint.onPayload(client.seal(new SetPassword("first password")));
        endpoint.onPayload(client.seal(new SetPassword("second password")));
        // 第二个请求在第一个处理期间到达：立即得到 RATE_LIMITED；两条结果都能按序号顺序解开
        List<PasswordResult.Status> statuses = List.of(nextResult().status(), nextResult().status());
        assertTrue(statuses.contains(PasswordResult.Status.RATE_LIMITED), statuses.toString());
        assertTrue(statuses.contains(PasswordResult.Status.OK), statuses.toString());
        assertTrue(service.verifyLoginPassword("steve", "first password").join());
    }

    @Test
    void tamperedPayloadKicksAndChannelStaysDead() throws Exception {
        byte[] payload = client.seal(new SetPassword("valid password"));
        byte[] tampered = payload.clone();
        tampered[tampered.length - 1] ^= 1;
        endpoint.onPayload(tampered);
        assertEquals(1, kicks.get());
        endpoint.onPayload(payload); // 失效后忽略一切
        assertEquals(1, kicks.get());
        assertNull(sent.poll(200, TimeUnit.MILLISECONDS));
        assertFalse(service.verifyLoginPassword("steve", "valid password").join());
    }

    @Test
    void wrongMessageTypeKicks() throws Exception {
        endpoint.onPayload(client.seal(new PasswordAnswer("login-phase answer")));
        assertEquals(1, kicks.get());
    }

    @Test
    void replayKicks() throws Exception {
        byte[] payload = client.seal(new SetPassword("valid password"));
        endpoint.onPayload(payload);
        nextResult();
        endpoint.onPayload(payload);
        assertEquals(1, kicks.get());
    }
}
