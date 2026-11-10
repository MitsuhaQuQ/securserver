package com.mtmrails.trustedserver.server.account;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mtmrails.trustedserver.core.message.PasswordRequest;
import com.mtmrails.trustedserver.core.message.PasswordResult;
import com.mtmrails.trustedserver.core.session.AccountView;
import com.mtmrails.trustedserver.core.session.PasswordChange;
import com.mtmrails.trustedserver.core.session.RecoveryOrigin;
import com.mtmrails.trustedserver.core.session.RecoveryResult;
import com.mtmrails.trustedserver.server.password.PasswordHasher;
import com.mtmrails.trustedserver.server.password.PasswordPolicy;
import com.mtmrails.trustedserver.server.store.Account;
import com.mtmrails.trustedserver.server.store.AuditRecord;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AccountServiceTest {
    static final PasswordHasher.Params FAST = new PasswordHasher.Params(64, 1, 1);
    static final AccountServiceConfig CONFIG = new AccountServiceConfig(FAST, PasswordPolicy.DEFAULT, 2, 64, 10,
            Duration.ofMinutes(15), Duration.ofDays(90));

    @TempDir
    Path dir;
    MutableClock clock;
    AccountService service;

    @BeforeEach
    void setUp() {
        clock = new MutableClock();
        service = open(CONFIG);
    }

    @AfterEach
    void tearDown() {
        service.close();
    }

    private AccountService open(AccountServiceConfig config) {
        return AccountService.open(dir.resolve("players.db"), config, clock, new SecureRandom());
    }

    private static byte[] key(int b) {
        byte[] k = new byte[32];
        k[0] = (byte) b;
        return k;
    }

    private Account account(String id) {
        return service.inspect(s -> s.find(id).orElseThrow()).join();
    }

    private List<String> events(String id) {
        return service.inspect(s -> s.auditFor(id)).join().stream().map(AuditRecord::event).toList();
    }

    @Test
    void bindAndFind() {
        assertTrue(service.find("steve").join().isEmpty());
        assertTrue(service.bindNew("steve", "Steve", key(1)).join());
        assertFalse(service.bindNew("steve", "Steve", key(2)).join());
        AccountView view = service.find("steve").join().orElseThrow();
        assertArrayEquals(key(1), view.playerPub());
        assertTrue(view.restricted());
        assertFalse(view.hasLoginPassword());
        assertEquals(List.of("bind"), events("steve"));
    }

    @Test
    void setLoginPasswordAppliesPolicyAndUnrestricts() {
        service.bindNew("steve", "Steve", key(1)).join();
        assertFalse(service.setLoginPassword("steve", "short").join());
        assertTrue(account("steve").restricted());
        assertTrue(service.setLoginPassword("steve", "long enough").join());
        assertFalse(account("steve").restricted());
        assertTrue(account("steve").passwordHash().startsWith("$argon2id$"));
        assertTrue(service.verifyLoginPassword("steve", "long enough").join());
        assertFalse(service.verifyLoginPassword("steve", "wrong one").join());
    }

    @Test
    void loginAndRecoveryPasswordsMustDiffer() {
        service.bindNew("steve", "Steve", key(1)).join();
        assertEquals(PasswordResult.Status.OK, service.setLoginPasswordInGame("steve", "same-secret").join().status());
        PasswordResult rejected = service.setRecoveryPasswordInGame("steve", "same-secret").join();
        assertEquals(PasswordResult.Status.REJECTED, rejected.status());
        assertTrue(rejected.message().contains("不能相同"));
        assertEquals(PasswordResult.Status.OK, service.setRecoveryPasswordInGame("steve", "other-secret").join().status());
        assertEquals(PasswordResult.Status.REJECTED, service.setLoginPasswordInGame("steve", "other-secret").join().status());
        assertTrue(service.verifyRecoveryPassword("steve", "other-secret").join());
    }

    @Test
    void inGameResultsForBadInput() {
        assertEquals(PasswordResult.Status.ERROR, service.setLoginPasswordInGame("nobody", "long enough").join().status());
        assertEquals(PasswordResult.Status.REJECTED, service.setLoginPasswordInGame("nobody", "x").join().status());
    }

    @Test
    void verifyWithoutPasswordIsFalse() {
        service.bindNew("steve", "Steve", key(1)).join();
        assertFalse(service.verifyLoginPassword("steve", "anything").join());
        assertFalse(service.verifyRecoveryPassword("steve", "anything").join());
        assertFalse(service.verifyLoginPassword("nobody", "anything").join());
    }

    @Test
    void exhaustedAttemptsLockTheAccount() {
        service.bindNew("steve", "Steve", key(1)).join();
        service.setLoginPassword("steve", "correct pw").join();
        service.passwordFailed("steve", PasswordRequest.Kind.LOGIN, true).join();
        assertTrue(service.isLocked("steve").join());
        // 锁定期内即使密码正确也判为错误，且不做哈希
        assertFalse(service.verifyLoginPassword("steve", "correct pw").join());
        clock.advance(Duration.ofMinutes(15).plusMillis(1));
        assertFalse(service.isLocked("steve").join());
        assertTrue(service.verifyLoginPassword("steve", "correct pw").join());
        assertEquals(List.of("bind", "set_password", "login_fail", "lockout"), events("steve"));
    }

    @Test
    void cumulativeFailuresAcrossConnectionsLock() {
        service.bindNew("steve", "Steve", key(1)).join();
        for (int i = 0; i < 9; i++) {
            service.passwordFailed("steve", PasswordRequest.Kind.LOGIN, false).join();
        }
        assertFalse(service.isLocked("steve").join());
        service.passwordFailed("steve", PasswordRequest.Kind.RECOVERY, false).join();
        assertTrue(service.isLocked("steve").join());
    }

    @Test
    void successfulLoginClearsFailureCount() {
        service.bindNew("steve", "Steve", key(1)).join();
        for (int i = 0; i < 9; i++) {
            service.passwordFailed("steve", PasswordRequest.Kind.LOGIN, false).join();
        }
        service.recordLogin("steve", "Steve", "10.1.2.3").join();
        service.passwordFailed("steve", PasswordRequest.Kind.LOGIN, false).join();
        assertFalse(service.isLocked("steve").join());
        assertEquals("10.1.2.3", account("steve").lastIp());
    }

    @Test
    void rehashesWhenParametersChange() {
        service.bindNew("steve", "Steve", key(1)).join();
        service.setLoginPassword("steve", "long enough").join();
        service.inspect(s -> s.setRestricted("steve", true)).join(); // 确认重新哈希不改变受限状态
        service.close();

        service = open(new AccountServiceConfig(new PasswordHasher.Params(128, 2, 1), PasswordPolicy.DEFAULT, 2, 64,
                10, Duration.ofMinutes(15), Duration.ofDays(90)));
        assertTrue(service.verifyLoginPassword("steve", "long enough").join());
        assertTrue(account("steve").passwordHash().startsWith("$argon2id$v=19$m=128,t=2,p=1$"));
        assertTrue(account("steve").restricted());
        assertTrue(service.verifyLoginPassword("steve", "long enough").join());
    }

    @Test
    void rebindAuditsReason() {
        service.bindNew("steve", "Steve", key(1)).join();
        assertTrue(service.rebindRecoveredKey("steve", key(1), key(2)).join());
        service.rebindOnline("steve", key(3)).join();
        assertArrayEquals(key(3), account("steve").playerPub());
        assertEquals(List.of("bind", "recovery_rebind", "online_rebind"), events("steve"));
    }

    @Test
    void atomicRecoveryHashesNewPasswordAndComparesOldKey() {
        service.bindNew("steve", "Steve", key(1)).join();
        service.setLoginPasswordInGame("steve", "old password").join();
        service.setRecoveryPasswordInGame("steve", "recovery password").join();

        assertEquals(RecoveryResult.PASSWORD_REJECTED,
                service.recoverAccount("steve", key(1), key(2), PasswordChange.SET,
                        "recovery password", RecoveryOrigin.RECOVERY_PASSWORD).join());
        assertEquals(RecoveryResult.ACCOUNT_CONFLICT,
                service.recoverAccount("steve", key(9), key(2), PasswordChange.SET,
                        "new password", RecoveryOrigin.RECOVERY_PASSWORD).join());
        assertArrayEquals(key(1), account("steve").playerPub());
        assertTrue(service.verifyLoginPassword("steve", "old password").join());

        assertEquals(RecoveryResult.OK,
                service.recoverAccount("steve", key(1), key(2), PasswordChange.SET,
                        "new password", RecoveryOrigin.RECOVERY_PASSWORD).join());
        assertArrayEquals(key(2), account("steve").playerPub());
        assertTrue(service.verifyLoginPassword("steve", "new password").join());
        assertFalse(service.verifyLoginPassword("steve", "old password").join());
        assertEquals(List.of("bind", "set_password", "set_recovery", "recovery_password_reset"),
                events("steve"));
    }

    @Test
    void onlineRecoveryCanClearPasswordWithoutChangingKey() {
        service.bindNew("steve", "Steve", key(1)).join();
        service.setLoginPasswordInGame("steve", "old password").join();
        assertEquals(RecoveryResult.OK,
                service.recoverAccount("steve", key(1), key(1), PasswordChange.CLEAR, "",
                        RecoveryOrigin.ONLINE_SESSION_AND_KEY).join());
        assertNull(account("steve").passwordHash());
        assertTrue(account("steve").restricted());
        assertEquals(List.of("bind", "set_password", "online_password_reset"), events("steve"));
    }

    @Test
    void adminCommands() {
        service.bindNew("steve", "Steve", key(1)).join();
        service.setLoginPassword("steve", "long enough").join();
        service.setRecoveryPasswordInGame("steve", "recovery pw").join();

        assertEquals(AdminResult.DONE, service.resetKey("steve").join());
        assertNull(account("steve").playerPub());
        assertFalse(account("steve").restricted());
        assertTrue(service.claimUnboundKey("steve", key(2)).join());
        assertFalse(service.claimUnboundKey("steve", key(3)).join());

        assertEquals(AdminResult.DONE, service.resetRecovery("steve").join());
        assertNull(account("steve").recoveryHash());
        assertEquals(AdminResult.DONE, service.resetPassword("steve").join());
        assertNull(account("steve").passwordHash());
        assertTrue(account("steve").restricted());
        assertEquals(AdminResult.DONE, service.trust("steve").join());
        assertFalse(account("steve").restricted());
        assertEquals(AdminResult.DONE, service.resetAll("steve").join());
        assertTrue(service.find("steve").join().isEmpty());

        assertEquals(AdminResult.NO_SUCH_ACCOUNT, service.trust("nobody").join());
        assertEquals(List.of("bind", "set_password", "set_recovery", "reset_key", "bind_after_reset",
                "reset_recovery", "reset_password", "trust", "reset_all"), events("steve"));
    }

    @Test
    void auditRetention() {
        service.bindNew("steve", "Steve", key(1)).join();
        clock.advance(Duration.ofDays(91));
        service.recordLogin("steve", "Steve", null).join();
        assertEquals(1, service.purgeOldAudit().join());
        assertEquals(List.of("login_ok"), events("steve"));
    }

    @Test
    void fullHashQueueIsReportedAsBusy() {
        service.close();
        service = open(new AccountServiceConfig(new PasswordHasher.Params(64 * 1024, 3, 1), PasswordPolicy.DEFAULT,
                1, 1, 10, Duration.ofMinutes(15), Duration.ofDays(90)));
        for (int i = 0; i < 12; i++) {
            service.bindNew("p" + i, "P" + i, key(i)).join();
        }
        List<CompletableFuture<PasswordResult>> results = new ArrayList<>();
        for (int i = 0; i < 12; i++) {
            results.add(service.setLoginPasswordInGame("p" + i, "long enough " + i));
        }
        List<PasswordResult.Status> statuses = results.stream().map(f -> f.join().status()).toList();
        assertTrue(statuses.contains(PasswordResult.Status.RATE_LIMITED), statuses.toString());
        assertTrue(statuses.contains(PasswordResult.Status.OK), statuses.toString());
    }
}
