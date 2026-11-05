package com.mtmrails.trustedserver.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mtmrails.trustedserver.core.crypto.SecureMessageChannel;
import com.mtmrails.trustedserver.core.crypto.SessionKeys;
import com.mtmrails.trustedserver.core.crypto.Side;
import com.mtmrails.trustedserver.core.message.PasswordAnswer;
import com.mtmrails.trustedserver.core.message.PasswordResult;
import com.mtmrails.trustedserver.core.message.SetPassword;
import com.mtmrails.trustedserver.core.message.SetRecoveryPassword;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class PasswordCommandTest {
    @Test
    void validCommands() {
        assertEquals(new PasswordCommand.Set(PasswordCommand.Kind.LOGIN, "s3cret!"),
                PasswordCommand.parse("/passwd s3cret! s3cret!"));
        assertEquals(new PasswordCommand.Set(PasswordCommand.Kind.RECOVERY, "密码"),
                PasswordCommand.parse("/RecoveryPasswd 密码 密码"));
    }

    @Test
    void ourCommandsWithBadArgumentsAreStillIntercepted() {
        for (String line : new String[] {"/passwd", "/passwd a", "/passwd a b c", "/passwd  a a", "/passwd a ",
                "/recoverypasswd x"}) {
            assertInstanceOf(PasswordCommand.Invalid.class, PasswordCommand.parse(line), line);
        }
        PasswordCommand mismatch = PasswordCommand.parse("/passwd first second");
        assertInstanceOf(PasswordCommand.Invalid.class, mismatch);
        assertFalse(mismatch.toString().contains("first"));
    }

    @Test
    void otherInputIsNotOurs() {
        for (String line : new String[] {"/help", "hello /passwd a a", "/passwdx a a", "passwd a a", "", "/"}) {
            assertInstanceOf(PasswordCommand.NotOurs.class, PasswordCommand.parse(line), line);
        }
        assertInstanceOf(PasswordCommand.NotOurs.class, PasswordCommand.parse(null));
    }

    @Test
    void passwordIsRedactedInToString() {
        assertFalse(PasswordCommand.parse("/passwd hunter22 hunter22").toString().contains("hunter22"));
    }

    private static SecureMessageChannel[] channels() {
        byte[] shared = new byte[32];
        byte[] t = new byte[32];
        new SecureRandom().nextBytes(shared);
        SessionKeys keys = SessionKeys.derive(shared, new byte[32], new byte[32], t);
        return new SecureMessageChannel[] {keys.passwordChannel(Side.CLIENT), keys.passwordChannel(Side.SERVER)};
    }

    @Test
    void playClientRoundTripAndOneRequestAtATime() throws Exception {
        SecureMessageChannel[] ch = channels();
        PlayPasswordClient client = new PlayPasswordClient(ch[0]);
        byte[] request = client.request(new PasswordCommand.Set(PasswordCommand.Kind.RECOVERY, "recovery"));
        assertTrue(client.awaitingResult());
        assertThrows(IllegalStateException.class,
                () -> client.request(new PasswordCommand.Set(PasswordCommand.Kind.LOGIN, "x")));
        assertEquals(new SetRecoveryPassword("recovery"), ch[1].open(request));
        PasswordResult result = client.onPayload(ch[1].seal(new PasswordResult(PasswordResult.Status.OK, "ok")));
        assertEquals(PasswordResult.Status.OK, result.status());
        assertFalse(client.awaitingResult());
        assertEquals(new SetPassword("login pw"),
                ch[1].open(client.request(new PasswordCommand.Set(PasswordCommand.Kind.LOGIN, "login pw"))));
    }

    @Test
    void unexpectedMessageClosesClientChannel() throws Exception {
        SecureMessageChannel[] ch = channels();
        PlayPasswordClient client = new PlayPasswordClient(ch[0]);
        // 游戏阶段服务端只应发 PasswordResult；收到其他类型说明通道状态不对
        assertThrows(MalformedMessageException.class, () -> client.onPayload(ch[1].seal(new PasswordAnswer("x"))));
        assertFalse(ch[0].isOpen());
    }
}
