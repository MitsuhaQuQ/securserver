package com.mtmrails.trustedserver.core.crypto;

import com.mtmrails.trustedserver.core.message.Channel;
import com.mtmrails.trustedserver.core.message.ClientHello;
import com.mtmrails.trustedserver.core.message.Message;
import com.mtmrails.trustedserver.core.message.MessageCodec;
import com.mtmrails.trustedserver.core.message.ServerHello;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireWriter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * {@code transcript_0 = SHA-256(server_hello_payload || client_hello_payload || username_field || online_mode_flag)}
 * （PROTOCOL.md 4.3.1）。
 */
public final class Transcript {
    public static final int LENGTH = 32;

    private Transcript() {
    }

    /**
     * @param serverHelloPayload 实际发送或收到的完整 ServerHello payload（含 magic 和 type）
     * @param clientHelloPayload 实际发送或收到的完整 ClientHello payload
     * @param username 原版登录 Hello 中的原始用户名，保留大小写、不做归一化
     * @throws MalformedMessageException 两个 payload 不是严格合法的对应 Hello
     */
    public static byte[] compute(byte[] serverHelloPayload, byte[] clientHelloPayload, String username)
            throws MalformedMessageException {
        Message serverHello = MessageCodec.decodePlain(Channel.AUTH, serverHelloPayload);
        if (!(serverHello instanceof ServerHello hello)) {
            throw new MalformedMessageException("expected ServerHello, got " + serverHello.type());
        }
        Message clientHello = MessageCodec.decodePlain(Channel.AUTH, clientHelloPayload);
        if (!(clientHello instanceof ClientHello)) {
            throw new MalformedMessageException("expected ClientHello, got " + clientHello.type());
        }
        byte[] usernameField = new WireWriter().varBytes(WireWriter.utf8(username), Integer.MAX_VALUE).toByteArray();

        MessageDigest sha256;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
        sha256.update(serverHelloPayload);
        sha256.update(clientHelloPayload);
        sha256.update(usernameField);
        sha256.update((byte) (hello.onlineMode() ? 1 : 0));
        return sha256.digest();
    }
}
