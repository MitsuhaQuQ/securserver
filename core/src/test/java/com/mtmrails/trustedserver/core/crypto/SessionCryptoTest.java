package com.mtmrails.trustedserver.core.crypto;

import static com.mtmrails.trustedserver.core.crypto.Hex.h;
import static com.mtmrails.trustedserver.core.crypto.Hex.s;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mtmrails.trustedserver.core.ProtocolVersion;
import com.mtmrails.trustedserver.core.message.Challenge;
import com.mtmrails.trustedserver.core.message.ClientHello;
import com.mtmrails.trustedserver.core.message.Envelope;
import com.mtmrails.trustedserver.core.message.Finish;
import com.mtmrails.trustedserver.core.message.FinishAck;
import com.mtmrails.trustedserver.core.message.Limits;
import com.mtmrails.trustedserver.core.message.MessageCodec;
import com.mtmrails.trustedserver.core.message.MessageType;
import com.mtmrails.trustedserver.core.message.PasswordAnswer;
import com.mtmrails.trustedserver.core.message.PasswordRequest;
import com.mtmrails.trustedserver.core.message.PasswordResult;
import com.mtmrails.trustedserver.core.message.ServerHello;
import com.mtmrails.trustedserver.core.message.SetPassword;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class SessionCryptoTest {
    private KatFixture fixture;
    private SessionKeys serverKeys;
    private SessionKeys clientKeys;

    @BeforeEach
    void setUp() throws Exception {
        fixture = new KatFixture();
        serverKeys = fixture.keys();
        clientKeys = fixture.keys();
    }

    // ---- 冻结的已知答案向量：Hello → transcript → 六把密钥 → 首条密文 ----
    // transcript、六把密钥已用 Python 标准库独立重算，服务端签名已用 OpenSSL 验证。

    @Test
    void knownAnswerVector() throws Exception {
        assertEquals("54535256010200038520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
                + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000100",
                s(fixture.serverHelloPayload));
        assertEquals("54535256020003de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
                + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00",
                s(fixture.clientHelloPayload));
        assertEquals("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", s(fixture.sharedSecret));
        assertEquals("bae79106630df10e016e69884fa4da909669bd371740cca20267df0d09552d42", s(fixture.transcript));

        assertKey("07ad7d79cd7e0ae34cc46fd559fc457114cccc48bb4c46fac7ac692976fdd3fb", SessionKeys.Purpose.AUTH, Direction.S2C);
        assertKey("0d6e4ca76c1ecf1a30fd4c9b9613aae2c091cd837963bac3ab6de07ddfbbd0d1", SessionKeys.Purpose.AUTH, Direction.C2S);
        assertKey("dc8f4729cfc2031d1b6adde26c26a315e8a339c0296e58f952f16562871b8312", SessionKeys.Purpose.TUNNEL, Direction.S2C);
        assertKey("59a90acf01b37dab99c41815b523c54a89d5f4265039ab220d15236d295d74d4", SessionKeys.Purpose.TUNNEL, Direction.C2S);
        assertKey("8baab284565ff64f5c10ebb61e56fbc0f8c167ad442f091f087a74e431b89023", SessionKeys.Purpose.PASSWORD, Direction.S2C);
        assertKey("0bd9d1792ecfcafaf50f62911ee743191e7bad082108dbeb8bd233358b3ad802", SessionKeys.Purpose.PASSWORD, Direction.C2S);

        Ed25519.KeyPairData identity = Ed25519.fromSeed(KatFixture.SERVER_ID_SEED, KatFixture.SERVER_ID_PUB);
        byte[] signature = HandshakeSignatures.signServer(identity, fixture.transcript);
        assertEquals("594403ccd4c93c589220f8377090a29090c545debcd9bf27cb65a9231124a0d98"
                + "ba35fb71fe93cb69a0c360c6a9f67b8a1abeaf141ef731383f292c58120f00d", s(signature));

        String challengePayload = "5453525603d0e282be6e46a69a1a901092b47cfd76955a1a6954c7c6de7b8bf79528cfaccf1146fced81053"
                + "2086c7f97760c92198faa7f97ee90f9deb09c0f6a44cd33c3a32e44aba9a1ab74b904e6743f84c33038ba78"
                + "867d11e6e6636de0fce49bc1c5d13c818ec21d85528fc241da2920a0f0ed";
        byte[] sealed = serverKeys.authChannel(Side.SERVER).seal(new Challenge(KatFixture.SERVER_ID_PUB, signature));
        assertEquals(challengePayload, s(sealed));

        Challenge opened = (Challenge) clientKeys.authChannel(Side.CLIENT).open(h(challengePayload));
        assertTrue(HandshakeSignatures.verifyServer(opened.serverIdPub(), fixture.transcript, opened.serverSig()));
    }

    private void assertKey(String expected, SessionKeys.Purpose purpose, Direction direction) {
        assertEquals(expected, s(serverKeys.key(purpose, direction)), purpose + " " + direction);
    }

    @Test
    void labelsAreExactAscii() {
        assertEquals("tsrv v3 auth s2c", SessionKeys.label(SessionKeys.Purpose.AUTH, Direction.S2C));
        assertEquals("tsrv v3 password c2s", SessionKeys.label(SessionKeys.Purpose.PASSWORD, Direction.C2S));
        assertEquals("tsrv v3 tunnel s2c", SessionKeys.label(SessionKeys.Purpose.TUNNEL, Direction.S2C));
        assertArrayEquals(h("53324300"), Direction.S2C.tag());
        assertArrayEquals(h("43325300"), Direction.C2S.tag());
    }

    // ---- 双向收发 ----

    @Test
    void bothDirectionsRoundTrip() throws Exception {
        SecureMessageChannel server = serverKeys.authChannel(Side.SERVER);
        SecureMessageChannel client = clientKeys.authChannel(Side.CLIENT);
        Finish finish = new Finish(true, List.of("hello"));
        assertEquals(finish, client.open(server.seal(finish)));
        assertEquals(new FinishAck(), server.open(client.seal(new FinishAck())));
    }

    @Test
    void emptyBodyRoundTrips() throws Exception {
        byte[] payload = clientKeys.authChannel(Side.CLIENT).seal(new FinishAck());
        assertEquals(Envelope.HEADER_LENGTH + Aes256Gcm.TAG_LENGTH, payload.length);
        assertEquals(new FinishAck(), serverKeys.authChannel(Side.SERVER).open(payload));
    }

    // ---- 方向与用途隔离 ----

    @Test
    void directionsAndPurposesAreIsolated() throws Exception {
        byte[] aad = {1};
        byte[] sealed = new AeadStream(serverKeys.key(SessionKeys.Purpose.AUTH, Direction.S2C), Direction.S2C,
                AeadStream.Role.SEAL).seal(aad, new byte[] {42});

        // 同一密钥、错误方向标签
        assertThrows(CryptoException.class, () -> new AeadStream(serverKeys.key(SessionKeys.Purpose.AUTH, Direction.S2C),
                Direction.C2S, AeadStream.Role.OPEN).open(aad, sealed));
        // 正确方向标签、其他用途或方向的密钥
        for (SessionKeys.Purpose purpose : SessionKeys.Purpose.values()) {
            for (Direction direction : Direction.values()) {
                if (purpose == SessionKeys.Purpose.AUTH && direction == Direction.S2C) {
                    continue;
                }
                assertThrows(CryptoException.class, () -> new AeadStream(serverKeys.key(purpose, direction),
                        Direction.S2C, AeadStream.Role.OPEN).open(aad, sealed), purpose + " " + direction);
            }
        }
        assertArrayEquals(new byte[] {42}, new AeadStream(serverKeys.key(SessionKeys.Purpose.AUTH, Direction.S2C),
                Direction.S2C, AeadStream.Role.OPEN).open(aad, sealed));
    }

    @Test
    void endpointCannotOpenItsOwnOutput() throws Exception {
        SecureMessageChannel server = serverKeys.authChannel(Side.SERVER);
        byte[] payload = server.seal(new Finish(false, List.of()));
        assertThrows(CryptoException.class, () -> server.open(payload));
    }

    @Test
    void messagesAreBoundToTheirChannel() throws Exception {
        byte[] passwordPayload = serverKeys.passwordChannel(Side.SERVER)
                .seal(new PasswordRequest(PasswordRequest.Kind.LOGIN, 3, 60));
        SecureMessageChannel clientAuth = clientKeys.authChannel(Side.CLIENT);
        assertThrows(MalformedMessageException.class, () -> clientAuth.open(passwordPayload));
        assertFalse(clientAuth.isOpen());

        SecureMessageChannel serverAuth = serverKeys.authChannel(Side.SERVER);
        assertThrows(IllegalArgumentException.class, () -> serverAuth.seal(new PasswordAnswer("x")));
        assertThrows(IllegalArgumentException.class, () -> serverAuth.seal(new ServerHello(
                new int[] {ProtocolVersion.CURRENT}, new byte[32], new byte[32], 0, false)));
    }

    @Test
    void plaintextTypesAreRejectedOnEncryptedChannel() throws Exception {
        byte[] hello = MessageCodec.encodePlain(new ClientHello(ProtocolVersion.CURRENT, new byte[32], new byte[32], false));
        SecureMessageChannel server = serverKeys.authChannel(Side.SERVER);
        assertThrows(MalformedMessageException.class, () -> server.open(hello));
        assertFalse(server.isOpen());
    }

    // ---- 篡改与失败后不可复用 ----

    @Test
    void headerTypeIsAuthenticated() throws Exception {
        byte[] payload = serverKeys.authChannel(Side.SERVER).seal(new Finish(false, List.of()));
        payload[4] = (byte) MessageType.CHALLENGE.id(); // 换成同频道另一个加密类型
        SecureMessageChannel client = clientKeys.authChannel(Side.CLIENT);
        assertThrows(CryptoException.class, () -> client.open(payload));
    }

    @Test
    void invalidTagKillsTheChannelForGood() throws Exception {
        SecureMessageChannel server = serverKeys.authChannel(Side.SERVER);
        byte[] first = server.seal(new Finish(false, List.of()));
        SecureMessageChannel client = clientKeys.authChannel(Side.CLIENT);

        byte[] tampered = first.clone();
        tampered[tampered.length - 1] ^= 1;
        assertThrows(CryptoException.class, () -> client.open(tampered));
        assertFalse(client.isOpen());
        // 原本合法的密文也不能再解开，发送方向同样关闭
        assertThrows(CryptoException.class, () -> client.open(first));
        assertThrows(CryptoException.class, () -> client.seal(new FinishAck()));
    }

    @Test
    void replayAndReorderingAreRejected() throws Exception {
        SecureMessageChannel server = serverKeys.authChannel(Side.SERVER);
        byte[] m1 = server.seal(new Finish(false, List.of("1")));
        byte[] m2 = server.seal(new Finish(false, List.of("2")));

        SecureMessageChannel reordered = fixture.keys().authChannel(Side.CLIENT);
        assertThrows(CryptoException.class, () -> reordered.open(m2));

        SecureMessageChannel replayed = clientKeys.authChannel(Side.CLIENT);
        replayed.open(m1);
        assertThrows(CryptoException.class, () -> replayed.open(m1));
    }

    @Test
    void truncatedPayloadsAreRejected() throws Exception {
        byte[] payload = serverKeys.authChannel(Side.SERVER).seal(new Finish(false, List.of()));
        for (int length = 0; length < payload.length; length++) {
            byte[] truncated = Arrays.copyOf(payload, length);
            SecureMessageChannel client = fixture.keys().authChannel(Side.CLIENT);
            try {
                client.open(truncated);
                throw new AssertionError("truncated payload of " + length + " bytes was accepted");
            } catch (CryptoException | MalformedMessageException expected) {
                assertFalse(client.isOpen());
            }
        }
    }

    // ---- 长度边界 ----

    /** 构造消息体恰好为 {@code bodyLength} 字节的 Finish：4 条 1000 字节提示 + 1 条补齐。 */
    private static Finish finishWithBody(int bodyLength) {
        List<String> notices = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            notices.add("a".repeat(1000));
        }
        int used = 3 + 4 * (2 + 1000); // result + tunnel + count + 4 × (VarInt 长度 + 内容)
        notices.add("b".repeat(bodyLength - used - 1)); // 余下 < 128 字节，VarInt 长度占 1 字节
        Finish finish = new Finish(false, notices);
        assertEquals(bodyLength, MessageCodec.encodeBody(finish).length);
        return finish;
    }

    @Test
    void bodyLimitIs4075Bytes() throws Exception {
        assertEquals(4075, SecureMessageChannel.MAX_BODY);
        Finish max = finishWithBody(4075);
        byte[] payload = serverKeys.authChannel(Side.SERVER).seal(max);
        assertEquals(Limits.MAX_PAYLOAD, payload.length);
        assertEquals(max, clientKeys.authChannel(Side.CLIENT).open(payload));

        Finish tooBig = finishWithBody(4076);
        assertThrows(IllegalArgumentException.class, () -> fixture.keys().authChannel(Side.SERVER).seal(tooBig));
    }

    @Test
    void oversizedIncomingPayloadIsRejectedBeforeDecryption() throws Exception {
        byte[] payload = Arrays.copyOf(serverKeys.authChannel(Side.SERVER).seal(finishWithBody(4075)),
                Limits.MAX_PAYLOAD + 1);
        SecureMessageChannel client = clientKeys.authChannel(Side.CLIENT);
        assertThrows(MalformedMessageException.class, () -> client.open(payload));
        assertFalse(client.isOpen());
    }

    // ---- 使用上限 ----

    @Test
    void recordLimitClosesStreamBeforeProcessing() throws Exception {
        byte[] key = new byte[32];
        AeadStream sealer = new AeadStream(key, Direction.S2C, AeadStream.Role.SEAL, 3, Long.MAX_VALUE);
        AeadStream opener = new AeadStream(key, Direction.S2C, AeadStream.Role.OPEN, 3, Long.MAX_VALUE);
        for (int i = 0; i < 3; i++) {
            opener.open(new byte[0], sealer.seal(new byte[0], new byte[0])); // 空消息也计数
        }
        assertEquals(3, sealer.sequence());
        assertThrows(CryptoException.class, () -> sealer.seal(new byte[0], new byte[0]));
        assertFalse(sealer.isOpen());
        assertThrows(CryptoException.class, () -> opener.open(new byte[0], new byte[16]));
        assertFalse(opener.isOpen());
    }

    @Test
    void byteLimitClosesStreamBeforeProcessing() throws Exception {
        byte[] key = new byte[32];
        AeadStream sealer = new AeadStream(key, Direction.C2S, AeadStream.Role.SEAL, Long.MAX_VALUE, 10);
        AeadStream opener = new AeadStream(key, Direction.C2S, AeadStream.Role.OPEN, Long.MAX_VALUE, 10);
        opener.open(new byte[0], sealer.seal(new byte[0], new byte[6]));
        byte[] last = sealer.seal(new byte[0], new byte[4]);
        opener.open(new byte[0], last);
        assertThrows(CryptoException.class, () -> sealer.seal(new byte[0], new byte[1]));
        assertThrows(CryptoException.class, () -> opener.open(new byte[0], new byte[17]));
    }

    @Test
    void defaultLimitsMatchProtocol() {
        assertEquals(1L << 24, AeadStream.MAX_RECORDS);
        assertEquals(1L << 36, AeadStream.MAX_PLAINTEXT_BYTES);
    }

    @Test
    void streamRolesCannotBeMixed() {
        AeadStream sealer = new AeadStream(new byte[32], Direction.S2C, AeadStream.Role.SEAL);
        assertThrows(IllegalStateException.class, () -> sealer.open(new byte[0], new byte[16]));
        AeadStream opener = new AeadStream(new byte[32], Direction.S2C, AeadStream.Role.OPEN);
        assertThrows(IllegalStateException.class, () -> opener.seal(new byte[0], new byte[0]));
    }

    // ---- 密码通道跨阶段计数连续 ----

    @Test
    void passwordChannelSequenceContinuesFromLoginToPlay() throws Exception {
        SecureMessageChannel server = serverKeys.passwordChannel(Side.SERVER);
        SecureMessageChannel client = clientKeys.passwordChannel(Side.CLIENT);

        // 登录阶段
        client.open(server.seal(new PasswordRequest(PasswordRequest.Kind.SET, 0, 90)));
        byte[] loginAnswer = client.seal(new PasswordAnswer("first"));
        assertEquals(new PasswordAnswer("first"), server.open(loginAnswer));

        // 游戏阶段：同一实例继续
        assertEquals(new SetPassword("second"), server.open(client.seal(new SetPassword("second"))));
        assertEquals(PasswordResult.Status.OK, ((PasswordResult) client.open(
                server.seal(new PasswordResult(PasswordResult.Status.OK, "")))).status());

        // 登录阶段的密码消息不能在游戏阶段重放
        assertThrows(CryptoException.class, () -> server.open(loginAnswer));
    }

    @Test
    void freshPasswordChannelCannotReadPlayPhaseMessages() throws Exception {
        SecureMessageChannel client = clientKeys.passwordChannel(Side.CLIENT);
        client.seal(new PasswordAnswer("login")); // 登录阶段已消耗序号 0
        byte[] play = client.seal(new SetPassword("play"));
        // 若错误地重建通道（序号回到 0），解不开
        assertThrows(CryptoException.class, () -> fixture.keys().passwordChannel(Side.SERVER).open(play));
    }

    // ---- transcript 与签名 ----

    @Test
    void transcriptBindsUsernameAndOnlineMode() throws Exception {
        assertFalse(Arrays.equals(fixture.transcript,
                Transcript.compute(fixture.serverHelloPayload, fixture.clientHelloPayload, "steve")));
        byte[] online = fixture.serverHelloPayload.clone();
        online[online.length - 1] = 1;
        assertFalse(Arrays.equals(fixture.transcript,
                Transcript.compute(online, fixture.clientHelloPayload, KatFixture.USERNAME)));
    }

    @Test
    void transcriptRequiresStrictHellos() {
        assertThrows(MalformedMessageException.class,
                () -> Transcript.compute(fixture.clientHelloPayload, fixture.serverHelloPayload, "Steve"));
        byte[] bad = fixture.serverHelloPayload.clone();
        bad[bad.length - 1] = 2; // online_mode 只能是 0 或 1
        assertThrows(MalformedMessageException.class,
                () -> Transcript.compute(bad, fixture.clientHelloPayload, "Steve"));
        byte[] trailing = Arrays.copyOf(fixture.clientHelloPayload, fixture.clientHelloPayload.length + 1);
        assertThrows(MalformedMessageException.class,
                () -> Transcript.compute(fixture.serverHelloPayload, trailing, "Steve"));
    }

    @Test
    void signatureLabelsSeparateServerAndClient() throws Exception {
        Ed25519.KeyPairData key = Ed25519.fromSeed(KatFixture.SERVER_ID_SEED, KatFixture.SERVER_ID_PUB);
        byte[] serverSig = HandshakeSignatures.signServer(key, fixture.transcript);
        assertTrue(HandshakeSignatures.verifyServer(KatFixture.SERVER_ID_PUB, fixture.transcript, serverSig));
        assertFalse(HandshakeSignatures.verifyClient(KatFixture.SERVER_ID_PUB, fixture.transcript, serverSig));

        byte[] otherTranscript = fixture.transcript.clone();
        otherTranscript[0] ^= 1;
        assertFalse(HandshakeSignatures.verifyServer(KatFixture.SERVER_ID_PUB, otherTranscript, serverSig));

        byte[] clientSig = HandshakeSignatures.signClient(key, fixture.transcript);
        assertTrue(HandshakeSignatures.verifyClient(KatFixture.SERVER_ID_PUB, fixture.transcript, clientSig));
        assertFalse(HandshakeSignatures.verifyServer(KatFixture.SERVER_ID_PUB, fixture.transcript, clientSig));
    }

    // ---- 密钥生命周期 ----

    @Test
    void destroyedKeysCannotBeUsed() {
        serverKeys.destroy();
        assertThrows(IllegalStateException.class, () -> serverKeys.key(SessionKeys.Purpose.AUTH, Direction.S2C));
        assertThrows(IllegalStateException.class, () -> serverKeys.authChannel(Side.SERVER));
    }

    @Test
    void deriveValidatesInputLengths() {
        assertThrows(IllegalArgumentException.class,
                () -> SessionKeys.derive(new byte[31], new byte[32], new byte[32], new byte[32]));
        assertThrows(IllegalArgumentException.class,
                () -> SessionKeys.derive(new byte[32], new byte[32], new byte[32], new byte[31]));
    }

    @Test
    void deriveWipesSharedSecret() {
        byte[] shared = fixture.sharedSecret.clone();
        SessionKeys.derive(shared, fixture.serverNonce, fixture.clientNonce, fixture.transcript);
        assertArrayEquals(new byte[32], shared);
    }
}
