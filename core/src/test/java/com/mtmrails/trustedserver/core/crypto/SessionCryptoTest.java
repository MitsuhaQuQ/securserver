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
        assertEquals("54535256010200028520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
                + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0000000100",
                s(fixture.serverHelloPayload));
        assertEquals("54535256020002de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
                + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f00",
                s(fixture.clientHelloPayload));
        assertEquals("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", s(fixture.sharedSecret));
        assertEquals("60861b9ddfa406e2eded9a9937ac40c9540425c346e659460ed573d16a7ca051", s(fixture.transcript));

        assertKey("b909edfb8176c7e6f0b3fb211108e4e38bd4872b4498a8d480e4830e642d0416", SessionKeys.Purpose.AUTH, Direction.S2C);
        assertKey("8a675b6a58c36212f6e616edbb680a0f0adda6c5daade9172f372fa5759cff27", SessionKeys.Purpose.AUTH, Direction.C2S);
        assertKey("836a89fa9d7d3c8d13bdfe2c5d57d22d68caaeee71361870bfaebb933c896365", SessionKeys.Purpose.TUNNEL, Direction.S2C);
        assertKey("49f72060b7fe29218405c2230915372457bda2a4f90f5fa70d4d674a8a89671b", SessionKeys.Purpose.TUNNEL, Direction.C2S);
        assertKey("fad5dcc83aa52e6c08fec5239239e1ba9ebc4ed6e94e023d03ead19f773b166c", SessionKeys.Purpose.PASSWORD, Direction.S2C);
        assertKey("f0cee3b3473bcf3c783581c9d7d6b0f334fec095abbe04eab357eda6edcfd84c", SessionKeys.Purpose.PASSWORD, Direction.C2S);

        Ed25519.KeyPairData identity = Ed25519.fromSeed(KatFixture.SERVER_ID_SEED, KatFixture.SERVER_ID_PUB);
        byte[] signature = HandshakeSignatures.signServer(identity, fixture.transcript);
        assertEquals("4f5c0417fb538505de0768a83add89f1575c40c8bdc97d674a57824bb2555731"
                + "41dc0b56a1fd143577c5f9d22b65756896d1ad7cc6f96e551cabeab0969f850f", s(signature));

        String challengePayload = "5453525603e3648cffe97279f8e926f2889bb9c5f23f563400a1a3a301da7e6e24c2fb76024fe67b"
                + "877c55ad0c9ffc54b9ff3a162ff7f3353b6b451d5f9a267e38e0881fa7647eab8fc6f6d098e650582dd36d"
                + "a217ea25b184866114381fadac0598cef74fa6a50e4c56c067544f1ac7a1fd99e4d0";
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
        assertEquals("tsrv v2 auth s2c", SessionKeys.label(SessionKeys.Purpose.AUTH, Direction.S2C));
        assertEquals("tsrv v2 password c2s", SessionKeys.label(SessionKeys.Purpose.PASSWORD, Direction.C2S));
        assertEquals("tsrv v2 tunnel s2c", SessionKeys.label(SessionKeys.Purpose.TUNNEL, Direction.S2C));
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
