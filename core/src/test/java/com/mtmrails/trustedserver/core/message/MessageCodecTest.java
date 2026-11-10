package com.mtmrails.trustedserver.core.message;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import org.junit.jupiter.api.Test;

class MessageCodecTest {
    private static byte[] filled(int length, int seed) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) (seed + i);
        }
        return out;
    }

    /** 每种消息类型至少一个样例。 */
    static List<Message> samples() {
        return List.of(
                new ServerHello(new int[] {2, 1}, filled(32, 1), filled(32, 2),
                        ServerHello.FEATURE_TUNNEL_AVAILABLE | ServerHello.FEATURE_TUNNEL_REQUIRED, true),
                new ServerHello(new int[] {1}, filled(32, 3), filled(32, 4), 0, false),
                new ClientHello(1, filled(32, 5), filled(32, 6), true),
                new ClientHello(0, filled(32, 7), filled(32, 8), false),
                new Challenge(filled(32, 9), filled(64, 10)),
                new ClientProof(filled(32, 11), filled(64, 12)),
                new PasswordRequest(PasswordRequest.Kind.LOGIN, 3, 90),
                new PasswordRequest(PasswordRequest.Kind.RECOVERY, 1, 60),
                new PasswordRequest(PasswordRequest.Kind.SET, 0, 120),
                new PasswordRequest(PasswordRequest.Kind.RESET, 0, 60),
                new PasswordAnswer("hunter2"),
                new PasswordAnswer(""),
                PasswordAnswer.requestReset(),
                PasswordAnswer.clear(),
                new Finish(true, List.of("尚未设置找回密码", "notice 2")),
                new Finish(false, List.of()),
                new FinishAck(),
                new SetPassword("新密码🔑"),
                new SetRecoveryPassword("recovery"),
                new PasswordResult(PasswordResult.Status.OK, "密码已设定"),
                new PasswordResult(PasswordResult.Status.RATE_LIMITED, ""));
    }

    private static byte[] payload(Message message) {
        return new Envelope(message.type(), MessageCodec.encodeBody(message)).toBytes();
    }

    @Test
    void samplesCoverEveryType() {
        Set<MessageType> covered = EnumSet.noneOf(MessageType.class);
        samples().forEach(m -> covered.add(m.type()));
        assertEquals(EnumSet.allOf(MessageType.class), covered);
    }

    @Test
    void bodiesRoundTrip() throws Exception {
        for (Message message : samples()) {
            byte[] body = MessageCodec.encodeBody(message);
            assertEquals(message, MessageCodec.decodeBody(message.type(), body), message.toString());
        }
    }

    @Test
    void plainMessagesRoundTripThroughEnvelope() throws Exception {
        for (Message message : samples()) {
            if (!message.type().encrypted()) {
                byte[] payload = MessageCodec.encodePlain(message);
                assertEquals(message, MessageCodec.decodePlain(message.type().channel(), payload));
            }
        }
    }

    @Test
    void plainCodecRefusesEncryptedTypes() {
        for (Message message : samples()) {
            if (message.type().encrypted()) {
                assertThrows(IllegalArgumentException.class, () -> MessageCodec.encodePlain(message));
                assertThrows(MalformedMessageException.class,
                        () -> MessageCodec.decodePlain(message.type().channel(), payload(message)));
            }
        }
    }

    @Test
    void everyTruncationIsRejected() {
        for (Message message : samples()) {
            byte[] body = MessageCodec.encodeBody(message);
            for (int length = 0; length < body.length; length++) {
                byte[] truncated = Arrays.copyOf(body, length);
                assertThrows(MalformedMessageException.class,
                        () -> MessageCodec.decodeBody(message.type(), truncated),
                        message.type() + " truncated to " + length);
            }
        }
    }

    @Test
    void trailingBytesAreRejected() {
        for (Message message : samples()) {
            byte[] body = MessageCodec.encodeBody(message);
            byte[] extended = Arrays.copyOf(body, body.length + 1);
            assertThrows(MalformedMessageException.class, () -> MessageCodec.decodeBody(message.type(), extended));
        }
    }

    @Test
    void envelopeChecksMagicTypeAndChannel() {
        byte[] good = payload(new FinishAck());
        byte[] badMagic = good.clone();
        badMagic[0] = 'X';
        assertThrows(MalformedMessageException.class, () -> Envelope.parse(Channel.AUTH, badMagic));

        byte[] unknownType = good.clone();
        unknownType[4] = (byte) 0xEE;
        assertThrows(MalformedMessageException.class, () -> Envelope.parse(Channel.AUTH, unknownType));

        assertThrows(MalformedMessageException.class, () -> Envelope.parse(Channel.AUTH, new byte[] {'T', 'S'}));
    }

    @Test
    void everyTypeIsRejectedOnTheOtherChannel() throws Exception {
        for (Message message : samples()) {
            byte[] payload = payload(message);
            Channel own = message.type().channel();
            Channel other = own == Channel.AUTH ? Channel.PASSWORD : Channel.AUTH;
            assertEquals(message.type(), Envelope.parse(own, payload).type());
            assertThrows(MalformedMessageException.class, () -> Envelope.parse(other, payload),
                    message.type() + " on " + other);
        }
    }

    @Test
    void passwordTypesLiveOnlyOnPasswordChannel() {
        Set<MessageType> passwordTypes = EnumSet.of(MessageType.PASSWORD_REQUEST, MessageType.PASSWORD_ANSWER,
                MessageType.SET_PASSWORD, MessageType.SET_RECOVERY_PASSWORD, MessageType.PASSWORD_RESULT);
        for (MessageType type : MessageType.values()) {
            assertEquals(passwordTypes.contains(type), type.channel() == Channel.PASSWORD, type.toString());
        }
    }

    @Test
    void oversizedPayloadIsRejected() {
        byte[] huge = new byte[Limits.MAX_PAYLOAD + 1];
        System.arraycopy(payload(new FinishAck()), 0, huge, 0, Envelope.HEADER_LENGTH);
        assertThrows(MalformedMessageException.class, () -> Envelope.parse(Channel.AUTH, huge));
    }

    @Test
    void randomInputOnlyEverFailsWithMalformedMessage() {
        Random random = new Random(20261030L);
        for (int i = 0; i < 20_000; i++) {
            byte[] data = new byte[random.nextInt(200)];
            random.nextBytes(data);
            for (MessageType type : MessageType.values()) {
                assertDecodesOrMalformed(type, data);
            }
        }
    }

    @Test
    void bitFlipsOnlyEverFailWithMalformedMessage() {
        Random random = new Random(42L);
        for (Message message : samples()) {
            byte[] body = MessageCodec.encodeBody(message);
            for (int i = 0; i < 500 && body.length > 0; i++) {
                byte[] mutated = body.clone();
                mutated[random.nextInt(mutated.length)] ^= (byte) (1 << random.nextInt(8));
                assertDecodesOrMalformed(message.type(), mutated);
            }
        }
    }

    private static void assertDecodesOrMalformed(MessageType type, byte[] body) {
        try {
            Message decoded = MessageCodec.decodeBody(type, body);
            // 能解码的必须能原样编码回去（编码唯一）
            assertArrayEquals(body, MessageCodec.encodeBody(decoded), type.toString());
        } catch (MalformedMessageException expected) {
            // 预期之内
        }
    }

    @Test
    void validationRules() {
        assertThrows(IllegalArgumentException.class,
                () -> new ServerHello(new int[] {1}, filled(32, 0), filled(32, 0), ServerHello.FEATURE_TUNNEL_REQUIRED, false));
        assertThrows(IllegalArgumentException.class,
                () -> new ServerHello(new int[] {1}, filled(32, 0), filled(32, 0), 1 << 5, false));
        assertThrows(IllegalArgumentException.class,
                () -> new ServerHello(new int[0], filled(32, 0), filled(32, 0), 0, false));
        assertThrows(IllegalArgumentException.class,
                () -> new ServerHello(new int[] {0}, filled(32, 0), filled(32, 0), 0, false));
        assertThrows(IllegalArgumentException.class, () -> new Challenge(filled(31, 0), filled(64, 0)));
        assertThrows(IllegalArgumentException.class, () -> new PasswordRequest(PasswordRequest.Kind.SET, 1, 60));
        assertThrows(IllegalArgumentException.class, () -> new PasswordRequest(PasswordRequest.Kind.RESET, 1, 60));
        assertThrows(IllegalArgumentException.class, () -> new PasswordRequest(PasswordRequest.Kind.LOGIN, 3, 0));
        assertThrows(IllegalArgumentException.class, () -> new SetPassword(""));
        assertThrows(IllegalArgumentException.class, () -> new SetRecoveryPassword(""));
        assertTrue(new PasswordAnswer("").skipped());
        assertFalse(new PasswordAnswer("x").skipped());
        assertThrows(IllegalArgumentException.class,
                () -> new PasswordAnswer(PasswordAnswer.Action.SUBMIT, ""));
        assertThrows(IllegalArgumentException.class,
                () -> new PasswordAnswer(PasswordAnswer.Action.CLEAR, "secret"));
        assertEquals("recovery", new PasswordAnswer(PasswordAnswer.Action.REQUEST_RESET, "recovery").password());
    }

    @Test
    void versionTwoPasswordAnswersAreRejected() {
        // v2 body was only a VarInt-length-prefixed string: empty and "x" respectively.
        assertThrows(MalformedMessageException.class,
                () -> MessageCodec.decodeBody(MessageType.PASSWORD_ANSWER, new byte[] {0}));
        assertThrows(MalformedMessageException.class,
                () -> MessageCodec.decodeBody(MessageType.PASSWORD_ANSWER, new byte[] {1, 'x'}));
        assertThrows(MalformedMessageException.class,
                () -> MessageCodec.decodeBody(MessageType.PASSWORD_ANSWER, new byte[] {4, 0}));
    }

    @Test
    void serverHelloRequiresCanonicalOnlineModeFlag() throws Exception {
        for (boolean onlineMode : new boolean[] {false, true}) {
            ServerHello hello = new ServerHello(new int[] {2}, filled(32, 1), filled(32, 2), 0, onlineMode);
            byte[] payload = MessageCodec.encodePlain(hello);
            assertEquals(onlineMode ? 1 : 0, payload[payload.length - 1]);
            assertEquals(hello, MessageCodec.decodePlain(Channel.AUTH, payload));
            payload[payload.length - 1] = 2;
            assertThrows(MalformedMessageException.class, () -> MessageCodec.decodePlain(Channel.AUTH, payload));
        }
    }

    @Test
    void passwordLengthCountsCodePoints() {
        String emoji = "🔑"; // 1 个码点、2 个 char、4 个 UTF-8 字节
        new SetPassword(emoji.repeat(Limits.MAX_PASSWORD_CODE_POINTS));
        assertThrows(IllegalArgumentException.class,
                () -> new SetPassword(emoji.repeat(Limits.MAX_PASSWORD_CODE_POINTS + 1)));
        assertThrows(IllegalArgumentException.class,
                () -> new PasswordAnswer("a".repeat(Limits.MAX_PASSWORD_CODE_POINTS + 1)));
    }

    @Test
    void passwordsNeverAppearInToString() {
        String secret = "super-secret-密码";
        for (Message message : List.of(new PasswordAnswer(secret), new SetPassword(secret),
                new SetRecoveryPassword(secret))) {
            assertFalse(message.toString().contains(secret), message.type().toString());
        }
    }

    @Test
    void byteArraysAreDefensivelyCopied() {
        byte[] key = filled(32, 0);
        Challenge challenge = new Challenge(key, filled(64, 0));
        key[0] = 99;
        assertEquals(0, challenge.serverIdPub()[0]);
        challenge.serverIdPub()[0] = 99;
        assertEquals(0, challenge.serverIdPub()[0]);

        int[] versions = {1};
        ServerHello hello = new ServerHello(versions, filled(32, 0), filled(32, 0), 0, false);
        versions[0] = 7;
        hello.versions()[0] = 7;
        assertArrayEquals(new int[] {1}, hello.versions());
    }

    @Test
    void channelIdsResolve() {
        assertEquals(Channel.AUTH, Channel.fromId("trustedserver:auth").orElseThrow());
        assertEquals(Channel.PASSWORD, Channel.fromId("trustedserver:password").orElseThrow());
        assertTrue(Channel.fromId("minecraft:brand").isEmpty());
    }
}
