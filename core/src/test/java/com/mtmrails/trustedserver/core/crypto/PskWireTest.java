package com.mtmrails.trustedserver.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class PskWireTest {
    private static byte[] bytes(int length, int seed) {
        byte[] value = new byte[length];
        for (int i = 0; i < length; i++) {
            value[i] = (byte) (seed + i);
        }
        return value;
    }

    @Test
    void allMessagesRoundTrip() throws Exception {
        PresharedKeyHandshake.Challenge challenge = new PresharedKeyHandshake.Challenge(bytes(32, 1));
        byte[] challengeBytes = PskWire.encodeChallenge(challenge);
        assertEquals(PskWire.Type.CHALLENGE, PskWire.type(challengeBytes));
        assertArrayEquals(challenge.serverNonce(), PskWire.decodeChallenge(challengeBytes).serverNonce());

        PresharedKeyHandshake.ClientResponse response =
                new PresharedKeyHandshake.ClientResponse(bytes(32, 2), bytes(32, 3));
        byte[] responseBytes = PskWire.encodeClientResponse(response);
        assertEquals(PskWire.Type.CLIENT_RESPONSE, PskWire.type(responseBytes));
        assertArrayEquals(response.clientNonce(), PskWire.decodeClientResponse(responseBytes).clientNonce());
        assertArrayEquals(response.proof(), PskWire.decodeClientResponse(responseBytes).proof());

        PresharedKeyHandshake.ServerProof proof = new PresharedKeyHandshake.ServerProof(bytes(32, 4));
        byte[] proofBytes = PskWire.encodeServerProof(proof);
        assertEquals(PskWire.Type.SERVER_PROOF, PskWire.type(proofBytes));
        assertArrayEquals(proof.proof(), PskWire.decodeServerProof(proofBytes).proof());

        byte[] ack = PskWire.encodeAck();
        assertEquals(PskWire.Type.ACK, PskWire.type(ack));
        PskWire.decodeAck(ack);

        byte[] prompt = PskWire.encodePromptRequest();
        assertEquals(PskWire.Type.PROMPT_REQUEST, PskWire.type(prompt));
        PskWire.decodePromptRequest(prompt);
    }

    @Test
    void rejectsTruncationTrailingDataWrongMagicAndWrongType() {
        byte[] challenge = PskWire.encodeChallenge(new PresharedKeyHandshake.Challenge(bytes(32, 1)));
        for (int length = 0; length < challenge.length; length++) {
            byte[] truncated = Arrays.copyOf(challenge, length);
            assertThrows(MalformedMessageException.class, () -> PskWire.decodeChallenge(truncated));
        }
        assertThrows(MalformedMessageException.class,
                () -> PskWire.decodeChallenge(Arrays.copyOf(challenge, challenge.length + 1)));
        byte[] badMagic = challenge.clone();
        badMagic[0] ^= 1;
        assertThrows(MalformedMessageException.class, () -> PskWire.decodeChallenge(badMagic));
        assertThrows(MalformedMessageException.class, () -> PskWire.decodeServerProof(challenge));
    }

    @Test
    void contextHasExactCanonicalEncoding() {
        assertArrayEquals(concat("trustedserver:psk:v1".getBytes(StandardCharsets.US_ASCII),
                new byte[] {0, 0, 5}, "Steve".getBytes(StandardCharsets.UTF_8)), PskWire.context("Steve"));
        assertThrows(IllegalArgumentException.class, () -> PskWire.context("\ud800"));
    }

    @Test
    void completeWireExchangeAuthenticatesBothSides() throws Exception {
        byte[] key = bytes(32, 9);
        byte[] context = PskWire.context("OfflinePlayer");
        PresharedKeyHandshake.Server server =
                PresharedKeyHandshake.beginServer(key, context, new java.security.SecureRandom());

        PresharedKeyHandshake.Client client = PresharedKeyHandshake.beginClient(key, context,
                PskWire.decodeChallenge(PskWire.encodeChallenge(server.challenge())),
                new java.security.SecureRandom());
        PresharedKeyHandshake.ServerProof serverProof = server.verify(
                PskWire.decodeClientResponse(PskWire.encodeClientResponse(client.response())));
        client.verify(PskWire.decodeServerProof(PskWire.encodeServerProof(serverProof)));
        PskWire.decodeAck(PskWire.encodeAck());

        assertTrue(server.authenticated());
        assertTrue(client.authenticated());
    }

    private static byte[] concat(byte[]... parts) {
        int size = Arrays.stream(parts).mapToInt(a -> a.length).sum();
        byte[] result = new byte[size];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, result, offset, part.length);
            offset += part.length;
        }
        return result;
    }
}
