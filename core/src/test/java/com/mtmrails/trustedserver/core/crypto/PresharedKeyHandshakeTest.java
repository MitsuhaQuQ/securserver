package com.mtmrails.trustedserver.core.crypto;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class PresharedKeyHandshakeTest {
    private static final byte[] KEY = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] CONTEXT = "server-id|steve|protocol-2".getBytes(StandardCharsets.US_ASCII);

    @Test
    void bothSidesAuthenticateWithTheSameKeyAndContext() throws Exception {
        PresharedKeyHandshake.Server server = PresharedKeyHandshake.beginServer(KEY, CONTEXT, new SecureRandom());
        PresharedKeyHandshake.Client client = PresharedKeyHandshake.beginClient(
                KEY, CONTEXT, server.challenge(), new SecureRandom());

        PresharedKeyHandshake.ServerProof proof = server.verify(client.response());
        assertTrue(server.authenticated());
        assertFalse(client.authenticated());
        client.verify(proof);
        assertTrue(client.authenticated());
    }

    @Test
    void wrongKeyFailsAndServerIsSingleUse() {
        byte[] wrong = KEY.clone();
        wrong[0] ^= 1;
        PresharedKeyHandshake.Server server = PresharedKeyHandshake.beginServer(KEY, CONTEXT, new SecureRandom());
        PresharedKeyHandshake.Client client = PresharedKeyHandshake.beginClient(
                wrong, CONTEXT, server.challenge(), new SecureRandom());

        assertThrows(PskAuthenticationException.class, () -> server.verify(client.response()));
        assertFalse(server.authenticated());
        assertThrows(IllegalStateException.class, () -> server.verify(client.response()));
        assertThrows(IllegalStateException.class, server::challenge);
    }

    @Test
    void contextMismatchFails() {
        PresharedKeyHandshake.Server server = PresharedKeyHandshake.beginServer(KEY, CONTEXT, new SecureRandom());
        PresharedKeyHandshake.Client client = PresharedKeyHandshake.beginClient(KEY,
                "server-id|alex|protocol-2".getBytes(StandardCharsets.US_ASCII),
                server.challenge(), new SecureRandom());
        assertThrows(PskAuthenticationException.class, () -> server.verify(client.response()));
    }

    @Test
    void responseCannotBeReplayedAgainstAnotherChallenge() throws Exception {
        PresharedKeyHandshake.Server first = PresharedKeyHandshake.beginServer(KEY, CONTEXT, new SecureRandom());
        PresharedKeyHandshake.Client client = PresharedKeyHandshake.beginClient(
                KEY, CONTEXT, first.challenge(), new SecureRandom());
        PresharedKeyHandshake.ClientResponse response = client.response();
        first.verify(response);

        PresharedKeyHandshake.Server second = PresharedKeyHandshake.beginServer(KEY, CONTEXT, new SecureRandom());
        assertThrows(PskAuthenticationException.class, () -> second.verify(response));
    }

    @Test
    void tamperedServerProofFailsAndClientIsSingleUse() throws Exception {
        PresharedKeyHandshake.Server server = PresharedKeyHandshake.beginServer(KEY, CONTEXT, new SecureRandom());
        PresharedKeyHandshake.Client client = PresharedKeyHandshake.beginClient(
                KEY, CONTEXT, server.challenge(), new SecureRandom());
        byte[] proof = server.verify(client.response()).proof();
        proof[0] ^= 1;

        assertThrows(PskAuthenticationException.class,
                () -> client.verify(new PresharedKeyHandshake.ServerProof(proof)));
        assertFalse(client.authenticated());
        assertThrows(IllegalStateException.class,
                () -> client.verify(new PresharedKeyHandshake.ServerProof(new byte[32])));
    }

    @Test
    void challengeAndResponseDefensivelyCopyArrays() {
        PresharedKeyHandshake.Server server = PresharedKeyHandshake.beginServer(KEY, CONTEXT, new SecureRandom());
        PresharedKeyHandshake.Challenge challenge = server.challenge();
        byte[] original = challenge.serverNonce();
        challenge.serverNonce()[0] ^= 1;
        assertTrue(Arrays.equals(original, challenge.serverNonce()));

        PresharedKeyHandshake.Client client = PresharedKeyHandshake.beginClient(
                KEY, CONTEXT, challenge, new SecureRandom());
        PresharedKeyHandshake.ClientResponse response = client.response();
        byte[] responseProof = response.proof();
        response.proof()[0] ^= 1;
        assertTrue(Arrays.equals(responseProof, response.proof()));
    }

    @Test
    void rejectsShortKeyAndMalformedValues() {
        assertThrows(IllegalArgumentException.class,
                () -> PresharedKeyHandshake.beginServer(new byte[31], CONTEXT, new SecureRandom()));
        assertThrows(IllegalArgumentException.class,
                () -> new PresharedKeyHandshake.Challenge(new byte[31]));
        assertThrows(IllegalArgumentException.class,
                () -> new PresharedKeyHandshake.ClientResponse(new byte[32], new byte[31]));
    }
}
