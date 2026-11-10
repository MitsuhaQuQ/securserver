package com.mtmrails.trustedserver.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import java.util.Arrays;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class OnlineTokenWireTest {
    private final OnlineTokenWire.Challenge challenge = new OnlineTokenWire.Challenge(
            filled(32, 1), UUID.fromString("12345678-1234-5678-9abc-def012345678"), "Player", filled(32, 2));

    @Test
    void roundTripsAllMessagesAndProofs() throws Exception {
        byte[] token = filled(32, 3);
        OnlineTokenWire.Challenge decoded = OnlineTokenWire.decodeChallenge(
                OnlineTokenWire.encodeChallenge(challenge));
        assertArrayEquals(challenge.serverIdentity(), decoded.serverIdentity());
        assertTrue(OnlineTokenWire.verifiesToken(token, decoded, new OnlineTokenWire.ClientProof(true,
                OnlineTokenWire.tokenProof(token, decoded))));
        assertFalse(OnlineTokenWire.verifiesToken(filled(32, 4), decoded,
                new OnlineTokenWire.ClientProof(true, OnlineTokenWire.tokenProof(token, decoded))));
        assertArrayEquals(token, OnlineTokenWire.decodeIssue(OnlineTokenWire.encodeIssue(token)));
        byte[] ack = OnlineTokenWire.issueAck(token, decoded);
        assertTrue(OnlineTokenWire.verifiesAck(token, decoded,
                OnlineTokenWire.decodeAck(OnlineTokenWire.encodeAck(ack))));
    }

    @Test
    void missingTokenAndMalformedMessagesAreStrict() throws Exception {
        OnlineTokenWire.ClientProof missing = new OnlineTokenWire.ClientProof(false, new byte[0]);
        assertFalse(OnlineTokenWire.verifiesToken(filled(32, 1), challenge, missing));
        assertFalse(OnlineTokenWire.decodeClientProof(OnlineTokenWire.encodeClientProof(missing)).hasToken());
        byte[] valid = OnlineTokenWire.encodeChallenge(challenge);
        assertThrows(MalformedMessageException.class,
                () -> OnlineTokenWire.decodeChallenge(Arrays.copyOf(valid, valid.length - 1)));
        assertThrows(MalformedMessageException.class,
                () -> OnlineTokenWire.decodeChallenge(Arrays.copyOf(valid, valid.length + 1)));
    }

    private static byte[] filled(int length, int value) {
        byte[] out = new byte[length];
        Arrays.fill(out, (byte) value);
        return out;
    }
}
