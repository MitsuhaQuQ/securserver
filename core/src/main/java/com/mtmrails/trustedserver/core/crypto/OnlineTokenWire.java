package com.mtmrails.trustedserver.core.crypto;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.UUID;

/** 正版 session 验证后的按账号令牌登记与确认子协议。 */
public final class OnlineTokenWire {
    public static final String CHANNEL = "trustedserver:online_token";
    public static final int TOKEN_LENGTH = 32;
    public static final int NONCE_LENGTH = 32;
    public static final int PROOF_LENGTH = 32;
    private static final int USERNAME_MAX_BYTES = 64;
    private static final byte[] MAGIC = {'T', 'S', 'T', 'K'};
    private static final byte[] PROOF_LABEL = Bytes.ascii("tsrv online token proof v1");
    private static final byte[] ACK_LABEL = Bytes.ascii("tsrv online token ack v1");

    private OnlineTokenWire() {
    }

    public record Challenge(byte[] serverIdentity, UUID playerId, String username, byte[] nonce) {
        public Challenge {
            serverIdentity = require(serverIdentity, Ed25519.PUBLIC_KEY_LENGTH, "serverIdentity");
            if (playerId == null || username == null) {
                throw new IllegalArgumentException("playerId and username are required");
            }
            if (WireWriter.utf8(username).length > USERNAME_MAX_BYTES) {
                throw new IllegalArgumentException("username is too long");
            }
            nonce = require(nonce, NONCE_LENGTH, "nonce");
        }

        @Override public byte[] serverIdentity() { return serverIdentity.clone(); }
        @Override public byte[] nonce() { return nonce.clone(); }
    }

    public record ClientProof(boolean hasToken, byte[] proof) {
        public ClientProof {
            proof = require(proof, hasToken ? PROOF_LENGTH : 0, "proof");
        }

        @Override public byte[] proof() { return proof.clone(); }
    }

    public static byte[] encodeChallenge(Challenge value) {
        return writer(1).fixed(value.serverIdentity()).fixed(uuid(value.playerId()))
                .string(value.username(), USERNAME_MAX_BYTES).fixed(value.nonce()).toByteArray();
    }

    public static Challenge decodeChallenge(byte[] payload) throws MalformedMessageException {
        WireReader reader = reader(payload, 1);
        Challenge value = new Challenge(reader.fixed(Ed25519.PUBLIC_KEY_LENGTH),
                readUuid(reader), reader.string(USERNAME_MAX_BYTES), reader.fixed(NONCE_LENGTH));
        reader.expectEnd();
        return value;
    }

    public static byte[] encodeClientProof(ClientProof value) {
        return writer(2).bool(value.hasToken()).fixed(value.proof()).toByteArray();
    }

    public static ClientProof decodeClientProof(byte[] payload) throws MalformedMessageException {
        WireReader reader = reader(payload, 2);
        boolean hasToken = reader.bool();
        ClientProof value = new ClientProof(hasToken, reader.fixed(hasToken ? PROOF_LENGTH : 0));
        reader.expectEnd();
        return value;
    }

    public static byte[] encodeIssue(byte[] token) {
        return writer(3).fixed(require(token, TOKEN_LENGTH, "token")).toByteArray();
    }

    public static byte[] decodeIssue(byte[] payload) throws MalformedMessageException {
        WireReader reader = reader(payload, 3);
        byte[] token = reader.fixed(TOKEN_LENGTH);
        reader.expectEnd();
        return token;
    }

    public static byte[] encodeAck(byte[] proof) {
        return writer(4).fixed(require(proof, PROOF_LENGTH, "proof")).toByteArray();
    }

    public static byte[] decodeAck(byte[] payload) throws MalformedMessageException {
        WireReader reader = reader(payload, 4);
        byte[] proof = reader.fixed(PROOF_LENGTH);
        reader.expectEnd();
        return proof;
    }

    public static byte[] tokenProof(byte[] token, Challenge challenge) {
        return derive(token, PROOF_LABEL, challenge);
    }

    public static byte[] issueAck(byte[] token, Challenge challenge) {
        return derive(token, ACK_LABEL, challenge);
    }

    public static boolean verifiesToken(byte[] expectedToken, Challenge challenge, ClientProof response) {
        if (!response.hasToken()) {
            return false;
        }
        byte[] expected = tokenProof(expectedToken, challenge);
        try {
            return MessageDigest.isEqual(expected, response.proof());
        } finally {
            Arrays.fill(expected, (byte) 0);
        }
    }

    public static boolean verifiesAck(byte[] token, Challenge challenge, byte[] received) {
        byte[] expected = issueAck(token, challenge);
        try {
            return MessageDigest.isEqual(expected, received);
        } finally {
            Arrays.fill(expected, (byte) 0);
        }
    }

    private static byte[] derive(byte[] token, byte[] label, Challenge challenge) {
        byte[] checked = require(token, TOKEN_LENGTH, "token");
        byte[] context = new WireWriter().fixed(label).fixed(challenge.serverIdentity())
                .fixed(uuid(challenge.playerId())).string(challenge.username(), USERNAME_MAX_BYTES)
                .fixed(challenge.nonce()).toByteArray();
        try {
            return Hkdf.expand(checked, context, PROOF_LENGTH);
        } finally {
            Arrays.fill(checked, (byte) 0);
        }
    }

    private static WireWriter writer(int type) {
        return new WireWriter().fixed(MAGIC).u8(type);
    }

    private static WireReader reader(byte[] payload, int expected) throws MalformedMessageException {
        WireReader reader = new WireReader(payload);
        if (!Arrays.equals(reader.fixed(MAGIC.length), MAGIC)) {
            throw new MalformedMessageException("bad online token magic");
        }
        int actual = reader.u8();
        if (actual != expected) {
            throw new MalformedMessageException("expected online token type " + expected + ", got " + actual);
        }
        return reader;
    }

    private static byte[] uuid(UUID value) {
        return new WireWriter().u32((int) (value.getMostSignificantBits() >>> 32))
                .u32((int) value.getMostSignificantBits()).u32((int) (value.getLeastSignificantBits() >>> 32))
                .u32((int) value.getLeastSignificantBits()).toByteArray();
    }

    private static UUID readUuid(WireReader reader) throws MalformedMessageException {
        long most = Integer.toUnsignedLong(reader.u32()) << 32 | Integer.toUnsignedLong(reader.u32());
        long least = Integer.toUnsignedLong(reader.u32()) << 32 | Integer.toUnsignedLong(reader.u32());
        return new UUID(most, least);
    }

    private static byte[] require(byte[] value, int length, String name) {
        if (value == null || value.length != length) {
            throw new IllegalArgumentException(name + " must be " + length + " bytes");
        }
        return value.clone();
    }
}
