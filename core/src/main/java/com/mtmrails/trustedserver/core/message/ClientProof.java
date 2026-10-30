package com.mtmrails.trustedserver.core.message;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;
import java.util.Arrays;
import java.util.HexFormat;

/** C→S，加密：玩家公钥与对 transcript 的签名（PROTOCOL.md 4.5）。 */
public record ClientProof(byte[] playerPub, byte[] playerSig) implements AuthMessage {
    public ClientProof {
        playerPub = Limits.copyExact(playerPub, Limits.ED25519_KEY_LENGTH, "playerPub");
        playerSig = Limits.copyExact(playerSig, Limits.ED25519_SIGNATURE_LENGTH, "playerSig");
    }

    @Override
    public byte[] playerPub() {
        return playerPub.clone();
    }

    @Override
    public byte[] playerSig() {
        return playerSig.clone();
    }

    @Override
    public MessageType type() {
        return MessageType.CLIENT_PROOF;
    }

    @Override
    public void writeBody(WireWriter out) {
        out.fixed(playerPub).fixed(playerSig);
    }

    static ClientProof read(WireReader in) throws MalformedMessageException {
        return new ClientProof(in.fixed(Limits.ED25519_KEY_LENGTH), in.fixed(Limits.ED25519_SIGNATURE_LENGTH));
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ClientProof other
                && Arrays.equals(playerPub, other.playerPub)
                && Arrays.equals(playerSig, other.playerSig);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(playerPub) + Arrays.hashCode(playerSig);
    }

    @Override
    public String toString() {
        HexFormat hex = HexFormat.of();
        return "ClientProof[playerPub=" + hex.formatHex(playerPub)
                + ", playerSig=" + hex.formatHex(playerSig) + "]";
    }
}
