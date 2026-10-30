package com.mtmrails.trustedserver.core.message;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;
import java.util.Arrays;
import java.util.HexFormat;

/** S→C，加密：服务端身份公钥与对 transcript 的签名（PROTOCOL.md 4.4）。 */
public record Challenge(byte[] serverIdPub, byte[] serverSig) implements AuthMessage {
    public Challenge {
        serverIdPub = Limits.copyExact(serverIdPub, Limits.ED25519_KEY_LENGTH, "serverIdPub");
        serverSig = Limits.copyExact(serverSig, Limits.ED25519_SIGNATURE_LENGTH, "serverSig");
    }

    @Override
    public byte[] serverIdPub() {
        return serverIdPub.clone();
    }

    @Override
    public byte[] serverSig() {
        return serverSig.clone();
    }

    @Override
    public MessageType type() {
        return MessageType.CHALLENGE;
    }

    @Override
    public void writeBody(WireWriter out) {
        out.fixed(serverIdPub).fixed(serverSig);
    }

    static Challenge read(WireReader in) throws MalformedMessageException {
        return new Challenge(in.fixed(Limits.ED25519_KEY_LENGTH), in.fixed(Limits.ED25519_SIGNATURE_LENGTH));
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Challenge other
                && Arrays.equals(serverIdPub, other.serverIdPub)
                && Arrays.equals(serverSig, other.serverSig);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(serverIdPub) + Arrays.hashCode(serverSig);
    }

    @Override
    public String toString() {
        HexFormat hex = HexFormat.of();
        return "Challenge[serverIdPub=" + hex.formatHex(serverIdPub)
                + ", serverSig=" + hex.formatHex(serverSig) + "]";
    }
}
