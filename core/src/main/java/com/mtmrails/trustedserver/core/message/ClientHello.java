package com.mtmrails.trustedserver.core.message;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;
import java.util.Arrays;
import java.util.HexFormat;

/**
 * C→S，明文（PROTOCOL.md 4.2）。{@code version} 为 0 表示没有共同版本。
 */
public record ClientHello(int version, byte[] clientEphPub, byte[] clientNonce, boolean wantTunnel)
        implements AuthMessage {
    public ClientHello {
        if (version < 0 || version > 0xFFFF) {
            throw new IllegalArgumentException("invalid protocol version: " + version);
        }
        clientEphPub = Limits.copyExact(clientEphPub, Limits.X25519_KEY_LENGTH, "clientEphPub");
        clientNonce = Limits.copyExact(clientNonce, Limits.NONCE_LENGTH, "clientNonce");
    }

    @Override
    public byte[] clientEphPub() {
        return clientEphPub.clone();
    }

    @Override
    public byte[] clientNonce() {
        return clientNonce.clone();
    }

    @Override
    public MessageType type() {
        return MessageType.CLIENT_HELLO;
    }

    @Override
    public void writeBody(WireWriter out) {
        out.u16(version).fixed(clientEphPub).fixed(clientNonce).bool(wantTunnel);
    }

    static ClientHello read(WireReader in) throws MalformedMessageException {
        return new ClientHello(in.u16(),
                in.fixed(Limits.X25519_KEY_LENGTH),
                in.fixed(Limits.NONCE_LENGTH),
                in.bool());
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ClientHello other
                && version == other.version
                && Arrays.equals(clientEphPub, other.clientEphPub)
                && Arrays.equals(clientNonce, other.clientNonce)
                && wantTunnel == other.wantTunnel;
    }

    @Override
    public int hashCode() {
        int h = version;
        h = 31 * h + Arrays.hashCode(clientEphPub);
        h = 31 * h + Arrays.hashCode(clientNonce);
        return 31 * h + Boolean.hashCode(wantTunnel);
    }

    @Override
    public String toString() {
        HexFormat hex = HexFormat.of();
        return "ClientHello[version=" + version
                + ", clientEphPub=" + hex.formatHex(clientEphPub)
                + ", clientNonce=" + hex.formatHex(clientNonce)
                + ", wantTunnel=" + wantTunnel + "]";
    }
}
