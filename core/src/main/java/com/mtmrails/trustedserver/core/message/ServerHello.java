package com.mtmrails.trustedserver.core.message;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;
import java.util.Arrays;
import java.util.HexFormat;

/** S→C，明文（PROTOCOL.md 4.1）。 */
public record ServerHello(int[] versions, byte[] serverEphPub, byte[] serverNonce, int features, boolean onlineMode)
        implements AuthMessage {
    /** 服务端允许隧道模式。 */
    public static final int FEATURE_TUNNEL_AVAILABLE = 1;
    /** 服务端强制隧道模式（隐含 {@link #FEATURE_TUNNEL_AVAILABLE}）。 */
    public static final int FEATURE_TUNNEL_REQUIRED = 1 << 1;
    private static final int KNOWN_FEATURES = FEATURE_TUNNEL_AVAILABLE | FEATURE_TUNNEL_REQUIRED;

    public ServerHello {
        if (versions == null || versions.length == 0 || versions.length > Limits.MAX_VERSIONS) {
            throw new IllegalArgumentException("versions must list 1.." + Limits.MAX_VERSIONS + " entries");
        }
        versions = versions.clone();
        for (int version : versions) {
            if (version < 1 || version > 0xFFFF) {
                throw new IllegalArgumentException("invalid protocol version: " + version);
            }
        }
        serverEphPub = Limits.copyExact(serverEphPub, Limits.X25519_KEY_LENGTH, "serverEphPub");
        serverNonce = Limits.copyExact(serverNonce, Limits.NONCE_LENGTH, "serverNonce");
        if ((features & ~KNOWN_FEATURES) != 0) {
            throw new IllegalArgumentException("unknown feature bits: 0x" + Integer.toHexString(features));
        }
        if ((features & FEATURE_TUNNEL_REQUIRED) != 0 && (features & FEATURE_TUNNEL_AVAILABLE) == 0) {
            throw new IllegalArgumentException("TUNNEL_REQUIRED without TUNNEL_AVAILABLE");
        }
    }

    @Override
    public int[] versions() {
        return versions.clone();
    }

    @Override
    public byte[] serverEphPub() {
        return serverEphPub.clone();
    }

    @Override
    public byte[] serverNonce() {
        return serverNonce.clone();
    }

    public boolean tunnelAvailable() {
        return (features & FEATURE_TUNNEL_AVAILABLE) != 0;
    }

    public boolean tunnelRequired() {
        return (features & FEATURE_TUNNEL_REQUIRED) != 0;
    }

    @Override
    public MessageType type() {
        return MessageType.SERVER_HELLO;
    }

    @Override
    public void writeBody(WireWriter out) {
        WireWriter list = new WireWriter();
        for (int version : versions) {
            list.u16(version);
        }
        out.varBytes(list.toByteArray(), Limits.MAX_VERSIONS * 2)
                .fixed(serverEphPub)
                .fixed(serverNonce)
                .u32(features)
                .bool(onlineMode);
    }

    static ServerHello read(WireReader in) throws MalformedMessageException {
        byte[] list = in.varBytes(Limits.MAX_VERSIONS * 2);
        if (list.length % 2 != 0) {
            throw new MalformedMessageException("version list has odd length " + list.length);
        }
        WireReader listReader = new WireReader(list);
        int[] versions = new int[list.length / 2];
        for (int i = 0; i < versions.length; i++) {
            versions[i] = listReader.u16();
        }
        return new ServerHello(versions,
                in.fixed(Limits.X25519_KEY_LENGTH),
                in.fixed(Limits.NONCE_LENGTH),
                in.u32(),
                in.bool());
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof ServerHello other
                && Arrays.equals(versions, other.versions)
                && Arrays.equals(serverEphPub, other.serverEphPub)
                && Arrays.equals(serverNonce, other.serverNonce)
                && features == other.features
                && onlineMode == other.onlineMode;
    }

    @Override
    public int hashCode() {
        int h = Arrays.hashCode(versions);
        h = 31 * h + Arrays.hashCode(serverEphPub);
        h = 31 * h + Arrays.hashCode(serverNonce);
        h = 31 * h + features;
        return 31 * h + Boolean.hashCode(onlineMode);
    }

    @Override
    public String toString() {
        HexFormat hex = HexFormat.of();
        return "ServerHello[versions=" + Arrays.toString(versions)
                + ", serverEphPub=" + hex.formatHex(serverEphPub)
                + ", serverNonce=" + hex.formatHex(serverNonce)
                + ", features=0x" + Integer.toHexString(features) + ", onlineMode=" + onlineMode + "]";
    }
}
