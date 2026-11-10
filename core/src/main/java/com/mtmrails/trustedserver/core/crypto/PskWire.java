package com.mtmrails.trustedserver.core.crypto;

import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.core.wire.WireReader;
import com.mtmrails.trustedserver.core.wire.WireWriter;
import java.util.Arrays;

/** PSK 前置门禁子协议 v1 的严格编解码（PROTOCOL.md 1.1）。 */
public final class PskWire {
    public static final String CHANNEL = "trustedserver:psk";
    private static final byte[] MAGIC = {'T', 'S', 'P', 'K'};
    private static final byte[] CONTEXT_LABEL = Bytes.ascii("trustedserver:psk:v1");

    private PskWire() {
    }

    public enum Type {
        CHALLENGE(1),
        CLIENT_RESPONSE(2),
        SERVER_PROOF(3),
        ACK(4),
        PROMPT_REQUEST(5);

        private final int id;

        Type(int id) {
            this.id = id;
        }

        int id() {
            return id;
        }

        static Type fromId(int id) throws MalformedMessageException {
            for (Type type : values()) {
                if (type.id == id) {
                    return type;
                }
            }
            throw new MalformedMessageException("unknown PSK message type: " + id);
        }
    }

    public static byte[] encodeChallenge(PresharedKeyHandshake.Challenge challenge) {
        return writer(Type.CHALLENGE).fixed(challenge.serverNonce()).toByteArray();
    }

    public static PresharedKeyHandshake.Challenge decodeChallenge(byte[] payload)
            throws MalformedMessageException {
        WireReader reader = reader(payload, Type.CHALLENGE);
        PresharedKeyHandshake.Challenge challenge =
                new PresharedKeyHandshake.Challenge(reader.fixed(PresharedKeyHandshake.NONCE_LENGTH));
        reader.expectEnd();
        return challenge;
    }

    public static byte[] encodeClientResponse(PresharedKeyHandshake.ClientResponse response) {
        return writer(Type.CLIENT_RESPONSE).fixed(response.clientNonce()).fixed(response.proof()).toByteArray();
    }

    public static PresharedKeyHandshake.ClientResponse decodeClientResponse(byte[] payload)
            throws MalformedMessageException {
        WireReader reader = reader(payload, Type.CLIENT_RESPONSE);
        PresharedKeyHandshake.ClientResponse response = new PresharedKeyHandshake.ClientResponse(
                reader.fixed(PresharedKeyHandshake.NONCE_LENGTH), reader.fixed(PresharedKeyHandshake.PROOF_LENGTH));
        reader.expectEnd();
        return response;
    }

    public static byte[] encodeServerProof(PresharedKeyHandshake.ServerProof proof) {
        return writer(Type.SERVER_PROOF).fixed(proof.proof()).toByteArray();
    }

    public static PresharedKeyHandshake.ServerProof decodeServerProof(byte[] payload)
            throws MalformedMessageException {
        WireReader reader = reader(payload, Type.SERVER_PROOF);
        PresharedKeyHandshake.ServerProof proof =
                new PresharedKeyHandshake.ServerProof(reader.fixed(PresharedKeyHandshake.PROOF_LENGTH));
        reader.expectEnd();
        return proof;
    }

    public static byte[] encodeAck() {
        return writer(Type.ACK).toByteArray();
    }

    public static void decodeAck(byte[] payload) throws MalformedMessageException {
        reader(payload, Type.ACK).expectEnd();
    }

    /** 客户端已安装本 mod、但本地没有该服务器的 PSK，请求一次人工输入窗口。 */
    public static byte[] encodePromptRequest() {
        return writer(Type.PROMPT_REQUEST).toByteArray();
    }

    public static void decodePromptRequest(byte[] payload) throws MalformedMessageException {
        reader(payload, Type.PROMPT_REQUEST).expectEnd();
    }

    /** 返回消息类型，同时验证 magic；具体 body 长度由对应 decode 方法验证。 */
    public static Type type(byte[] payload) throws MalformedMessageException {
        WireReader reader = new WireReader(payload);
        if (!Arrays.equals(reader.fixed(MAGIC.length), MAGIC)) {
            throw new MalformedMessageException("bad PSK magic");
        }
        return Type.fromId(reader.u8());
    }

    /** PSK 证明绑定的规范上下文。 */
    public static byte[] context(String username) {
        byte[] encoded = WireWriter.utf8(username);
        if (encoded.length > 0xFFFF) {
            throw new IllegalArgumentException("username is too long for PSK context");
        }
        return new WireWriter().fixed(CONTEXT_LABEL).u8(0).u16(encoded.length).fixed(encoded).toByteArray();
    }

    private static WireWriter writer(Type type) {
        return new WireWriter().fixed(MAGIC).u8(type.id());
    }

    private static WireReader reader(byte[] payload, Type expected) throws MalformedMessageException {
        WireReader reader = new WireReader(payload);
        if (!Arrays.equals(reader.fixed(MAGIC.length), MAGIC)) {
            throw new MalformedMessageException("bad PSK magic");
        }
        Type actual = Type.fromId(reader.u8());
        if (actual != expected) {
            throw new MalformedMessageException("expected PSK " + expected + ", got " + actual);
        }
        return reader;
    }
}
