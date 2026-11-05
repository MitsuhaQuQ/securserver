package com.mtmrails.trustedserver.core.crypto;

import static com.mtmrails.trustedserver.core.crypto.Hex.h;

import com.mtmrails.trustedserver.core.ProtocolVersion;
import com.mtmrails.trustedserver.core.message.ClientHello;
import com.mtmrails.trustedserver.core.message.MessageCodec;
import com.mtmrails.trustedserver.core.message.ServerHello;

/** 冻结的已知答案向量所用的固定输入。 */
final class KatFixture {
    static final byte[] SERVER_EPH_SCALAR = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    static final byte[] CLIENT_EPH_SCALAR = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    static final byte[] SERVER_ID_SEED = h("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    static final byte[] SERVER_ID_PUB = h("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    static final String USERNAME = "Steve";

    final byte[] serverNonce = new byte[32];
    final byte[] clientNonce = new byte[32];
    final byte[] serverHelloPayload;
    final byte[] clientHelloPayload;
    final byte[] sharedSecret;
    final byte[] transcript;

    KatFixture() throws Exception {
        for (int i = 0; i < 32; i++) {
            serverNonce[i] = (byte) i;
            clientNonce[i] = (byte) (0x20 + i);
        }
        serverHelloPayload = MessageCodec.encodePlain(new ServerHello(new int[] {ProtocolVersion.CURRENT},
                X25519.publicKeyOf(SERVER_EPH_SCALAR), serverNonce, ServerHello.FEATURE_TUNNEL_AVAILABLE, false));
        clientHelloPayload = MessageCodec.encodePlain(new ClientHello(ProtocolVersion.CURRENT,
                X25519.publicKeyOf(CLIENT_EPH_SCALAR), clientNonce, false));
        sharedSecret = X25519.agree(SERVER_EPH_SCALAR, X25519.publicKeyOf(CLIENT_EPH_SCALAR));
        transcript = Transcript.compute(serverHelloPayload, clientHelloPayload, USERNAME);
    }

    SessionKeys keys() {
        return SessionKeys.derive(sharedSecret.clone(), serverNonce, clientNonce, transcript);
    }
}
