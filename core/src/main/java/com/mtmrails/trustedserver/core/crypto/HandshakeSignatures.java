package com.mtmrails.trustedserver.core.crypto;

/**
 * Challenge 与 ClientProof 的签名（PROTOCOL.md 4.4、4.5）：
 * 对 ASCII 标签直接拼接 32 字节 transcript_0 做普通 Ed25519 签名，不做预哈希。
 */
public final class HandshakeSignatures {
    static final String SERVER_LABEL = "tsrv v3 server";
    static final String CLIENT_LABEL = "tsrv v3 client";

    private HandshakeSignatures() {
    }

    public static byte[] signServer(Ed25519.KeyPairData serverIdentity, byte[] transcript) {
        return serverIdentity.sign(input(SERVER_LABEL, transcript));
    }

    public static boolean verifyServer(byte[] serverIdPub, byte[] transcript, byte[] signature) {
        return Ed25519.verify(serverIdPub, input(SERVER_LABEL, transcript), signature);
    }

    public static byte[] signClient(Ed25519.KeyPairData playerKey, byte[] transcript) {
        return playerKey.sign(input(CLIENT_LABEL, transcript));
    }

    public static boolean verifyClient(byte[] playerPub, byte[] transcript, byte[] signature) {
        return Ed25519.verify(playerPub, input(CLIENT_LABEL, transcript), signature);
    }

    static byte[] input(String label, byte[] transcript) {
        return Bytes.concat(Bytes.ascii(label), Bytes.requireLength(transcript, Transcript.LENGTH, "transcript"));
    }
}
