package com.mtmrails.trustedserver.core.tunnel;

import java.nio.charset.StandardCharsets;

/** 隧道帧常量（PROTOCOL.md 第 5 节）。 */
final class TunnelFrames {
    static final int TAG_LENGTH = 16;
    static final int MAX_PLAINTEXT = 65536;
    /** L = 明文长度 + 16。 */
    static final int MIN_L = 1 + TAG_LENGTH;
    static final int MAX_L = MAX_PLAINTEXT + TAG_LENGTH;
    /** 长度前缀最多 3 字节（65552 < 2^21）。 */
    static final int MAX_LENGTH_BYTES = 3;
    static final byte[] AAD_PREFIX = "tsrv v3 tunnel frame".getBytes(StandardCharsets.US_ASCII);

    private TunnelFrames() {
    }

    static byte[] aad(byte[] lengthBytes) {
        byte[] aad = new byte[AAD_PREFIX.length + lengthBytes.length];
        System.arraycopy(AAD_PREFIX, 0, aad, 0, AAD_PREFIX.length);
        System.arraycopy(lengthBytes, 0, aad, AAD_PREFIX.length, lengthBytes.length);
        return aad;
    }
}
