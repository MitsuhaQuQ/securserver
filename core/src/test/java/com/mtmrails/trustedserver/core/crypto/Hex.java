package com.mtmrails.trustedserver.core.crypto;

import java.util.HexFormat;

final class Hex {
    private Hex() {
    }

    static byte[] h(String hex) {
        return HexFormat.of().parseHex(hex.replace(" ", ""));
    }

    static String s(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }
}
