package com.mtmrails.trustedserver.core.crypto;

/** 线上方向；标签用作 AES-GCM nonce 的前 4 字节（PROTOCOL.md 4.3.2）。 */
public enum Direction {
    /** 服务端 → 客户端，标签 {@code 53 32 43 00}（"S2C\0"）。 */
    S2C("s2c", new byte[] {0x53, 0x32, 0x43, 0x00}),
    /** 客户端 → 服务端，标签 {@code 43 32 53 00}（"C2S\0"）。 */
    C2S("c2s", new byte[] {0x43, 0x32, 0x53, 0x00});

    private final String label;
    private final byte[] tag;

    Direction(String label, byte[] tag) {
        this.label = label;
        this.tag = tag;
    }

    /** 密钥派生标签中使用的名称。 */
    public String label() {
        return label;
    }

    public byte[] tag() {
        return tag.clone();
    }
}
