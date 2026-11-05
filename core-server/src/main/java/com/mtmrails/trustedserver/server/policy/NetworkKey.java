package com.mtmrails.trustedserver.server.policy;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.HexFormat;

/**
 * IP 维度计数所用的键：IPv4 按单个地址，IPv6 按 /64 网段（同一用户通常拥有整个 /64，可随意换地址）。
 * IPv4 映射的 IPv6 地址（::ffff:a.b.c.d）按 IPv4 处理。
 */
public final class NetworkKey {
    private NetworkKey() {
    }

    public static String of(InetAddress address) {
        byte[] bytes = address.getAddress();
        if (address instanceof Inet4Address) {
            return "ip4:" + address.getHostAddress();
        }
        if (address instanceof Inet6Address && isIpv4Mapped(bytes)) {
            return "ip4:" + (bytes[12] & 0xFF) + "." + (bytes[13] & 0xFF) + "." + (bytes[14] & 0xFF) + "."
                    + (bytes[15] & 0xFF);
        }
        return "ip6:" + HexFormat.of().formatHex(bytes, 0, 8) + "/64";
    }

    public static boolean isIpv4(InetAddress address) {
        return address instanceof Inet4Address || isIpv4Mapped(address.getAddress());
    }

    static boolean isIpv4Mapped(byte[] bytes) {
        if (bytes.length != 16) {
            return false;
        }
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return bytes[10] == (byte) 0xFF && bytes[11] == (byte) 0xFF;
    }
}
