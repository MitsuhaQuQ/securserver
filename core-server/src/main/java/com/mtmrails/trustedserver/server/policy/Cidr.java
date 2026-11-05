package com.mtmrails.trustedserver.server.policy;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/** CIDR 网段，例如 {@code 10.0.0.0/8}、{@code 2001:db8::/32}。IPv4 映射的 IPv6 地址按 IPv4 匹配。 */
public final class Cidr {
    private final byte[] network;
    private final int prefix;
    private final String text;

    private Cidr(byte[] network, int prefix, String text) {
        this.network = network;
        this.prefix = prefix;
        this.text = text;
    }

    /**
     * 解析 {@code 地址/前缀}；只写地址时视为单个主机。只接受字面 IP 地址，不做 DNS 解析。
     *
     * @throws IllegalArgumentException 格式非法，或主机位不为零
     */
    public static Cidr parse(String text) {
        String trimmed = text.trim();
        int slash = trimmed.indexOf('/');
        String host = slash < 0 ? trimmed : trimmed.substring(0, slash);
        // 只接受字面地址，避免 getByName 把类似 "deadbeef" 的字符串当作主机名去做 DNS 解析
        boolean ipv4 = host.matches("\\d{1,3}(\\.\\d{1,3}){3}");
        boolean ipv6 = host.contains(":") && host.matches("[0-9A-Fa-f:.]+");
        if (!ipv4 && !ipv6) {
            throw new IllegalArgumentException("not a literal IP address: " + text);
        }
        byte[] address;
        try {
            address = InetAddress.getByName(host).getAddress();
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("not a literal IP address: " + text, e);
        }
        int max = address.length * 8;
        int prefix;
        try {
            prefix = slash < 0 ? max : Integer.parseInt(trimmed.substring(slash + 1));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("invalid prefix length: " + text, e);
        }
        if (prefix < 0 || prefix > max) {
            throw new IllegalArgumentException("prefix length out of range: " + text);
        }
        if (!Arrays.equals(mask(address, prefix), address)) {
            throw new IllegalArgumentException("host bits must be zero: " + text);
        }
        return new Cidr(address, prefix, trimmed);
    }

    public boolean contains(InetAddress address) {
        byte[] bytes = address.getAddress();
        if (network.length == 4 && NetworkKey.isIpv4Mapped(bytes)) {
            bytes = Arrays.copyOfRange(bytes, 12, 16);
        }
        return bytes.length == network.length && Arrays.equals(mask(bytes, prefix), network);
    }

    private static byte[] mask(byte[] address, int prefix) {
        byte[] out = address.clone();
        for (int i = 0; i < out.length; i++) {
            int bits = Math.max(0, Math.min(8, prefix - i * 8));
            out[i] &= (byte) (0xFF << (8 - bits));
        }
        return out;
    }

    @Override
    public String toString() {
        return text;
    }
}
