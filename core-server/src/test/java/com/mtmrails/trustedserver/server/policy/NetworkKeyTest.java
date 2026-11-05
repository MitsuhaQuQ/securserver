package com.mtmrails.trustedserver.server.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import org.junit.jupiter.api.Test;

class NetworkKeyTest {
    static InetAddress ip(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    @Test
    void ipv4IsPerAddress() {
        assertEquals("ip4:203.0.113.7", NetworkKey.of(ip("203.0.113.7")));
        assertNotEquals(NetworkKey.of(ip("203.0.113.7")), NetworkKey.of(ip("203.0.113.8")));
        assertTrue(NetworkKey.isIpv4(ip("203.0.113.7")));
    }

    @Test
    void ipv6IsPerSlash64() {
        assertEquals(NetworkKey.of(ip("2001:db8:1:2::1")), NetworkKey.of(ip("2001:db8:1:2:ffff:ffff:ffff:ffff")));
        assertNotEquals(NetworkKey.of(ip("2001:db8:1:2::1")), NetworkKey.of(ip("2001:db8:1:3::1")));
        assertEquals("ip6:20010db800010002/64", NetworkKey.of(ip("2001:db8:1:2::1")));
        assertFalse(NetworkKey.isIpv4(ip("2001:db8::1")));
    }

    @Test
    void ipv4MappedIpv6CountsAsIpv4() {
        byte[] mapped = new byte[16];
        mapped[10] = (byte) 0xFF;
        mapped[11] = (byte) 0xFF;
        mapped[12] = (byte) 203;
        mapped[13] = 0;
        mapped[14] = 113;
        mapped[15] = 7;
        InetAddress address;
        try {
            address = java.net.Inet6Address.getByAddress(null, mapped, -1);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
        assertEquals("ip4:203.0.113.7", NetworkKey.of(address));
        assertTrue(NetworkKey.isIpv4(address));
        assertTrue(Cidr.parse("203.0.113.0/24").contains(address));
    }

    @Test
    void cidrMatching() {
        Cidr v4 = Cidr.parse("10.20.0.0/16");
        assertTrue(v4.contains(ip("10.20.255.1")));
        assertFalse(v4.contains(ip("10.21.0.1")));
        assertFalse(v4.contains(ip("2001:db8::1")));
        Cidr v6 = Cidr.parse("2001:db8::/32");
        assertTrue(v6.contains(ip("2001:db8:ffff::1")));
        assertFalse(v6.contains(ip("2001:db9::1")));
        assertTrue(Cidr.parse("192.0.2.5").contains(ip("192.0.2.5")));
        assertTrue(Cidr.parse("0.0.0.0/0").contains(ip("8.8.8.8")));
    }

    @Test
    void cidrRejectsBadInputWithoutDns() {
        for (String bad : new String[] {"10.0.0.1/24", "10.0.0.0/33", "example.com", "deadbeef", "10.0.0/8",
                "2001:db8::/129", "", "/8", "10.0.0.0/x"}) {
            assertThrows(IllegalArgumentException.class, () -> Cidr.parse(bad), bad);
        }
    }
}
