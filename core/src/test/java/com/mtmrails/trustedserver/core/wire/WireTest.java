package com.mtmrails.trustedserver.core.wire;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class WireTest {
    private static byte[] bytes(int... values) {
        byte[] out = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            out[i] = (byte) values[i];
        }
        return out;
    }

    @Test
    void integersRoundTrip() throws Exception {
        byte[] data = new WireWriter().u8(0).u8(255).u16(0).u16(0xFFFF).u32(0xDEADBEEF).bool(true).bool(false)
                .toByteArray();
        WireReader in = new WireReader(data);
        assertEquals(0, in.u8());
        assertEquals(255, in.u8());
        assertEquals(0, in.u16());
        assertEquals(0xFFFF, in.u16());
        assertEquals(0xDEADBEEF, in.u32());
        assertTrue(in.bool());
        assertFalse(in.bool());
        in.expectEnd();
    }

    @Test
    void integersAreBigEndian() {
        assertArrayEquals(bytes(0x12, 0x34), new WireWriter().u16(0x1234).toByteArray());
        assertArrayEquals(bytes(0x12, 0x34, 0x56, 0x78), new WireWriter().u32(0x12345678).toByteArray());
    }

    @Test
    void varIntRoundTripsAtBoundaries() throws Exception {
        int[] values = {0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455, 268435456, Integer.MAX_VALUE};
        int[] lengths = {1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5};
        for (int i = 0; i < values.length; i++) {
            byte[] encoded = new WireWriter().varInt(values[i]).toByteArray();
            assertEquals(lengths[i], encoded.length, "length of " + values[i]);
            WireReader in = new WireReader(encoded);
            assertEquals(values[i], in.varInt());
            in.expectEnd();
        }
    }

    @Test
    void varIntMatchesMinecraftEncoding() {
        assertArrayEquals(bytes(0xDD, 0xC7, 0x01), new WireWriter().varInt(25565).toByteArray());
        assertArrayEquals(bytes(0xFF, 0xFF, 0xFF, 0xFF, 0x07), new WireWriter().varInt(Integer.MAX_VALUE).toByteArray());
    }

    @Test
    void rejectsNonCanonicalVarInt() {
        assertThrows(MalformedMessageException.class, () -> new WireReader(bytes(0x80, 0x00)).varInt());
        assertThrows(MalformedMessageException.class, () -> new WireReader(bytes(0x81, 0x80, 0x00)).varInt());
    }

    @Test
    void rejectsOutOfRangeVarInt() {
        // 负数（第 5 字节 bit 3 置位）
        assertThrows(MalformedMessageException.class,
                () -> new WireReader(bytes(0xFF, 0xFF, 0xFF, 0xFF, 0x0F)).varInt());
        // 超过 5 字节
        assertThrows(MalformedMessageException.class,
                () -> new WireReader(bytes(0xFF, 0xFF, 0xFF, 0xFF, 0x87, 0x00)).varInt());
    }

    @Test
    void rejectsTruncatedInput() {
        assertThrows(MalformedMessageException.class, () -> new WireReader(new byte[0]).u8());
        assertThrows(MalformedMessageException.class, () -> new WireReader(bytes(1)).u16());
        assertThrows(MalformedMessageException.class, () -> new WireReader(bytes(1, 2, 3)).u32());
        assertThrows(MalformedMessageException.class, () -> new WireReader(bytes(0x80)).varInt());
        assertThrows(MalformedMessageException.class, () -> new WireReader(bytes(1, 2)).fixed(3));
        assertThrows(MalformedMessageException.class, () -> new WireReader(bytes(5, 1, 2)).varBytes(10));
    }

    @Test
    void rejectsInvalidBoolean() {
        assertThrows(MalformedMessageException.class, () -> new WireReader(bytes(2)).bool());
    }

    @Test
    void enforcesLengthLimits() {
        assertThrows(MalformedMessageException.class, () -> new WireReader(bytes(3, 1, 2, 3)).varBytes(2));
        assertThrows(IllegalArgumentException.class, () -> new WireWriter().varBytes(new byte[3], 2));
        assertThrows(IllegalArgumentException.class, () -> new WireWriter().string("abc", 2));
    }

    @Test
    void stringsRoundTripAsUtf8() throws Exception {
        String value = "密码 🔑 ok";
        byte[] encoded = new WireWriter().string(value, 64).toByteArray();
        WireReader in = new WireReader(encoded);
        assertEquals(value, in.string(64));
        in.expectEnd();
    }

    @Test
    void rejectsInvalidUtf8() {
        assertThrows(MalformedMessageException.class, () -> new WireReader(bytes(2, 0xC3, 0x28)).string(10));
        // 代理字符的 UTF-8 编码（CESU 风格）不是合法 UTF-8
        assertThrows(MalformedMessageException.class,
                () -> new WireReader(bytes(3, 0xED, 0xA0, 0x80)).string(10));
    }

    @Test
    void refusesToWriteUnpairedSurrogate() {
        assertThrows(IllegalArgumentException.class, () -> new WireWriter().string("\uD800", 10));
    }

    @Test
    void rejectsTrailingBytes() throws Exception {
        WireReader in = new WireReader(bytes(1, 2));
        in.u8();
        assertThrows(MalformedMessageException.class, in::expectEnd);
    }

    @Test
    void writerRejectsOutOfRangeValues() {
        assertThrows(IllegalArgumentException.class, () -> new WireWriter().u8(256));
        assertThrows(IllegalArgumentException.class, () -> new WireWriter().u8(-1));
        assertThrows(IllegalArgumentException.class, () -> new WireWriter().u16(0x10000));
        assertThrows(IllegalArgumentException.class, () -> new WireWriter().varInt(-1));
    }
}
