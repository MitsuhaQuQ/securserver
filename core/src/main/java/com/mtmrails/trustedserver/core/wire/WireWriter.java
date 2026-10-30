package com.mtmrails.trustedserver.core.wire;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * 与 {@link WireReader} 对应的写入器。写入非法取值属于编程错误，
 * 抛出 {@link IllegalArgumentException}。
 */
public final class WireWriter {
    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    public WireWriter u8(int value) {
        if (value < 0 || value > 0xFF) {
            throw new IllegalArgumentException("u8 out of range: " + value);
        }
        out.write(value);
        return this;
    }

    public WireWriter u16(int value) {
        if (value < 0 || value > 0xFFFF) {
            throw new IllegalArgumentException("u16 out of range: " + value);
        }
        out.write(value >>> 8);
        out.write(value);
        return this;
    }

    /** 按位写出 32 位整数（适用于位掩码）。 */
    public WireWriter u32(int value) {
        out.write(value >>> 24);
        out.write(value >>> 16);
        out.write(value >>> 8);
        out.write(value);
        return this;
    }

    public WireWriter bool(boolean value) {
        out.write(value ? 1 : 0);
        return this;
    }

    public WireWriter varInt(int value) {
        if (value < 0) {
            throw new IllegalArgumentException("VarInt must be non-negative: " + value);
        }
        while ((value & ~0x7F) != 0) {
            out.write((value & 0x7F) | 0x80);
            value >>>= 7;
        }
        out.write(value);
        return this;
    }

    public WireWriter fixed(byte[] bytes) {
        out.writeBytes(Objects.requireNonNull(bytes, "bytes"));
        return this;
    }

    public WireWriter varBytes(byte[] bytes, int maxLength) {
        Objects.requireNonNull(bytes, "bytes");
        if (bytes.length > maxLength) {
            throw new IllegalArgumentException("length " + bytes.length + " exceeds limit " + maxLength);
        }
        varInt(bytes.length);
        return fixed(bytes);
    }

    public WireWriter string(String value, int maxBytes) {
        return varBytes(utf8(value), maxBytes);
    }

    public byte[] toByteArray() {
        return out.toByteArray();
    }

    /** 严格的 UTF-8 编码：含不成对代理字符等无法编码的内容时抛出 {@link IllegalArgumentException}。 */
    public static byte[] utf8(String value) {
        Objects.requireNonNull(value, "value");
        try {
            ByteBuffer encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(value));
            return Arrays.copyOfRange(encoded.array(), encoded.arrayOffset() + encoded.position(),
                    encoded.arrayOffset() + encoded.limit());
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("string is not valid Unicode", e);
        }
    }
}
