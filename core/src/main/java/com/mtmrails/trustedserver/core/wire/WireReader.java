package com.mtmrails.trustedserver.core.wire;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/**
 * 严格的二进制读取器。任何不合规的输入都抛出 {@link MalformedMessageException}，
 * 绝不静默截断或纠正。
 *
 * <p>整数均为大端序；VarInt 与 Minecraft 相同（每字节 7 位，低位在前），
 * 但只接受非负的 31 位值和最短编码，保证同一个值只有一种编码。
 */
public final class WireReader {
    /** VarInt 最多占用的字节数。 */
    static final int VAR_INT_MAX_BYTES = 5;

    private final byte[] data;
    private int pos;

    public WireReader(byte[] data) {
        this.data = Objects.requireNonNull(data, "data");
    }

    /** 尚未读取的字节数。 */
    public int remaining() {
        return data.length - pos;
    }

    public int u8() throws MalformedMessageException {
        require(1);
        return data[pos++] & 0xFF;
    }

    public int u16() throws MalformedMessageException {
        require(2);
        int value = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
        pos += 2;
        return value;
    }

    /** 读取 32 位无符号整数，按位原样放进 {@code int}（适用于位掩码）。 */
    public int u32() throws MalformedMessageException {
        require(4);
        int value = ((data[pos] & 0xFF) << 24)
                | ((data[pos + 1] & 0xFF) << 16)
                | ((data[pos + 2] & 0xFF) << 8)
                | (data[pos + 3] & 0xFF);
        pos += 4;
        return value;
    }

    /** 只接受 0 和 1。 */
    public boolean bool() throws MalformedMessageException {
        int value = u8();
        if (value > 1) {
            throw new MalformedMessageException("invalid boolean: " + value);
        }
        return value == 1;
    }

    public int varInt() throws MalformedMessageException {
        int value = 0;
        for (int i = 0; i < VAR_INT_MAX_BYTES; i++) {
            int b = u8();
            // 第 5 个字节只能携带 bit 28..30，且不能再有后续字节
            if (i == VAR_INT_MAX_BYTES - 1 && (b & 0xF8) != 0) {
                throw new MalformedMessageException("VarInt out of range");
            }
            value |= (b & 0x7F) << (7 * i);
            if ((b & 0x80) == 0) {
                if (i > 0 && b == 0) {
                    throw new MalformedMessageException("non-canonical VarInt");
                }
                return value;
            }
        }
        throw new AssertionError("unreachable");
    }

    /** 读取恰好 {@code length} 个字节。 */
    public byte[] fixed(int length) throws MalformedMessageException {
        require(length);
        byte[] out = Arrays.copyOfRange(data, pos, pos + length);
        pos += length;
        return out;
    }

    /** 读取 VarInt 长度前缀的字节串，长度超过 {@code maxLength} 即失败。 */
    public byte[] varBytes(int maxLength) throws MalformedMessageException {
        int length = varInt();
        if (length > maxLength) {
            throw new MalformedMessageException("length " + length + " exceeds limit " + maxLength);
        }
        return fixed(length);
    }

    /** 读取 VarInt 长度前缀的 UTF-8 字符串，非法 UTF-8 即失败。 */
    public String string(int maxBytes) throws MalformedMessageException {
        byte[] raw = varBytes(maxBytes);
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new MalformedMessageException("invalid UTF-8 string", e);
        }
    }

    /** 断言已读到末尾；还有剩余字节即失败。 */
    public void expectEnd() throws MalformedMessageException {
        if (remaining() != 0) {
            throw new MalformedMessageException(remaining() + " trailing bytes");
        }
    }

    private void require(int length) throws MalformedMessageException {
        if (length < 0 || remaining() < length) {
            throw new MalformedMessageException("truncated: need " + length + " bytes, have " + remaining());
        }
    }
}
