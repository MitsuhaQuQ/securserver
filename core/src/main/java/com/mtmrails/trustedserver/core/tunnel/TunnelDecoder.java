package com.mtmrails.trustedserver.core.tunnel;

import com.mtmrails.trustedserver.core.crypto.AeadStream;
import com.mtmrails.trustedserver.core.crypto.CryptoException;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Objects;

/**
 * 隧道接收端：按顺序喂入从网络读到的任意分片，输出已验证的明文字节流（PROTOCOL.md 第 5 节）。
 *
 * <ul>
 *   <li>长度前缀一读全就校验最短编码和 17–65552 的范围，再为帧分配缓冲；缓冲最多一帧大小
 *   <li>未收齐一帧时等待；只有验证标签之后才输出该帧明文
 *   <li>连接结束时调用 {@link #finish()}：还有残留字节即视为截断
 *   <li>任何失败后本解码器永久失效，上层应直接关闭连接，不尝试猜测格式
 * </ul>
 * 非线程安全。
 */
public final class TunnelDecoder {
    private final AeadStream opener;
    /** 当前帧已收到的长度前缀字节。 */
    private final byte[] lengthBytes = new byte[TunnelFrames.MAX_LENGTH_BYTES];
    private int lengthCount;
    private int frameLength = -1;
    private byte[] frame;
    private int frameFill;
    private boolean failed;

    public TunnelDecoder(AeadStream opener) {
        this.opener = Objects.requireNonNull(opener, "opener");
    }

    /** 喂入一段收到的字节，返回其中完整帧解密后的明文（可能为空）。 */
    public byte[] feed(byte[] data) throws CryptoException, MalformedMessageException {
        if (failed) {
            throw new CryptoException("tunnel decoder has failed");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            int pos = 0;
            while (pos < data.length) {
                if (frameLength < 0) {
                    pos = readLength(data, pos);
                    continue;
                }
                int n = Math.min(frameLength - frameFill, data.length - pos);
                System.arraycopy(data, pos, frame, frameFill, n);
                frameFill += n;
                pos += n;
                if (frameFill == frameLength) {
                    byte[] prefix = Arrays.copyOf(lengthBytes, lengthCount);
                    out.writeBytes(opener.open(TunnelFrames.aad(prefix), frame));
                    frameLength = -1;
                    lengthCount = 0;
                    frame = null;
                }
            }
        } catch (CryptoException | MalformedMessageException | RuntimeException e) {
            fail();
            throw e;
        }
        return out.toByteArray();
    }

    /** 连接结束：存在未收齐的帧（含半个长度前缀）即为截断。 */
    public void finish() throws MalformedMessageException {
        if (lengthCount > 0 || frameLength >= 0) {
            fail();
            throw new MalformedMessageException("tunnel stream truncated inside a frame");
        }
    }

    /** 读取长度前缀的一个字节；前缀完整时校验并分配帧缓冲。 */
    private int readLength(byte[] data, int pos) throws MalformedMessageException {
        int b = data[pos] & 0xFF;
        lengthBytes[lengthCount++] = (byte) b;
        boolean more = (b & 0x80) != 0;
        if (!more) {
            int value = 0;
            for (int i = 0; i < lengthCount; i++) {
                value |= (lengthBytes[i] & 0x7F) << (7 * i);
            }
            if (lengthCount > 1 && b == 0) {
                throw new MalformedMessageException("non-canonical tunnel frame length");
            }
            if (value < TunnelFrames.MIN_L || value > TunnelFrames.MAX_L) {
                throw new MalformedMessageException("tunnel frame length " + value + " out of range");
            }
            frameLength = value;
            frame = new byte[value];
            frameFill = 0;
        } else if (lengthCount == TunnelFrames.MAX_LENGTH_BYTES) {
            throw new MalformedMessageException("tunnel frame length prefix longer than 3 bytes");
        }
        return pos + 1;
    }

    private void fail() {
        failed = true;
        frame = null;
        opener.close();
    }
}
