package com.mtmrails.trustedserver.core.tunnel;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.mtmrails.trustedserver.core.crypto.AeadStream;
import com.mtmrails.trustedserver.core.crypto.Aes256Gcm;
import com.mtmrails.trustedserver.core.crypto.CryptoException;
import com.mtmrails.trustedserver.core.crypto.Direction;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import org.junit.jupiter.api.Test;

class TunnelCodecTest {
    private static final byte[] KEY = new byte[32];

    static {
        for (int i = 0; i < 32; i++) {
            KEY[i] = (byte) (0xA0 + i);
        }
    }

    private static TunnelEncoder encoder() {
        return new TunnelEncoder(new AeadStream(KEY, Direction.S2C, AeadStream.Role.SEAL));
    }

    private static TunnelDecoder decoder() {
        return new TunnelDecoder(new AeadStream(KEY, Direction.S2C, AeadStream.Role.OPEN));
    }

    private static byte[] random(int length, long seed) {
        byte[] out = new byte[length];
        new Random(seed).nextBytes(out);
        return out;
    }

    /** 按随机大小切片喂给解码器，模拟 TCP 分片。 */
    private static byte[] feedInChunks(TunnelDecoder decoder, byte[] wire, long seed) throws Exception {
        Random random = new Random(seed);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int pos = 0;
        while (pos < wire.length) {
            int n = Math.min(wire.length - pos, 1 + random.nextInt(5000));
            out.writeBytes(decoder.feed(Arrays.copyOfRange(wire, pos, pos + n)));
            pos += n;
        }
        decoder.finish();
        return out.toByteArray();
    }

    @Test
    void frameFormatMatchesSpec() throws Exception {
        byte[] plaintext = "hello".getBytes(StandardCharsets.US_ASCII);
        byte[] wire = encoder().encode(plaintext);
        // L = 5 + 16 = 21，一字节长度前缀
        assertEquals(21, wire[0]);
        assertEquals(1 + 21, wire.length);
        byte[] nonce = new byte[12];
        System.arraycopy(Direction.S2C.tag(), 0, nonce, 0, 4); // 第一帧序号为 0
        byte[] aad = "tsrv v3 tunnel frame\u0015".getBytes(StandardCharsets.ISO_8859_1);
        assertArrayEquals(plaintext, Aes256Gcm.decrypt(KEY, nonce, aad, Arrays.copyOfRange(wire, 1, wire.length)));
    }

    @Test
    void roundTripsAcrossSizesAndArbitraryFragmentation() throws Exception {
        int[] sizes = {1, 15, 127, 65535, 65536, 65537, 200_000};
        for (int size : sizes) {
            byte[] data = random(size, size);
            byte[] wire = encoder().encode(data);
            assertArrayEquals(data, feedInChunks(decoder(), wire, size), "size " + size);

            // 逐字节喂入
            TunnelDecoder byteByByte = decoder();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (byte b : wire) {
                out.writeBytes(byteByByte.feed(new byte[] {b}));
            }
            byteByByte.finish();
            assertArrayEquals(data, out.toByteArray(), "byte-by-byte size " + size);
        }
    }

    @Test
    void maximumFrameUsesThreeBytePrefixAndLargerWritesSplit() throws Exception {
        byte[] exact = encoder().encode(new byte[65536]);
        assertEquals(3 + 65536 + 16, exact.length);
        assertArrayEquals(new byte[] {(byte) 0x90, (byte) 0x80, 0x04}, Arrays.copyOf(exact, 3)); // 65552
        byte[] split = encoder().encode(new byte[65537]);
        assertEquals((3 + 65536 + 16) + (1 + 1 + 16), split.length);
    }

    @Test
    void mergedWritesDecodeInOrder() throws Exception {
        TunnelEncoder encoder = encoder();
        byte[] a = random(1000, 1);
        byte[] b = random(70_000, 2);
        byte[] c = random(3, 3);
        ByteArrayOutputStream wire = new ByteArrayOutputStream();
        wire.writeBytes(encoder.encode(a));
        wire.writeBytes(encoder.encode(b));
        wire.writeBytes(encoder.encode(c));
        assertEquals(0, encoder.encode(new byte[0]).length); // 不发送空帧
        ByteArrayOutputStream expected = new ByteArrayOutputStream();
        expected.writeBytes(a);
        expected.writeBytes(b);
        expected.writeBytes(c);
        TunnelDecoder decoder = decoder();
        assertArrayEquals(expected.toByteArray(), decoder.feed(wire.toByteArray()));
        decoder.finish();
    }

    @Test
    void lengthPrefixIsValidatedBeforeAllocating() {
        byte[][] bad = {
            {0x10},                                  // L = 16 < 17
            {(byte) 0x91, (byte) 0x80, 0x04},        // L = 65553 > 65552
            {(byte) 0x91, 0x00},                     // 非最短编码
            {(byte) 0x80, (byte) 0x80, (byte) 0x80}, // 超过 3 字节
        };
        for (byte[] prefix : bad) {
            assertThrows(MalformedMessageException.class, () -> decoder().feed(prefix), Arrays.toString(prefix));
        }
    }

    @Test
    void tamperingIsDetected() throws Exception {
        byte[] wire = encoder().encode(random(100, 9));
        for (int i = 0; i < wire.length; i++) {
            byte[] tampered = wire.clone();
            tampered[i] ^= 1;
            TunnelDecoder decoder = decoder();
            int index = i;
            assertThrows(Exception.class, () -> {
                byte[] out = decoder.feed(tampered);
                decoder.finish();
                if (out.length > 0) {
                    throw new AssertionError("tampered byte " + index + " produced output");
                }
            }, "byte " + i);
        }
    }

    @Test
    void truncationIsDetectedAtEndOfStream() throws Exception {
        byte[] wire = encoder().encode(random(100, 4));
        for (int length = 1; length < wire.length; length++) {
            TunnelDecoder decoder = decoder();
            assertEquals(0, decoder.feed(Arrays.copyOf(wire, length)).length);
            assertThrows(MalformedMessageException.class, decoder::finish, "length " + length);
        }
        decoder().finish(); // 什么都没收到是正常结束
    }

    @Test
    void reorderReplayAndWrongDirectionFail() throws Exception {
        TunnelEncoder encoder = encoder();
        byte[] first = encoder.encode(new byte[] {1});
        byte[] second = encoder.encode(new byte[] {2});

        assertThrows(CryptoException.class, () -> decoder().feed(second));

        TunnelDecoder replay = decoder();
        replay.feed(first);
        assertThrows(CryptoException.class, () -> replay.feed(first));

        TunnelDecoder wrongDirection = new TunnelDecoder(new AeadStream(KEY, Direction.C2S, AeadStream.Role.OPEN));
        assertThrows(CryptoException.class, () -> wrongDirection.feed(first));
    }

    @Test
    void decoderIsDeadAfterFailure() throws Exception {
        TunnelEncoder encoder = encoder();
        byte[] first = encoder.encode(new byte[] {1});
        TunnelDecoder decoder = decoder();
        byte[] tampered = first.clone();
        tampered[tampered.length - 1] ^= 1;
        assertThrows(CryptoException.class, () -> decoder.feed(tampered));
        assertThrows(CryptoException.class, () -> decoder.feed(first));
    }
}
