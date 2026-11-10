package com.mtmrails.trustedserver.core.tunnel;

import com.mtmrails.trustedserver.core.crypto.AeadStream;
import com.mtmrails.trustedserver.core.crypto.CryptoException;
import com.mtmrails.trustedserver.core.wire.WireWriter;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.Objects;

/**
 * 隧道发送端：把 Minecraft 编码后的原始字节流切成不超过 65536 字节的明文块，逐帧加密（PROTOCOL.md 第 5 节）。
 *
 * <pre>
 * length_bytes = 最短 VarInt(L)，L = 明文长度 + 16
 * frame        = length_bytes || AES-256-GCM(k_tun, nonce, plaintext, aad = "tsrv v3 tunnel frame" || length_bytes)
 * </pre>
 *
 * <p>不发送空帧。任何失败后本编码器永久失效，上层应关闭连接。非线程安全。
 */
public final class TunnelEncoder {
    private final AeadStream sealer;
    private boolean failed;

    public TunnelEncoder(AeadStream sealer) {
        this.sealer = Objects.requireNonNull(sealer, "sealer");
    }

    /** 加密一段字节，返回一个或多个完整帧拼接后的字节；输入为空时返回空数组。 */
    public byte[] encode(byte[] data) throws CryptoException {
        if (failed) {
            throw new CryptoException("tunnel encoder has failed");
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(data.length + 32);
        try {
            for (int offset = 0; offset < data.length; offset += TunnelFrames.MAX_PLAINTEXT) {
                byte[] chunk = Arrays.copyOfRange(data, offset,
                        Math.min(data.length, offset + TunnelFrames.MAX_PLAINTEXT));
                byte[] lengthBytes = new WireWriter().varInt(chunk.length + TunnelFrames.TAG_LENGTH).toByteArray();
                out.writeBytes(lengthBytes);
                out.writeBytes(sealer.seal(TunnelFrames.aad(lengthBytes), chunk));
            }
        } catch (CryptoException | RuntimeException e) {
            failed = true;
            sealer.close();
            throw e;
        }
        return out.toByteArray();
    }
}
