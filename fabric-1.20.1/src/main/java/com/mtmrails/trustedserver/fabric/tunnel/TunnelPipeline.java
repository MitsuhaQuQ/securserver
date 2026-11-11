package com.mtmrails.trustedserver.fabric.tunnel;

import com.mtmrails.trustedserver.core.crypto.CryptoException;
import com.mtmrails.trustedserver.core.crypto.SessionHandover;
import com.mtmrails.trustedserver.core.tunnel.TunnelDecoder;
import com.mtmrails.trustedserver.core.tunnel.TunnelEncoder;
import com.mtmrails.trustedserver.core.wire.MalformedMessageException;
import com.mtmrails.trustedserver.fabric.MinecraftAccess;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.ChannelPromise;
import io.netty.handler.codec.ByteToMessageDecoder;
import io.netty.handler.codec.MessageToByteEncoder;
import io.netty.util.concurrent.Future;
import java.util.List;
import java.util.Objects;
import net.minecraft.network.Connection;

/** 在 Minecraft 帧编解码器外安装 TrustedServer AES-GCM 字节流隧道。 */
public final class TunnelPipeline {
    private static final String INBOUND = "trustedserver_tunnel_decrypt";
    private static final String OUTBOUND = "trustedserver_tunnel_encrypt";
    private static final String CLIENT_SWITCH = "trustedserver_tunnel_switch";

    private TunnelPipeline() {
    }

    /** 服务端已验证 FinishAck；安装后发送的第一字节必须属于隧道帧。 */
    public static void installServer(Connection connection, SessionHandover handover) {
        if (!handover.tunnel()) {
            return;
        }
        Channel channel = MinecraftAccess.nettyChannel(connection);
        runOnEventLoop(channel, () -> install(channel.pipeline(), handover));
    }

    /**
     * 客户端即将返回 FinishAck。下一次原始出站写入仍走旧传输；写入完成后原子切换后续双向字节流。
     */
    public static void prepareClientSwitch(Connection connection, SessionHandover handover) {
        if (!handover.tunnel()) {
            return;
        }
        Channel channel = MinecraftAccess.nettyChannel(connection);
        runOnEventLoop(channel, () -> {
            ChannelPipeline pipeline = channel.pipeline();
            rejectExisting(pipeline);
            String anchor = pipeline.get("encrypt") != null ? "encrypt" : "splitter";
            pipeline.addBefore(anchor, CLIENT_SWITCH, new FinishAckSwitch(handover));
        });
    }

    private static void install(ChannelPipeline pipeline, SessionHandover handover) {
        rejectExisting(pipeline);
        removeIfPresent(pipeline, "decrypt");
        removeIfPresent(pipeline, "encrypt");
        pipeline.addBefore("splitter", INBOUND, new Inbound(handover));
        pipeline.addBefore("prepender", OUTBOUND, new Outbound(handover));
    }

    private static void finishClientSwitch(ChannelPipeline pipeline, SessionHandover handover) {
        removeIfPresent(pipeline, "decrypt");
        removeIfPresent(pipeline, "encrypt");
        pipeline.addBefore("splitter", INBOUND, new Inbound(handover));
        pipeline.replace(CLIENT_SWITCH, OUTBOUND, new Outbound(handover));
    }

    private static void rejectExisting(ChannelPipeline pipeline) {
        if (pipeline.get(INBOUND) != null || pipeline.get(OUTBOUND) != null
                || pipeline.get(CLIENT_SWITCH) != null) {
            throw new IllegalStateException("TrustedServer tunnel is already installed");
        }
        if (pipeline.get("splitter") == null || pipeline.get("prepender") == null) {
            throw new IllegalStateException("Minecraft frame handlers are not installed");
        }
    }

    private static void removeIfPresent(ChannelPipeline pipeline, String name) {
        if (pipeline.get(name) != null) {
            pipeline.remove(name);
        }
    }

    private static void runOnEventLoop(Channel channel, Runnable action) {
        if (channel.eventLoop().inEventLoop()) {
            action.run();
            return;
        }
        Future<?> future = channel.eventLoop().submit(action).syncUninterruptibly();
        if (!future.isSuccess()) {
            throw new IllegalStateException("cannot update TrustedServer tunnel pipeline", future.cause());
        }
    }

    private static final class FinishAckSwitch extends ChannelOutboundHandlerAdapter {
        private final SessionHandover handover;
        private boolean writing;

        private FinishAckSwitch(SessionHandover handover) {
            this.handover = Objects.requireNonNull(handover, "handover");
        }

        @Override
        public void write(ChannelHandlerContext ctx, Object message, ChannelPromise promise) throws Exception {
            if (!(message instanceof ByteBuf)) {
                super.write(ctx, message, promise);
                return;
            }
            if (writing) {
                io.netty.util.ReferenceCountUtil.release(message);
                ctx.close();
                promise.tryFailure(new IllegalStateException("application data written before tunnel switch"));
                return;
            }
            writing = true;
            promise.addListener(future -> {
                if (!future.isSuccess()) {
                    ctx.close();
                    return;
                }
                try {
                    finishClientSwitch(ctx.pipeline(), handover);
                } catch (RuntimeException e) {
                    ctx.fireExceptionCaught(e);
                    ctx.close();
                }
            });
            super.write(ctx, message, promise);
        }
    }

    private static final class Outbound extends MessageToByteEncoder<ByteBuf> {
        private final TunnelEncoder encoder;

        private Outbound(SessionHandover handover) {
            this.encoder = new TunnelEncoder(handover.tunnelSealer().orElseThrow());
        }

        @Override
        protected void encode(ChannelHandlerContext ctx, ByteBuf message, ByteBuf out) throws CryptoException {
            try {
                byte[] plaintext = new byte[message.readableBytes()];
                message.readBytes(plaintext);
                out.writeBytes(encoder.encode(plaintext));
            } catch (CryptoException | RuntimeException e) {
                ctx.close();
                throw e;
            }
        }
    }

    private static final class Inbound extends ByteToMessageDecoder {
        private final TunnelDecoder decoder;

        private Inbound(SessionHandover handover) {
            this.decoder = new TunnelDecoder(handover.tunnelOpener().orElseThrow());
        }

        @Override
        protected void decode(ChannelHandlerContext ctx, ByteBuf input, List<Object> output)
                throws CryptoException, MalformedMessageException {
            try {
                byte[] ciphertext = new byte[input.readableBytes()];
                input.readBytes(ciphertext);
                byte[] plaintext = decoder.feed(ciphertext);
                if (plaintext.length > 0) {
                    output.add(Unpooled.wrappedBuffer(plaintext));
                }
            } catch (CryptoException | MalformedMessageException | RuntimeException e) {
                ctx.close();
                throw e;
            }
        }

        @Override
        protected void decodeLast(ChannelHandlerContext ctx, ByteBuf input, List<Object> output) throws Exception {
            if (input.isReadable()) {
                decode(ctx, input, output);
            }
            decoder.finish();
        }
    }
}
