package com.mtmrails.trustedserver.fabric.tunnel;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.mtmrails.trustedserver.core.crypto.SessionHandover;
import com.mtmrails.trustedserver.core.crypto.SessionKeys;
import com.mtmrails.trustedserver.core.crypto.Side;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelOutboundHandlerAdapter;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.codec.DecoderException;
import java.lang.reflect.Field;
import java.util.Arrays;
import net.minecraft.network.Connection;
import net.minecraft.network.protocol.PacketFlow;
import org.junit.jupiter.api.Test;

class TunnelPipelineTest {
    private record End(Connection connection, EmbeddedChannel channel, SessionHandover handover) {
    }

    @Test
    void encryptsBothDirectionsOutsideMinecraftFraming() {
        End client = end(Side.CLIENT, PacketFlow.CLIENTBOUND, false);
        End server = end(Side.SERVER, PacketFlow.SERVERBOUND, false);
        TunnelPipeline.installServer(client.connection(), client.handover());
        TunnelPipeline.installServer(server.connection(), server.handover());

        byte[] s2c = bytes(70_000, 1);
        assertArrayEquals(s2c, transferOutbound(server.channel(), client.channel(), s2c));
        byte[] c2s = bytes(16_000, 2);
        assertArrayEquals(c2s, transferOutbound(client.channel(), server.channel(), c2s));

        close(client, server);
    }

    @Test
    void clientFinishAckStaysOnOldTransportThenSwitches() {
        End client = end(Side.CLIENT, PacketFlow.CLIENTBOUND, true);
        End server = end(Side.SERVER, PacketFlow.SERVERBOUND, true);
        TunnelPipeline.prepareClientSwitch(client.connection(), client.handover());

        byte[] finishAck = bytes(32, 3);
        client.channel().writeOutbound(Unpooled.wrappedBuffer(finishAck));
        ByteBuf oldWire = client.channel().readOutbound();
        assertArrayEquals(finishAck, read(oldWire));
        assertNull(client.channel().pipeline().get("encrypt"));
        assertNull(client.channel().pipeline().get("decrypt"));
        assertNotNull(client.channel().pipeline().get("trustedserver_tunnel_encrypt"));
        assertNotNull(client.channel().pipeline().get("trustedserver_tunnel_decrypt"));

        TunnelPipeline.installServer(server.connection(), server.handover());
        byte[] application = bytes(4096, 4);
        assertArrayEquals(application, transferOutbound(client.channel(), server.channel(), application));
        close(client, server);
    }

    @Test
    void tamperingClosesDecoderState() {
        End client = end(Side.CLIENT, PacketFlow.CLIENTBOUND, false);
        End server = end(Side.SERVER, PacketFlow.SERVERBOUND, false);
        TunnelPipeline.installServer(client.connection(), client.handover());
        TunnelPipeline.installServer(server.connection(), server.handover());

        server.channel().writeOutbound(Unpooled.wrappedBuffer(bytes(100, 5)));
        ByteBuf wire = server.channel().readOutbound();
        wire.setByte(wire.writerIndex() - 1, wire.getByte(wire.writerIndex() - 1) ^ 1);
        assertThrows(DecoderException.class, () -> client.channel().writeInbound(wire));
        assertThrows(Exception.class,
                () -> client.channel().writeInbound(Unpooled.wrappedBuffer(new byte[] {17})));
        if (client.channel().pipeline().get("trustedserver_tunnel_decrypt") != null) {
            client.channel().pipeline().remove("trustedserver_tunnel_decrypt");
        }
        if (client.channel().pipeline().get("trustedserver_tunnel_encrypt") != null) {
            client.channel().pipeline().remove("trustedserver_tunnel_encrypt");
        }
        client.channel().finishAndReleaseAll();
        client.handover().close();
        close(server);
    }

    private static End end(Side side, PacketFlow receiving, boolean originalEncryption) {
        EmbeddedChannel channel = new EmbeddedChannel();
        channel.pipeline().addLast("splitter", new ChannelInboundHandlerAdapter());
        channel.pipeline().addLast("prepender", new ChannelOutboundHandlerAdapter());
        if (originalEncryption) {
            channel.pipeline().addBefore("splitter", "decrypt", new ChannelInboundHandlerAdapter());
            channel.pipeline().addBefore("prepender", "encrypt", new ChannelOutboundHandlerAdapter());
        }
        Connection connection = new Connection(receiving);
        try {
            Field field = Connection.class.getDeclaredField("channel");
            field.setAccessible(true);
            field.set(connection, channel);
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }

        byte[] shared = bytes(32, 90);
        byte[] serverNonce = bytes(32, 91);
        byte[] clientNonce = bytes(32, 92);
        byte[] transcript = bytes(32, 93);
        SessionKeys keys = SessionKeys.derive(shared, serverNonce, clientNonce, transcript);
        SessionHandover handover = SessionHandover.create(keys, side, keys.passwordChannel(side), true);
        keys.destroy();
        return new End(connection, channel, handover);
    }

    private static byte[] transferOutbound(EmbeddedChannel from, EmbeddedChannel to, byte[] plaintext) {
        from.writeOutbound(Unpooled.wrappedBuffer(plaintext));
        ByteBuf wire = from.readOutbound();
        to.writeInbound(wire);
        ByteBuf decoded = to.readInbound();
        return read(decoded);
    }

    private static byte[] read(ByteBuf buf) {
        try {
            byte[] out = new byte[buf.readableBytes()];
            buf.readBytes(out);
            return out;
        } finally {
            buf.release();
        }
    }

    private static byte[] bytes(int length, int salt) {
        byte[] out = new byte[length];
        for (int i = 0; i < length; i++) {
            out[i] = (byte) (i * 31 + salt);
        }
        return out;
    }

    private static void close(End... ends) {
        Arrays.stream(ends).forEach(end -> {
            end.channel().finishAndReleaseAll();
            end.handover().close();
        });
    }
}
