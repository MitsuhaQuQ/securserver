package com.mtmrails.trustedserver.core.session;

import com.mtmrails.trustedserver.core.message.Channel;
import java.util.Objects;

/** 服务端要发出的一条 login query：频道与完整 payload。 */
public record Outbound(Channel channel, byte[] payload) {
    public Outbound {
        Objects.requireNonNull(channel, "channel");
        payload = payload.clone();
    }

    @Override
    public byte[] payload() {
        return payload.clone();
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Outbound other && channel == other.channel
                && java.util.Arrays.equals(payload, other.payload);
    }

    @Override
    public int hashCode() {
        return 31 * channel.hashCode() + java.util.Arrays.hashCode(payload);
    }

    @Override
    public String toString() {
        return "Outbound[channel=" + channel.id() + ", payload=" + payload.length + " bytes]";
    }
}
