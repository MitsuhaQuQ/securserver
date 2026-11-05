package com.mtmrails.trustedserver.core.crypto;

/** 本端角色，决定发送和接收各用哪个方向。 */
public enum Side {
    SERVER(Direction.S2C, Direction.C2S),
    CLIENT(Direction.C2S, Direction.S2C);

    private final Direction outbound;
    private final Direction inbound;

    Side(Direction outbound, Direction inbound) {
        this.outbound = outbound;
        this.inbound = inbound;
    }

    public Direction outbound() {
        return outbound;
    }

    public Direction inbound() {
        return inbound;
    }
}
