package com.mtmrails.trustedserver.core.message;

/** 认证通道 {@link Channel#AUTH} 上的消息。 */
public sealed interface AuthMessage extends Message
        permits ServerHello, ClientHello, Challenge, ClientProof, Finish, FinishAck {
}
