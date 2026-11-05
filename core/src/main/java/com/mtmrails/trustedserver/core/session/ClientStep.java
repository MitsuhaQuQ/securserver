package com.mtmrails.trustedserver.core.session;

import java.util.Objects;
import java.util.Optional;

/** 客户端处理一条 query 后的动作。 */
public sealed interface ClientStep {
    /** 回答这条 query。 */
    record Reply(byte[] payload) implements ClientStep {
        public Reply {
            payload = payload.clone();
        }

        @Override
        public byte[] payload() {
            return payload.clone();
        }
    }

    /**
     * 回答 FinishAck，认证完成。开启隧道时，上层须先把这条回答排入旧编码链路，再原子切换编解码器。
     */
    record Complete(byte[] payload, ClientResult result) implements ClientStep {
        public Complete {
            payload = payload.clone();
            Objects.requireNonNull(result, "result");
        }

        @Override
        public byte[] payload() {
            return payload.clone();
        }
    }

    /**
     * 失败。{@code reply} 存在时（仅版本不兼容：version = 0 的 ClientHello）应先发出再等待断开；
     * 否则直接断开。
     */
    record Fail(ClientFailure failure, Optional<byte[]> reply) implements ClientStep {
        public Fail {
            Objects.requireNonNull(failure, "failure");
            reply = reply.map(byte[]::clone);
        }

        @Override
        public Optional<byte[]> reply() {
            return reply.map(byte[]::clone);
        }
    }
}
