package com.mtmrails.trustedserver.core.session;

import com.mtmrails.trustedserver.core.crypto.SessionHandover;
import java.util.List;
import java.util.Objects;

/** 服务端认证的最终结果。 */
public sealed interface AuthOutcome {
    /**
     * 放行：已收到 FinishAck。{@code restricted} 等字段反映本次认证结束时的账号状态，
     * {@code verifiedOriginalKey} 表示本次 Mojang session 与进入认证时已绑定的设备密钥均已验证。
     * {@code reboundBy} 非空表示本次登录把账号改绑到了当前设备的密钥。
     */
    record Accepted(String accountId, String username, byte[] playerPub, boolean restricted,
            boolean hasLoginPassword, boolean hasRecoveryPassword, boolean verifiedOriginalKey, List<String> notices,
            java.util.Optional<RebindReason> reboundBy, SessionHandover handover) implements AuthOutcome {
        public Accepted {
            Objects.requireNonNull(accountId, "accountId");
            Objects.requireNonNull(username, "username");
            playerPub = playerPub.clone();
            notices = List.copyOf(notices);
            Objects.requireNonNull(reboundBy, "reboundBy");
            Objects.requireNonNull(handover, "handover");
        }

        @Override
        public byte[] playerPub() {
            return playerPub.clone();
        }

        public boolean tunnel() {
            return handover.tunnel();
        }
    }

    /**
     * 拒绝。{@code trusted} 表示拒绝发生在可信握手完成（ClientProof 验签通过）之后；
     * 只有这种情况才允许上层向对方提供具体原因，且须经受保护的通道（格式待定义）。
     */
    record Rejected(RejectReason reason, boolean trusted) implements AuthOutcome {
        public Rejected {
            Objects.requireNonNull(reason, "reason");
        }
    }
}
