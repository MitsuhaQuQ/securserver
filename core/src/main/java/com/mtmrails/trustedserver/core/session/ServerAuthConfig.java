package com.mtmrails.trustedserver.core.session;

import com.mtmrails.trustedserver.core.crypto.SecureMessageChannel;
import com.mtmrails.trustedserver.core.message.Finish;
import com.mtmrails.trustedserver.core.message.MessageCodec;
import com.mtmrails.trustedserver.core.message.ServerHello;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * 服务端状态机的配置。
 *
 * @param maxPasswordAttempts 每个连接上每种密码（登录 / 找回）的尝试次数，1–255
 * @param passwordTimeoutSec 发给客户端的密码输入框超时，1–65535 秒；应小于认证总超时
 * @param restrictedNotice 受限玩家进服时的提示，空串表示不提示
 * @param recoveryReminderNotice 未设找回密码的玩家进服时的提示，空串表示不提示
 */
public record ServerAuthConfig(TunnelPolicy tunnelPolicy, int maxPasswordAttempts, int passwordTimeoutSec,
        String restrictedNotice, String recoveryReminderNotice) {

    public enum TunnelPolicy {
        /** 不提供隧道。 */
        DISABLED,
        /** 客户端希望时开启。 */
        OPTIONAL,
        /** 强制开启。 */
        REQUIRED
    }

    public ServerAuthConfig {
        Objects.requireNonNull(tunnelPolicy, "tunnelPolicy");
        if (maxPasswordAttempts < 1 || maxPasswordAttempts > 0xFF) {
            throw new IllegalArgumentException("maxPasswordAttempts must be 1..255");
        }
        if (passwordTimeoutSec < 1 || passwordTimeoutSec > 0xFFFF) {
            throw new IllegalArgumentException("passwordTimeoutSec must be 1..65535");
        }
        Objects.requireNonNull(restrictedNotice, "restrictedNotice");
        Objects.requireNonNull(recoveryReminderNotice, "recoveryReminderNotice");
        // 两条提示同时出现时，Finish 仍须在加密消息体上限之内
        Finish worstCase = new Finish(true, notices(true, false, restrictedNotice, recoveryReminderNotice));
        if (MessageCodec.encodeBody(worstCase).length > SecureMessageChannel.MAX_BODY) {
            throw new IllegalArgumentException("notices do not fit in a Finish message");
        }
    }

    public static ServerAuthConfig defaults() {
        return new ServerAuthConfig(TunnelPolicy.OPTIONAL, 3, 60,
                "设定密码后解除新用户限制（使用 /passwd）",
                "尚未设置找回密码，可使用 /recoverypasswd 设置");
    }

    /** ServerHello 的 features 位。 */
    public int features() {
        return switch (tunnelPolicy) {
            case DISABLED -> 0;
            case OPTIONAL -> ServerHello.FEATURE_TUNNEL_AVAILABLE;
            case REQUIRED -> ServerHello.FEATURE_TUNNEL_AVAILABLE | ServerHello.FEATURE_TUNNEL_REQUIRED;
        };
    }

    boolean tunnelFor(boolean clientWantsTunnel) {
        return tunnelPolicy == TunnelPolicy.REQUIRED || (tunnelPolicy == TunnelPolicy.OPTIONAL && clientWantsTunnel);
    }

    List<String> noticesFor(AccountView account) {
        return notices(account.restricted(), account.hasRecoveryPassword(), restrictedNotice, recoveryReminderNotice);
    }

    private static List<String> notices(boolean restricted, boolean hasRecovery, String restrictedNotice,
            String recoveryReminderNotice) {
        List<String> out = new ArrayList<>(2);
        if (restricted && !restrictedNotice.isEmpty()) {
            out.add(restrictedNotice);
        }
        if (!hasRecovery && !recoveryReminderNotice.isEmpty()) {
            out.add(recoveryReminderNotice);
        }
        return out;
    }
}
