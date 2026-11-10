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
 * @param rebindNotice 本次登录把账号改绑到当前设备密钥时的提示（找回或正版新设备），空串表示不提示
 */
public record ServerAuthConfig(TunnelPolicy tunnelPolicy, ValidationLevels validation,
        int maxPasswordAttempts, int passwordTimeoutSec,
        String restrictedNotice, String recoveryReminderNotice, String rebindNotice) {

    /** 逐级附加验证开关；关闭上一层时不得开启依赖它的层。 */
    public record ValidationLevels(boolean ed25519, boolean loginPassword,
            boolean recoveryPassword, boolean newPlayerRestriction, boolean requirePasswordForVerifiedOps) {
        public static final ValidationLevels DEFAULT = new ValidationLevels(true, true, true, true, false);
        public static final ValidationLevels ALL = new ValidationLevels(true, true, true, true, true);

        public ValidationLevels(boolean ed25519, boolean loginPassword,
                boolean recoveryPassword, boolean newPlayerRestriction) {
            this(ed25519, loginPassword, recoveryPassword, newPlayerRestriction, false);
        }

        public ValidationLevels {
            if (!ed25519 && (loginPassword || recoveryPassword || newPlayerRestriction)) {
                throw new IllegalArgumentException("loginPassword, recoveryPassword and newPlayerRestriction "
                        + "require auth.validation.ed25519=true");
            }
            if (newPlayerRestriction && !loginPassword) {
                throw new IllegalArgumentException(
                        "newPlayerRestriction requires auth.validation.loginPassword=true");
            }
            if (requirePasswordForVerifiedOps && !loginPassword) {
                throw new IllegalArgumentException(
                        "requirePasswordForVerifiedOps requires auth.validation.loginPassword=true");
            }
        }

        /** 只影响当前连接的有效权限，原版 OP 名单仍由服务端管理。 */
        public boolean suspendOp(boolean restricted, boolean hasLoginPassword, boolean verifiedOriginalKey) {
            return restricted || (loginPassword && !hasLoginPassword
                    && (requirePasswordForVerifiedOps || !verifiedOriginalKey));
        }
    }

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
        Objects.requireNonNull(validation, "validation");
        if (!validation.ed25519() && tunnelPolicy != TunnelPolicy.DISABLED) {
            throw new IllegalArgumentException("tunnel requires auth.validation.ed25519=true");
        }
        if (maxPasswordAttempts < 1 || maxPasswordAttempts > 0xFF) {
            throw new IllegalArgumentException("maxPasswordAttempts must be 1..255");
        }
        if (passwordTimeoutSec < 1 || passwordTimeoutSec > 0xFFFF) {
            throw new IllegalArgumentException("passwordTimeoutSec must be 1..65535");
        }
        Objects.requireNonNull(restrictedNotice, "restrictedNotice");
        Objects.requireNonNull(recoveryReminderNotice, "recoveryReminderNotice");
        Objects.requireNonNull(rebindNotice, "rebindNotice");
        // 所有提示同时出现时，Finish 仍须在加密消息体上限之内
        Finish worstCase = new Finish(true,
                notices(true, false, true, restrictedNotice, recoveryReminderNotice, rebindNotice));
        if (MessageCodec.encodeBody(worstCase).length > SecureMessageChannel.MAX_BODY) {
            throw new IllegalArgumentException("notices do not fit in a Finish message");
        }
    }

    /** 保留核心层旧调用点的简写；默认启用全部验证层。 */
    public ServerAuthConfig(TunnelPolicy tunnelPolicy, int maxPasswordAttempts, int passwordTimeoutSec,
            String restrictedNotice, String recoveryReminderNotice, String rebindNotice) {
        this(tunnelPolicy, ValidationLevels.ALL, maxPasswordAttempts, passwordTimeoutSec,
                restrictedNotice, recoveryReminderNotice, rebindNotice);
    }

    public static ServerAuthConfig defaults() {
        return new ServerAuthConfig(TunnelPolicy.OPTIONAL, ValidationLevels.DEFAULT, 3, 60,
                "设定密码后解除新用户限制（使用 /passwd）",
                "尚未设置找回密码，可使用 /recoverypasswd 设置",
                "检测到新设备，已把本服务器的认证绑定更新为这台电脑");
    }

    /** 所有开关均开启的组合，用于完整状态机测试。 */
    public static ServerAuthConfig allValidationDefaults() {
        ServerAuthConfig defaults = defaults();
        return new ServerAuthConfig(defaults.tunnelPolicy(), ValidationLevels.ALL,
                defaults.maxPasswordAttempts(), defaults.passwordTimeoutSec(), defaults.restrictedNotice(),
                defaults.recoveryReminderNotice(), defaults.rebindNotice());
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

    List<String> noticesFor(AccountView account, boolean rebound) {
        return notices(validation.newPlayerRestriction() && account.restricted(),
                !validation.recoveryPassword() || account.hasRecoveryPassword(), rebound, restrictedNotice,
                recoveryReminderNotice, rebindNotice);
    }

    private static List<String> notices(boolean restricted, boolean hasRecovery, boolean rebound,
            String restrictedNotice, String recoveryReminderNotice, String rebindNotice) {
        List<String> out = new ArrayList<>(3);
        if (rebound && !rebindNotice.isEmpty()) {
            out.add(rebindNotice);
        }
        if (restricted && !restrictedNotice.isEmpty()) {
            out.add(restrictedNotice);
        }
        if (!hasRecovery && !recoveryReminderNotice.isEmpty()) {
            out.add(recoveryReminderNotice);
        }
        return out;
    }
}
