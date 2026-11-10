package com.mtmrails.trustedserver.server.config;

import com.mtmrails.trustedserver.core.session.ServerAuthConfig;
import com.mtmrails.trustedserver.server.account.AccountServiceConfig;
import com.mtmrails.trustedserver.server.policy.NetworkPolicyConfig;
import com.mtmrails.trustedserver.server.status.StatusConfig;
import com.mtmrails.trustedserver.server.store.SqliteStore;
import java.util.Objects;

/**
 * 服务端全部配置，对应 {@code config/trustedserver/server.json}。
 *
 * @param authTimeoutSec 认证总超时（秒），须大于密码输入框超时
 * @param databasePath 玩家数据库位置（相对服务端根目录）
 */
public record ServerConfig(ServerAuthConfig auth, int authTimeoutSec, AccountServiceConfig accounts,
        String databasePath, NetworkPolicyConfig network, StatusConfig status, RejectionText rejection,
        String opSuspendedNotice) {
    public static final ServerConfig DEFAULT = new ServerConfig(ServerAuthConfig.defaults(), 90,
            AccountServiceConfig.DEFAULT, SqliteStore.DEFAULT_PATH, NetworkPolicyConfig.DEFAULT, StatusConfig.DEFAULT,
            RejectionText.DEFAULT, "OP 权限已暂停，可使用 /passwd 设置登录密码");

    public ServerConfig {
        Objects.requireNonNull(auth, "auth");
        Objects.requireNonNull(accounts, "accounts");
        Objects.requireNonNull(databasePath, "databasePath");
        Objects.requireNonNull(network, "network");
        Objects.requireNonNull(status, "status");
        Objects.requireNonNull(rejection, "rejection");
        Objects.requireNonNull(opSuspendedNotice, "opSuspendedNotice");
        if (authTimeoutSec <= auth.passwordTimeoutSec()) {
            throw new IllegalArgumentException("authTimeoutSeconds must be greater than passwordPromptTimeoutSeconds");
        }
        if (databasePath.isBlank()) {
            throw new IllegalArgumentException("database path must not be blank");
        }
    }
}
