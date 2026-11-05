package com.mtmrails.trustedserver.server.policy;

import java.net.InetAddress;
import java.util.Optional;
import java.util.UUID;

/**
 * 封禁查询接口：由适配层接上原版封禁列表（用户名 / UUID / IP），在认证之前调用（PROTOCOL.md 第 7 节）。
 */
public interface BanGate {
    boolean isBanned(String username, Optional<UUID> uuid, InetAddress address);
}
