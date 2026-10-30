package com.mtmrails.trustedserver.core.message;

import java.util.Optional;

/** 本协议使用的两个频道（PROTOCOL.md 第 1 节）。 */
public enum Channel {
    /** 握手与身份认证。 */
    AUTH("trustedserver:auth"),
    /** 密码专用通道：所有携带密码的消息只走这里。 */
    PASSWORD("trustedserver:password");

    private final String id;

    Channel(String id) {
        this.id = id;
    }

    /** 频道 ID，即 Minecraft 自定义数据包使用的资源位置。 */
    public String id() {
        return id;
    }

    public static Optional<Channel> fromId(String id) {
        for (Channel channel : values()) {
            if (channel.id.equals(id)) {
                return Optional.of(channel);
            }
        }
        return Optional.empty();
    }
}
