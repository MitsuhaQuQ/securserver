package com.mtmrails.trustedserver.server.config;

/** 配置文件非法。服务端应拒绝启动并显示该信息，而不是悄悄改用默认值。 */
public final class ConfigException extends Exception {
    private static final long serialVersionUID = 1L;

    public ConfigException(String message) {
        super(message);
    }

    public ConfigException(String message, Throwable cause) {
        super(message, cause);
    }
}
