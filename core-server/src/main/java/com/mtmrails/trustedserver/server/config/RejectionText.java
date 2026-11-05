package com.mtmrails.trustedserver.server.config;

import java.util.Objects;

/**
 * 对外统一的拒绝提示（AGENTS.md 第 7、19 条）。默认使用原版封禁提示的翻译键，由客户端按玩家语言显示，
 * 与真正被封禁时无法区分。
 */
public record RejectionText(Mode mode, String customText) {
    public enum Mode {
        VANILLA_BAN,
        CUSTOM
    }

    /** 原版“你已被此服务器封禁”的翻译键。 */
    public static final String VANILLA_BAN_KEY = "multiplayer.disconnect.banned";
    public static final RejectionText DEFAULT = new RejectionText(Mode.VANILLA_BAN, "You are banned from this server.");

    public RejectionText {
        Objects.requireNonNull(mode, "mode");
        Objects.requireNonNull(customText, "customText");
        if (mode == Mode.CUSTOM && customText.isBlank()) {
            throw new IllegalArgumentException("custom rejection text must not be blank");
        }
    }
}
