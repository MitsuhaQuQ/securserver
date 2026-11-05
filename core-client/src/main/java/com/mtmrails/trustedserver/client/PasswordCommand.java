package com.mtmrails.trustedserver.client;

import java.util.Locale;
import java.util.Objects;

/**
 * 客户端在本地拦截 {@code /passwd} 与 {@code /recoverypasswd}（PROTOCOL.md 第 6 节）。
 *
 * <p>只要是这两个命令（无论参数是否正确），都必须拦截、绝不作为聊天命令发给服务器，以免密码以明文泄露。
 * 参数以单个空格分隔，因此密码不能包含空格。
 */
public sealed interface PasswordCommand {
    /** 设定登录密码或找回密码，两次输入已在本地核对一致。 */
    record Set(Kind kind, String password) implements PasswordCommand {
        public Set {
            Objects.requireNonNull(kind, "kind");
            Objects.requireNonNull(password, "password");
        }

        @Override
        public String toString() {
            return "Set[kind=" + kind + ", password=<redacted>]";
        }
    }

    /** 是本 mod 的命令但用法不对：只在本地提示，不发送任何内容。 */
    record Invalid(Kind kind, String reason) implements PasswordCommand {
    }

    /** 不是本 mod 的命令，照常交给原版处理。 */
    record NotOurs() implements PasswordCommand {
    }

    enum Kind {
        LOGIN("passwd"),
        RECOVERY("recoverypasswd");

        private final String command;

        Kind(String command) {
            this.command = command;
        }

        public String usage() {
            return "/" + command + " <密码> <确认密码>";
        }
    }

    /** 解析一行聊天输入（含开头的 {@code /}）。 */
    static PasswordCommand parse(String line) {
        if (line == null || !line.startsWith("/")) {
            return new NotOurs();
        }
        String body = line.substring(1);
        int space = body.indexOf(' ');
        String name = (space < 0 ? body : body.substring(0, space)).toLowerCase(Locale.ROOT);
        Kind kind;
        if (name.equals(Kind.LOGIN.command)) {
            kind = Kind.LOGIN;
        } else if (name.equals(Kind.RECOVERY.command)) {
            kind = Kind.RECOVERY;
        } else {
            return new NotOurs();
        }
        String[] args = space < 0 ? new String[0] : body.substring(space + 1).split(" ", -1);
        if (args.length != 2 || args[0].isEmpty() || args[1].isEmpty()) {
            return new Invalid(kind, "用法：" + kind.usage() + "（密码不能包含空格）");
        }
        if (!args[0].equals(args[1])) {
            return new Invalid(kind, "两次输入的密码不一致");
        }
        return new Set(kind, args[0]);
    }
}
