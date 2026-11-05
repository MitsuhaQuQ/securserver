package com.mtmrails.trustedserver.server.password;

import java.util.Optional;

/**
 * 服务端密码长度规则，按 Unicode 码点计。
 *
 * <p>“登录密码与找回密码不能相同”需要用另一种密码的哈希校验新密码，由账号服务负责。
 *
 * @param minLength 最短码点数，至少 1
 * @param maxLength 最长码点数，不超过协议上限 128
 */
public record PasswordPolicy(int minLength, int maxLength) {
    public static final PasswordPolicy DEFAULT = new PasswordPolicy(6, 128);
    private static final int PROTOCOL_MAX = 128;

    public PasswordPolicy {
        if (minLength < 1 || maxLength > PROTOCOL_MAX || minLength > maxLength) {
            throw new IllegalArgumentException("invalid password length range " + minLength + ".." + maxLength);
        }
    }

    /** @return 不符合规则时给玩家看的原因 */
    public Optional<String> checkLength(String password) {
        int length = password.codePointCount(0, password.length());
        if (length < minLength) {
            return Optional.of("密码至少需要 " + minLength + " 个字符");
        }
        if (length > maxLength) {
            return Optional.of("密码最多 " + maxLength + " 个字符");
        }
        return Optional.empty();
    }
}
