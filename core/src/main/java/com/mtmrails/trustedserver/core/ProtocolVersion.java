package com.mtmrails.trustedserver.core;

/**
 * 认证协议版本号（PROTOCOL.md 第 10 节）。
 *
 * <p>只在线上格式、密码学或状态机变化时递增，与 mod 版本号无关。
 */
public final class ProtocolVersion {
    /** 当前协议版本。 */
    public static final int CURRENT = 3;

    /** 本实现支持的全部协议版本。 */
    private static final int[] SUPPORTED = {CURRENT};

    /** ClientHello 中表示“没有共同版本”的取值。 */
    public static final int NONE = 0;

    private ProtocolVersion() {
    }

    /** 本实现支持的协议版本列表（副本）。 */
    public static int[] supported() {
        return SUPPORTED.clone();
    }

    /**
     * 从对方提供的版本列表中选出双方都支持的最高版本。
     *
     * @return 协商出的版本；没有共同版本时返回 {@link #NONE}
     */
    public static int negotiate(int[] offered) {
        int best = NONE;
        for (int candidate : offered) {
            if (candidate > best && isSupported(candidate)) {
                best = candidate;
            }
        }
        return best;
    }

    /** 本实现是否支持指定版本。 */
    public static boolean isSupported(int version) {
        for (int v : SUPPORTED) {
            if (v == version) {
                return true;
            }
        }
        return false;
    }
}
