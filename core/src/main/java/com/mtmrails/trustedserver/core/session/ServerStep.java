package com.mtmrails.trustedserver.core.session;

/** 服务端状态机处理一条回答后的下一步。 */
public sealed interface ServerStep {
    /** 继续：发出下一条 query。 */
    record Send(Outbound next) implements ServerStep {
    }

    /** 结束：放行或断开。 */
    record Done(AuthOutcome outcome) implements ServerStep {
    }
}
