package com.mtmrails.trustedserver.core.session;

import com.mtmrails.trustedserver.core.crypto.Ed25519;
import com.mtmrails.trustedserver.core.message.Channel;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiFunction;

/**
 * 把服务端与客户端状态机在内存中对接，模拟 login query 往返；可在两个方向上插入篡改函数。
 */
final class Handshake {
    static final String ADDRESS = "mc.example.test:25565";

    final Ed25519.KeyPairData serverIdentity;
    final InMemoryAccounts accounts;
    final TestClientEnvironment client;
    ServerAuthConfig config = ServerAuthConfig.allValidationDefaults();
    String serverUsername = "Steve";
    String clientUsername = "Steve";
    String accountId = "steve";
    boolean onlineMode;
    boolean mojangVerified;
    boolean wantTunnel;
    Clock clock = Clock.systemUTC();
    BiFunction<Channel, byte[], byte[]> toClient = (c, p) -> p;
    BiFunction<Channel, byte[], byte[]> toServer = (c, p) -> p;

    ServerAuthSession server;
    ClientAuthSession clientSession;
    AuthOutcome serverOutcome;
    ClientStep clientLast;
    final List<Channel> queryChannels = new ArrayList<>();

    Handshake(Ed25519.KeyPairData serverIdentity, InMemoryAccounts accounts, TestClientEnvironment client) {
        this.serverIdentity = serverIdentity;
        this.accounts = accounts;
        this.client = client;
    }

    Handshake run() {
        SecureRandom random = new SecureRandom();
        server = new ServerAuthSession(accountId, serverUsername, onlineMode, mojangVerified, config, serverIdentity,
                accounts, random, clock);
        clientSession = new ClientAuthSession(ADDRESS, clientUsername, wantTunnel, client, random);
        Outbound query = server.start();
        for (int round = 0; round < 32; round++) {
            queryChannels.add(query.channel());
            clientLast = clientSession.onQuery(query.channel(), toClient.apply(query.channel(), query.payload())).join();
            byte[] answer;
            if (clientLast instanceof ClientStep.Reply reply) {
                answer = reply.payload();
            } else if (clientLast instanceof ClientStep.Complete complete) {
                answer = complete.payload();
            } else {
                ClientStep.Fail fail = (ClientStep.Fail) clientLast;
                if (fail.reply().isEmpty()) {
                    // 客户端直接断开：服务端最终以超时结束
                    serverOutcome = server.timeout();
                    return this;
                }
                answer = fail.reply().get();
            }
            ServerStep step = server.onAnswer(query.channel(), toServer.apply(query.channel(), answer)).join();
            if (step instanceof ServerStep.Done done) {
                serverOutcome = done.outcome();
                return this;
            }
            query = ((ServerStep.Send) step).next();
        }
        throw new AssertionError("handshake did not terminate");
    }

    AuthOutcome.Accepted accepted() {
        if (!(serverOutcome instanceof AuthOutcome.Accepted accepted)) {
            throw new AssertionError("expected Accepted, got " + serverOutcome + " / client " + clientLast);
        }
        return accepted;
    }

    AuthOutcome.Rejected rejected() {
        if (!(serverOutcome instanceof AuthOutcome.Rejected rejected)) {
            throw new AssertionError("expected Rejected, got " + serverOutcome);
        }
        return rejected;
    }

    ClientResult clientResult() {
        return ((ClientStep.Complete) clientLast).result();
    }

    ClientFailure clientFailure() {
        if (!(clientLast instanceof ClientStep.Fail fail)) {
            throw new AssertionError("expected client failure, got " + clientLast);
        }
        return fail.failure();
    }

    byte[] clientPublicKey() {
        return client.keyFor(serverIdentity.publicKey(), clientUsername).publicKey();
    }
}
