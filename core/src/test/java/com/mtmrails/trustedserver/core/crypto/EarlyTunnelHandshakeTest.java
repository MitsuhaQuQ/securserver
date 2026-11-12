package com.mtmrails.trustedserver.core.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.mtmrails.trustedserver.core.tunnel.TunnelDecoder;
import com.mtmrails.trustedserver.core.tunnel.TunnelEncoder;
import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

class EarlyTunnelHandshakeTest {
    private final SecureRandom random = new SecureRandom();
    private final Ed25519.KeyPairData identity = Ed25519.generate(random);

    @Test
    void establishesTwoAuthenticatedStreamsForMinecraftBytes() throws Exception {
        try (var client = new EarlyTunnelHandshake.Client(identity.publicKey(), random);
                var server = new EarlyTunnelHandshake.Server(client.hello(), identity, random)) {
            var result = server.acceptFinished(client.acceptHello(server.hello()));
            try (var serverTransport = result.transport();
                    var clientTransport = client.acceptFinished(result.finished())) {
                byte[] packet = {3, 2, 1};
                assertArrayEquals(packet, new TunnelDecoder(serverTransport.opener())
                        .feed(new TunnelEncoder(clientTransport.sealer()).encode(packet)));
                assertArrayEquals(packet, new TunnelDecoder(clientTransport.opener())
                        .feed(new TunnelEncoder(serverTransport.sealer()).encode(packet)));
            }
        }
    }

    @Test
    void rejectsWrongIdentityAndAlteredTranscriptWithoutRetry() throws Exception {
        byte[] otherIdentity = Ed25519.generate(random).publicKey();
        try (var client = new EarlyTunnelHandshake.Client(otherIdentity, random);
                var server = new EarlyTunnelHandshake.Server(client.hello(), identity, random)) {
            assertThrows(CryptoException.class, () -> client.acceptHello(server.hello()));
        }
        try (var client = new EarlyTunnelHandshake.Client(identity.publicKey(), random)) {
            byte[] altered = client.hello();
            altered[altered.length - 1] ^= 1;
            try (var server = new EarlyTunnelHandshake.Server(altered, identity, random)) {
                assertThrows(CryptoException.class, () -> client.acceptHello(server.hello()));
            }
            try (var server = new EarlyTunnelHandshake.Server(client.hello(), identity, random)) {
                assertThrows(CryptoException.class, () -> client.acceptHello(server.hello()));
            }
        }
    }

    @Test
    void rejectsConfirmationFromAnotherConnectionAndConsumesFailedState() throws Exception {
        try (var client = new EarlyTunnelHandshake.Client(identity.publicKey(), random);
                var first = new EarlyTunnelHandshake.Server(client.hello(), identity, random);
                var second = new EarlyTunnelHandshake.Server(client.hello(), identity, random)) {
            byte[] proof = client.acceptHello(first.hello());
            assertThrows(CryptoException.class, () -> second.acceptFinished(proof));
            var result = first.acceptFinished(proof);
            try (var transport = result.transport()) {
                assertThrows(CryptoException.class, () -> first.acceptFinished(proof));
                byte[] altered = result.finished();
                altered[altered.length - 1] ^= 1;
                assertThrows(CryptoException.class, () -> client.acceptFinished(altered));
                assertThrows(CryptoException.class, () -> client.acceptFinished(result.finished()));
                assertTrue(transport.sealer().isOpen());
            }
        }
    }

    @Test
    void rejectsUnknownVersionAndTrailingBytes() {
        try (var client = new EarlyTunnelHandshake.Client(identity.publicKey(), random)) {
            byte[] hello = client.hello();
            hello[4]++;
            assertThrows(CryptoException.class, () -> new EarlyTunnelHandshake.Server(hello, identity, random));
            byte[] trailing = java.util.Arrays.copyOf(client.hello(), hello.length + 1);
            assertThrows(CryptoException.class, () -> new EarlyTunnelHandshake.Server(trailing, identity, random));
        }
    }
}
