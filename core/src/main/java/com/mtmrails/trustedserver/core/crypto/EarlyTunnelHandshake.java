package com.mtmrails.trustedserver.core.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/** 单连接增强隧道握手（PROTOCOL.md 5.1）。调用方串行传入完整消息，失败或超时后关闭连接。 */
public final class EarlyTunnelHandshake {
    private static final byte[] MAGIC = Bytes.ascii("TSTE");
    private static final int VERSION = 1;
    private static final int HEADER = 6;
    private static final int NONCE_OFFSET = HEADER + 32;
    private static final int IDENTITY_OFFSET = NONCE_OFFSET + 32;
    private static final int SIGNATURE_OFFSET = IDENTITY_OFFSET + 32;
    public static final int CLIENT_HELLO_LENGTH = IDENTITY_OFFSET;
    public static final int SERVER_HELLO_LENGTH = SIGNATURE_OFFSET + 64;
    public static final int FINISHED_LENGTH = HEADER + 32;

    private EarlyTunnelHandshake() {
    }

    public static final class Client implements AutoCloseable {
        private final byte[] trustedIdentity;
        private final byte[] hello;
        private X25519.Ephemeral ephemeral;
        private Secrets secrets;

        public Client(byte[] trustedIdentity, SecureRandom random) {
            this.trustedIdentity = Bytes.requireLength(trustedIdentity, 32, "trustedIdentity").clone();
            ephemeral = X25519.generate(random);
            hello = Bytes.concat(header(1), ephemeral.publicKey(), nonce(random));
        }

        public byte[] hello() {
            return hello.clone();
        }

        public byte[] acceptHello(byte[] serverHello) throws CryptoException {
            X25519.Ephemeral local = ephemeral;
            ephemeral = null;
            boolean accepted = false;
            try {
                if (local == null) {
                    throw new CryptoException("unexpected early tunnel ServerHello");
                }
                check(serverHello, 2, SERVER_HELLO_LENGTH);
                byte[] identity = Arrays.copyOfRange(serverHello, IDENTITY_OFFSET, SIGNATURE_OFFSET);
                byte[] signature = Arrays.copyOfRange(serverHello, SIGNATURE_OFFSET, SERVER_HELLO_LENGTH);
                byte[] unsigned = Arrays.copyOf(serverHello, SIGNATURE_OFFSET);
                if (!MessageDigest.isEqual(trustedIdentity, identity)
                        || !Ed25519.verify(identity, signatureInput(hello, unsigned), signature)) {
                    throw new CryptoException("untrusted early tunnel server identity");
                }
                secrets = new Secrets(local, serverHello, hello, serverHello);
                byte[] finished = secrets.finished(Side.CLIENT);
                accepted = true;
                return finished;
            } finally {
                if (!accepted) {
                    close();
                }
            }
        }

        public Transport acceptFinished(byte[] finished) throws CryptoException {
            ephemeral = null;
            try (Secrets pending = take(secrets)) {
                secrets = null;
                pending.verifyFinished(Side.SERVER, finished);
                return pending.transport(Side.CLIENT);
            }
        }

        @Override
        public void close() {
            ephemeral = null;
            if (secrets != null) {
                secrets.close();
                secrets = null;
            }
        }
    }

    public static final class Server implements AutoCloseable {
        private final byte[] hello;
        private Secrets secrets;

        public Server(byte[] clientHello, Ed25519.KeyPairData identity, SecureRandom random) throws CryptoException {
            check(clientHello, 1, CLIENT_HELLO_LENGTH);
            X25519.Ephemeral ephemeral = X25519.generate(random);
            byte[] unsigned = Bytes.concat(header(2), ephemeral.publicKey(), nonce(random), identity.publicKey());
            hello = Bytes.concat(unsigned, identity.sign(signatureInput(clientHello, unsigned)));
            secrets = new Secrets(ephemeral, clientHello, clientHello, hello);
        }

        public byte[] hello() {
            return hello.clone();
        }

        public ServerResult acceptFinished(byte[] finished) throws CryptoException {
            try (Secrets pending = take(secrets)) {
                secrets = null;
                pending.verifyFinished(Side.CLIENT, finished);
                return new ServerResult(pending.finished(Side.SERVER), pending.transport(Side.SERVER));
            }
        }

        @Override
        public void close() {
            if (secrets != null) {
                secrets.close();
                secrets = null;
            }
        }
    }

    /** 先发送 finished，再使用 transport 发送 Minecraft 字节。 */
    public record ServerResult(byte[] finished, Transport transport) {
        public ServerResult {
            finished = finished.clone();
        }

        @Override
        public byte[] finished() {
            return finished.clone();
        }
    }

    /** 移交给现有 TunnelEncoder / TunnelDecoder 的计数流。 */
    public record Transport(AeadStream sealer, AeadStream opener) implements AutoCloseable {
        @Override
        public void close() {
            sealer.close();
            opener.close();
        }
    }

    private static final class Secrets implements AutoCloseable {
        private final byte[] prk;
        private final byte[] context;

        Secrets(X25519.Ephemeral local, byte[] peer, byte[] clientHello, byte[] serverHello) throws CryptoException {
            context = hash(clientHello, serverHello);
            byte[] salt = Bytes.concat(Arrays.copyOfRange(serverHello, NONCE_OFFSET, IDENTITY_OFFSET),
                    Arrays.copyOfRange(clientHello, NONCE_OFFSET, IDENTITY_OFFSET));
            byte[] shared = local.agree(Arrays.copyOfRange(peer, HEADER, NONCE_OFFSET));
            try {
                prk = Hkdf.extract(salt, shared);
            } finally {
                Arrays.fill(shared, (byte) 0);
            }
        }

        byte[] finished(Side side) {
            return Bytes.concat(header(side == Side.CLIENT ? 3 : 4), derive("finished", side.outbound()));
        }

        void verifyFinished(Side peer, byte[] message) throws CryptoException {
            check(message, peer == Side.CLIENT ? 3 : 4, FINISHED_LENGTH);
            if (!MessageDigest.isEqual(finished(peer), message)) {
                throw new CryptoException("early tunnel key confirmation failed");
            }
        }

        Transport transport(Side side) {
            return new Transport(stream(side.outbound(), AeadStream.Role.SEAL),
                    stream(side.inbound(), AeadStream.Role.OPEN));
        }

        private AeadStream stream(Direction direction, AeadStream.Role role) {
            byte[] key = derive("traffic", direction);
            try {
                return new AeadStream(key, direction, role);
            } finally {
                Arrays.fill(key, (byte) 0);
            }
        }

        private byte[] derive(String purpose, Direction direction) {
            return Hkdf.expand(prk, Bytes.concat(Bytes.ascii("tsrv early v1 " + purpose + " " + direction.label()),
                    context), 32);
        }

        @Override
        public void close() {
            Arrays.fill(prk, (byte) 0);
        }
    }

    private static Secrets take(Secrets secrets) throws CryptoException {
        if (secrets == null) {
            throw new CryptoException("unexpected early tunnel Finished");
        }
        return secrets;
    }

    private static byte[] header(int type) {
        return Bytes.concat(MAGIC, new byte[] {VERSION, (byte) type});
    }

    private static void check(byte[] message, int type, int length) throws CryptoException {
        if (message == null || message.length != length
                || !Arrays.equals(message, 0, HEADER, header(type), 0, HEADER)) {
            throw new CryptoException("invalid early tunnel message");
        }
    }

    private static byte[] nonce(SecureRandom random) {
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);
        return nonce;
    }

    private static byte[] signatureInput(byte[] clientHello, byte[] unsignedServerHello) {
        return Bytes.concat(Bytes.ascii("tsrv early v1 signature"), hash(clientHello, unsignedServerHello));
    }

    private static byte[] hash(byte[] first, byte[] second) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            sha256.update(first);
            return sha256.digest(second);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
