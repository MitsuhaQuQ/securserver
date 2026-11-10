package com.mtmrails.trustedserver.core.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

/**
 * 基于高熵预共享密钥的简易双向挑战应答。
 *
 * <p>该类只负责证明双方持有同一个 PSK，不定义线上消息格式，也不建立加密通道。调用方应把服务器身份、
 * 用户名和协议版本等规范编码放进 {@code context}，并在一次连接中只使用一个实例。
 */
public final class PresharedKeyHandshake {
    public static final int MIN_KEY_LENGTH = 32;
    public static final int NONCE_LENGTH = 32;
    public static final int PROOF_LENGTH = 32;

    private static final byte[] CLIENT_LABEL = Bytes.ascii("tsrv psk v1 client");
    private static final byte[] SERVER_LABEL = Bytes.ascii("tsrv psk v1 server");

    private PresharedKeyHandshake() {
    }

    public static Server beginServer(byte[] key, byte[] context, SecureRandom random) {
        return new Server(key, context, random);
    }

    public static Client beginClient(byte[] key, byte[] context, Challenge challenge, SecureRandom random) {
        return new Client(key, context, challenge, random);
    }

    /** 服务端发给客户端的随机挑战。 */
    public record Challenge(byte[] serverNonce) {
        public Challenge {
            serverNonce = copyExact(serverNonce, NONCE_LENGTH, "serverNonce");
        }

        @Override
        public byte[] serverNonce() {
            return serverNonce.clone();
        }
    }

    /** 客户端返回的随机数与客户端证明。 */
    public record ClientResponse(byte[] clientNonce, byte[] proof) {
        public ClientResponse {
            clientNonce = copyExact(clientNonce, NONCE_LENGTH, "clientNonce");
            proof = copyExact(proof, PROOF_LENGTH, "proof");
        }

        @Override
        public byte[] clientNonce() {
            return clientNonce.clone();
        }

        @Override
        public byte[] proof() {
            return proof.clone();
        }
    }

    /** 客户端验证服务端持有同一 PSK 所需的证明。 */
    public record ServerProof(byte[] proof) {
        public ServerProof {
            proof = copyExact(proof, PROOF_LENGTH, "proof");
        }

        @Override
        public byte[] proof() {
            return proof.clone();
        }
    }

    /** 服务端侧的一次性验证状态。 */
    public static final class Server implements AutoCloseable {
        private final byte[] key;
        private final byte[] contextHash;
        private final byte[] serverNonce;
        private State state = State.ACTIVE;

        private Server(byte[] key, byte[] context, SecureRandom random) {
            this.key = copyKey(key);
            this.contextHash = hashContext(context);
            this.serverNonce = randomBytes(random, NONCE_LENGTH);
        }

        public Challenge challenge() {
            requireActive();
            return new Challenge(serverNonce);
        }

        /** 验证客户端并返回服务端证明。无论成功或失败，本实例都不能再次验证。 */
        public ServerProof verify(ClientResponse response) throws PskAuthenticationException {
            requireActive();
            Objects.requireNonNull(response, "response");
            Proofs proofs = derive(key, serverNonce, response.clientNonce, contextHash);
            boolean accepted = MessageDigest.isEqual(proofs.client, response.proof);
            Arrays.fill(proofs.client, (byte) 0);
            clearInputs();
            if (!accepted) {
                Arrays.fill(proofs.server, (byte) 0);
                state = State.FAILED;
                throw new PskAuthenticationException("client PSK proof does not match");
            }
            ServerProof result = new ServerProof(proofs.server);
            Arrays.fill(proofs.server, (byte) 0);
            state = State.AUTHENTICATED;
            return result;
        }

        public boolean authenticated() {
            return state == State.AUTHENTICATED;
        }

        @Override
        public void close() {
            clearInputs();
            state = State.CLOSED;
        }

        private void clearInputs() {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(contextHash, (byte) 0);
        }

        private void requireActive() {
            if (state != State.ACTIVE) {
                throw new IllegalStateException("PSK server handshake is no longer active");
            }
        }
    }

    /** 客户端侧的一次性验证状态。 */
    public static final class Client implements AutoCloseable {
        private final ClientResponse response;
        private final byte[] expectedServerProof;
        private State state = State.ACTIVE;

        private Client(byte[] key, byte[] context, Challenge challenge, SecureRandom random) {
            byte[] keyCopy = copyKey(key);
            byte[] contextHash = hashContext(context);
            byte[] clientNonce = randomBytes(random, NONCE_LENGTH);
            Objects.requireNonNull(challenge, "challenge");
            Proofs proofs = derive(keyCopy, challenge.serverNonce, clientNonce, contextHash);
            response = new ClientResponse(clientNonce, proofs.client);
            expectedServerProof = proofs.server;
            Arrays.fill(proofs.client, (byte) 0);
            Arrays.fill(keyCopy, (byte) 0);
            Arrays.fill(contextHash, (byte) 0);
            Arrays.fill(clientNonce, (byte) 0);
        }

        public ClientResponse response() {
            requireActive();
            return new ClientResponse(response.clientNonce, response.proof);
        }

        /** 验证服务端证明。无论成功或失败，本实例都不能再次验证。 */
        public void verify(ServerProof proof) throws PskAuthenticationException {
            requireActive();
            Objects.requireNonNull(proof, "proof");
            boolean accepted = MessageDigest.isEqual(expectedServerProof, proof.proof);
            clearInputs();
            if (!accepted) {
                state = State.FAILED;
                throw new PskAuthenticationException("server PSK proof does not match");
            }
            state = State.AUTHENTICATED;
        }

        public boolean authenticated() {
            return state == State.AUTHENTICATED;
        }

        @Override
        public void close() {
            clearInputs();
            state = State.CLOSED;
        }

        private void clearInputs() {
            Arrays.fill(expectedServerProof, (byte) 0);
            Arrays.fill(response.clientNonce, (byte) 0);
            Arrays.fill(response.proof, (byte) 0);
        }

        private void requireActive() {
            if (state != State.ACTIVE) {
                throw new IllegalStateException("PSK client handshake is no longer active");
            }
        }
    }

    private enum State {
        ACTIVE,
        AUTHENTICATED,
        FAILED,
        CLOSED
    }

    private record Proofs(byte[] client, byte[] server) {
    }

    private static Proofs derive(byte[] key, byte[] serverNonce, byte[] clientNonce, byte[] contextHash) {
        byte[] salt = Bytes.concat(serverNonce, clientNonce);
        byte[] prk = Hkdf.extract(salt, key);
        Arrays.fill(salt, (byte) 0);
        byte[] clientInfo = Bytes.concat(CLIENT_LABEL, contextHash);
        byte[] serverInfo = Bytes.concat(SERVER_LABEL, contextHash);
        byte[] clientProof = Hkdf.expand(prk, clientInfo, PROOF_LENGTH);
        byte[] serverProof = Hkdf.expand(prk, serverInfo, PROOF_LENGTH);
        Arrays.fill(prk, (byte) 0);
        Arrays.fill(clientInfo, (byte) 0);
        Arrays.fill(serverInfo, (byte) 0);
        return new Proofs(clientProof, serverProof);
    }

    private static byte[] copyKey(byte[] key) {
        Objects.requireNonNull(key, "key");
        if (key.length < MIN_KEY_LENGTH) {
            throw new IllegalArgumentException("PSK must be at least " + MIN_KEY_LENGTH + " bytes");
        }
        return key.clone();
    }

    private static byte[] hashContext(byte[] context) {
        Objects.requireNonNull(context, "context");
        try {
            return MessageDigest.getInstance("SHA-256").digest(context);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static byte[] randomBytes(SecureRandom random, int length) {
        Objects.requireNonNull(random, "random");
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    private static byte[] copyExact(byte[] value, int length, String name) {
        Objects.requireNonNull(value, name);
        if (value.length != length) {
            throw new IllegalArgumentException(name + " must be " + length + " bytes");
        }
        return value.clone();
    }
}
