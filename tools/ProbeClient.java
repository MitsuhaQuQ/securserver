import com.mtmrails.trustedserver.core.crypto.PresharedKeyHandshake;
import com.mtmrails.trustedserver.core.crypto.PskWire;
import com.mtmrails.trustedserver.core.crypto.Ed25519;
import com.mtmrails.trustedserver.core.message.Channel;
import com.mtmrails.trustedserver.core.message.PasswordRequest;
import com.mtmrails.trustedserver.core.session.ClientAuthSession;
import com.mtmrails.trustedserver.core.session.ClientEnvironment;
import com.mtmrails.trustedserver.core.session.ClientStep;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.nio.file.Files;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * 用核心层完成第一阶段 PSK 门禁的探测客户端（无图形界面），验证“PSK 通过 → 补发其他登录 query → 登录成功”。
 * 对非本 mod 的 query 回答“不理解”，与原版客户端一致。
 *
 * 用法：java -cp core.jar tools/ProbeClient.java [host] [port] [name] [pskFile] [--prompt]
 */
public final class ProbeClient {
    private final Socket socket;
    private DataInputStream in;
    private OutputStream out;
    private int threshold = -1;

    ProbeClient(String host, int port) throws IOException {
        socket = new Socket(host, port);
        socket.setSoTimeout(30_000);
        in = new DataInputStream(socket.getInputStream());
        out = socket.getOutputStream();
    }

    public static void main(String[] args) throws Exception {
        String host = args.length > 0 ? args[0] : "127.0.0.1";
        int port = args.length > 1 ? Integer.parseInt(args[1]) : 25565;
        String name = args.length > 2 ? args[2] : "ProbeClient";
        Path pskFile = Path.of(args.length > 3 ? args[3] : "fabric-1.20.1/run/config/trustedserver/psk.key");
        boolean simulatePrompt = args.length > 4 && "--prompt".equals(args[4]);
        byte[] psk = Base64.getDecoder().decode(Files.readString(pskFile).trim());
        SecureRandom random = new SecureRandom();
        PresharedKeyHandshake.Client pskSession = null;
        boolean promptRequested = false;
        Ed25519.KeyPairData playerKey = Ed25519.generate(random);
        byte[][] pinnedServer = new byte[1][];
        ClientEnvironment environment = new ClientEnvironment() {
            public Optional<byte[]> pinnedServerKey(String address) {
                return Optional.ofNullable(pinnedServer[0]).map(byte[]::clone);
            }
            public void pinServerKey(String address, byte[] key) {
                pinnedServer[0] = key.clone();
            }
            public CompletableFuture<Boolean> confirmServerKeyChange(String address, byte[] oldKey, byte[] newKey) {
                return CompletableFuture.completedFuture(false);
            }
            public CompletableFuture<Ed25519.KeyPairData> playerKey(byte[] serverKey, String username) {
                return CompletableFuture.completedFuture(playerKey);
            }
            public CompletableFuture<Optional<String>> promptPassword(PasswordRequest request) {
                return CompletableFuture.completedFuture(Optional.empty());
            }
        };
        ClientAuthSession formalAuth = new ClientAuthSession(host + ":" + port, name, false, environment, random);

        ProbeClient c = new ProbeClient(host, port);
        c.send(0x00, concat(varint(763), string(host), new byte[] {(byte) (port >> 8), (byte) port}, varint(2)));
        c.send(0x00, concat(string(name), new byte[] {0}));
        boolean authFinished = false;
        boolean baseFinished = false;
        while (true) {
            byte[] packet = c.receive();
            Reader r = new Reader(packet);
            int id = r.varint();
            switch (id) {
                case 0x01 -> {
                    r.string(); // legacy server id, empty in 1.20.1
                    byte[] encodedPublic = r.bytes();
                    byte[] verifyToken = r.bytes();
                    PublicKey publicKey = KeyFactory.getInstance("RSA")
                            .generatePublic(new X509EncodedKeySpec(encodedPublic));
                    KeyGenerator generator = KeyGenerator.getInstance("AES");
                    generator.init(128);
                    SecretKey secret = generator.generateKey();
                    Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    rsa.init(Cipher.ENCRYPT_MODE, publicKey);
                    c.send(0x01, concat(bytes(rsa.doFinal(secret.getEncoded())), bytes(rsa.doFinal(verifyToken))));
                    c.enableEncryption(secret);
                    System.out.println("online encryption established; intentionally skipping Mojang session join");
                }
                case 0x03 -> {
                    c.threshold = r.varint();
                    System.out.println("compression threshold " + c.threshold);
                }
                case 0x04 -> {
                    int messageId = r.varint();
                    String channel = r.string();
                    byte[] data = r.rest();
                    if (!PskWire.CHANNEL.equals(channel)) {
                        Optional<Channel> formalChannel = Channel.fromId(channel);
                        if (formalChannel.isPresent()) {
                            ClientStep step = formalAuth.onQuery(formalChannel.orElseThrow(), data).join();
                            if (step instanceof ClientStep.Reply replyStep) {
                                c.send(0x02, concat(varint(messageId), new byte[] {1}, replyStep.payload()));
                            } else if (step instanceof ClientStep.Complete complete) {
                                authFinished = true;
                                c.send(0x02, concat(varint(messageId), new byte[] {1}, complete.payload()));
                                System.out.println("Ed25519 server identity and player proof verified -> finish ack");
                            } else {
                                throw new IllegalStateException("formal auth failed: "
                                        + ((ClientStep.Fail) step).failure());
                            }
                            break;
                        }
                        System.out.println("query " + channel + (authFinished ? " (after auth)" : " (BEFORE auth!)")
                                + " -> not understood");
                        c.send(0x02, concat(varint(messageId), new byte[] {0}));
                        break;
                    }
                    byte[] reply;
                    PskWire.Type type = PskWire.type(data);
                    if (type == PskWire.Type.CHALLENGE) {
                        if (simulatePrompt && !promptRequested) {
                            promptRequested = true;
                            reply = PskWire.encodePromptRequest();
                            System.out.println("PSK missing -> prompt request");
                            c.send(0x02, concat(varint(messageId), new byte[] {1}, reply));
                            break;
                        }
                        pskSession = PresharedKeyHandshake.beginClient(psk, PskWire.context(name),
                                PskWire.decodeChallenge(data), random);
                        reply = PskWire.encodeClientResponse(pskSession.response());
                        System.out.println("PSK challenge -> client response");
                    } else if (type == PskWire.Type.SERVER_PROOF && pskSession != null) {
                        pskSession.verify(PskWire.decodeServerProof(data));
                        reply = PskWire.encodeAck();
                        baseFinished = true;
                        System.out.println("PSK server proof verified -> ack");
                    } else {
                        throw new IllegalStateException("unexpected PSK message " + type);
                    }
                    c.send(0x02, concat(varint(messageId), new byte[] {1}, reply));
                }
                case 0x02 -> {
                    System.out.println("LOGIN SUCCESS (base gate: " + baseFinished
                            + ", Ed25519 auth: " + authFinished + ")");
                    c.socket.close();
                    return;
                }
                case 0x00 -> {
                    System.out.println("DISCONNECTED: " + r.string());
                    return;
                }
                default -> System.out.println("login packet 0x" + Integer.toHexString(id));
            }
        }
    }

    void enableEncryption(SecretKey secret) throws Exception {
        Cipher decrypt = Cipher.getInstance("AES/CFB8/NoPadding");
        Cipher encrypt = Cipher.getInstance("AES/CFB8/NoPadding");
        IvParameterSpec iv = new IvParameterSpec(secret.getEncoded());
        decrypt.init(Cipher.DECRYPT_MODE, secret, iv);
        encrypt.init(Cipher.ENCRYPT_MODE, secret, iv);
        in = new DataInputStream(new CipherInputStream(socket.getInputStream(), decrypt));
        out = new CipherOutputStream(socket.getOutputStream(), encrypt);
    }

    void send(int id, byte[] body) throws IOException {
        byte[] data = concat(varint(id), body);
        if (threshold >= 0) {
            if (data.length >= threshold) {
                Deflater deflater = new Deflater();
                deflater.setInput(data);
                deflater.finish();
                ByteArrayOutputStream z = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                while (!deflater.finished()) {
                    z.write(buf, 0, deflater.deflate(buf));
                }
                data = concat(varint(data.length), z.toByteArray());
            } else {
                data = concat(varint(0), data);
            }
        }
        out.write(concat(varint(data.length), data));
        out.flush();
    }

    byte[] receive() throws Exception {
        int length = readVarint(in);
        byte[] data = new byte[length];
        in.readFully(data);
        if (threshold < 0) {
            return data;
        }
        Reader r = new Reader(data);
        int inner = r.varint();
        byte[] rest = r.rest();
        if (inner == 0) {
            return rest;
        }
        Inflater inflater = new Inflater();
        inflater.setInput(rest);
        byte[] result = new byte[inner];
        inflater.inflate(result);
        return result;
    }

    static int readVarint(InputStream s) throws IOException {
        int value = 0;
        for (int i = 0; i < 5; i++) {
            int b = s.read();
            if (b < 0) {
                throw new IOException("connection closed");
            }
            value |= (b & 0x7F) << (7 * i);
            if ((b & 0x80) == 0) {
                return value;
            }
        }
        throw new IOException("VarInt too long");
    }

    static final class Reader {
        final byte[] d;
        int p;

        Reader(byte[] d) {
            this.d = d;
        }

        int varint() {
            int value = 0;
            for (int i = 0; i < 5; i++) {
                int b = d[p++] & 0xFF;
                value |= (b & 0x7F) << (7 * i);
                if ((b & 0x80) == 0) {
                    return value;
                }
            }
            throw new IllegalStateException("VarInt too long");
        }

        String string() {
            int n = varint();
            String s = new String(d, p, n, StandardCharsets.UTF_8);
            p += n;
            return s;
        }

        byte[] bytes() {
            int n = varint();
            byte[] value = java.util.Arrays.copyOfRange(d, p, p + n);
            p += n;
            return value;
        }

        byte[] rest() {
            byte[] r = java.util.Arrays.copyOfRange(d, p, d.length);
            p = d.length;
            return r;
        }
    }

    static byte[] varint(int value) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        while ((value & ~0x7F) != 0) {
            o.write((value & 0x7F) | 0x80);
            value >>>= 7;
        }
        o.write(value);
        return o.toByteArray();
    }

    static byte[] string(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        return concat(varint(b.length), b);
    }

    static byte[] bytes(byte[] value) {
        return concat(varint(value.length), value);
    }

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            o.writeBytes(p);
        }
        return o.toByteArray();
    }
}
