import com.mtmrails.trustedserver.client.KeyTarget;
import com.mtmrails.trustedserver.client.PlayerKeyStore;
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
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * 用核心层完成真实认证握手的探测客户端（无图形界面），验证“认证通过 → 补发其他登录 query → 登录成功”这条路径。
 * 对非本 mod 的 query 回答“不理解”，与原版客户端一致。
 *
 * 用法：java -cp core.jar:core-client.jar tools/ProbeClient.java [host] [port] [name] [keyDir]
 */
public final class ProbeClient {
    private final Socket socket;
    private final DataInputStream in;
    private final OutputStream out;
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
        Path keyDir = Path.of(args.length > 3 ? args[3] : "build/probe-client-keys");

        PlayerKeyStore keys = new PlayerKeyStore(keyDir);
        Map<String, byte[]> pins = new HashMap<>();
        SecureRandom random = new SecureRandom();
        ClientEnvironment env = new ClientEnvironment() {
            public Optional<byte[]> pinnedServerKey(String a) { return Optional.ofNullable(pins.get(a)); }
            public void pinServerKey(String a, byte[] k) { pins.put(a, k); }
            public CompletableFuture<Boolean> confirmServerKeyChange(String a, byte[] o, byte[] n) {
                return CompletableFuture.completedFuture(false);
            }
            public CompletableFuture<Ed25519.KeyPairData> playerKey(byte[] server, String user) {
                try {
                    return CompletableFuture.completedFuture(keys.getOrCreate(new KeyTarget(server, user), random));
                } catch (IOException e) {
                    return CompletableFuture.failedFuture(e);
                }
            }
            public CompletableFuture<Optional<String>> promptPassword(PasswordRequest r) {
                System.out.println("  password prompt " + r.kind() + " -> skip");
                return CompletableFuture.completedFuture(Optional.empty());
            }
        };
        ClientAuthSession session = new ClientAuthSession(host + ":" + port, name, false, env, random);

        ProbeClient c = new ProbeClient(host, port);
        c.send(0x00, concat(varint(763), string(host), new byte[] {(byte) (port >> 8), (byte) port}, varint(2)));
        c.send(0x00, concat(string(name), new byte[] {0}));
        boolean authFinished = false;
        while (true) {
            byte[] packet = c.receive();
            Reader r = new Reader(packet);
            int id = r.varint();
            switch (id) {
                case 0x03 -> {
                    c.threshold = r.varint();
                    System.out.println("compression threshold " + c.threshold);
                }
                case 0x04 -> {
                    int messageId = r.varint();
                    String channel = r.string();
                    byte[] data = r.rest();
                    Optional<Channel> ours = Channel.fromId(channel);
                    if (ours.isEmpty()) {
                        System.out.println("query " + channel + (authFinished ? " (after auth)" : " (BEFORE auth!)")
                                + " -> not understood");
                        c.send(0x02, concat(varint(messageId), new byte[] {0}));
                        break;
                    }
                    ClientStep step = session.onQuery(ours.get(), data).join();
                    System.out.println("query " + channel + " -> " + step.getClass().getSimpleName());
                    byte[] reply;
                    if (step instanceof ClientStep.Reply rep) {
                        reply = rep.payload();
                    } else if (step instanceof ClientStep.Complete done) {
                        reply = done.payload();
                        authFinished = true;
                        System.out.println("  notices: " + done.result().notices());
                    } else {
                        System.out.println("LOCAL FAILURE: " + ((ClientStep.Fail) step).failure());
                        return;
                    }
                    c.send(0x02, concat(varint(messageId), new byte[] {1}, reply));
                }
                case 0x02 -> {
                    System.out.println("LOGIN SUCCESS (auth finished first: " + authFinished + ")");
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

    static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            o.writeBytes(p);
        }
        return o.toByteArray();
    }
}
