package com.mtmrails.trustedserver.server.password;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Argon2id 密码哈希，输出 PHC 格式：{@code $argon2id$v=19$m=<KiB>,t=<轮数>,p=<并行度>$<salt>$<hash>}
 * （salt 与 hash 为不带填充的标准 Base64）。
 *
 * <p>校验时使用编码串中记录的参数，所以调高参数后旧哈希仍能校验；{@link #needsRehash} 用于在下次登录成功时升级。
 */
public final class PasswordHasher {
    /** 哈希参数。默认值为 OWASP 推荐下限：m = 19 MiB、t = 2、p = 1。 */
    public record Params(int memoryKib, int iterations, int parallelism) {
        public static final Params DEFAULT = new Params(19 * 1024, 2, 1);

        public Params {
            if (memoryKib < 8 * parallelism || memoryKib > MAX_MEMORY_KIB) {
                throw new IllegalArgumentException("memoryKib out of range: " + memoryKib);
            }
            if (iterations < 1 || iterations > MAX_ITERATIONS) {
                throw new IllegalArgumentException("iterations out of range: " + iterations);
            }
            if (parallelism < 1 || parallelism > MAX_PARALLELISM) {
                throw new IllegalArgumentException("parallelism out of range: " + parallelism);
            }
        }
    }

    /** 解析存储的哈希时接受的参数上限，防止损坏或被改动的数据让服务器耗尽内存。 */
    static final int MAX_MEMORY_KIB = 1024 * 1024;
    static final int MAX_ITERATIONS = 64;
    static final int MAX_PARALLELISM = 16;
    static final int SALT_LENGTH = 16;
    static final int HASH_LENGTH = 32;
    private static final String PREFIX = "$argon2id$v=19$";
    private static final Base64.Encoder B64_ENCODER = Base64.getEncoder().withoutPadding();
    private static final Base64.Decoder B64_DECODER = Base64.getDecoder();

    private final Params params;
    private final SecureRandom random;

    public PasswordHasher(Params params, SecureRandom random) {
        this.params = Objects.requireNonNull(params, "params");
        this.random = Objects.requireNonNull(random, "random");
    }

    public String hash(String password) {
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        byte[] hash = derive(password, salt, params, HASH_LENGTH);
        try {
            return PREFIX + "m=" + params.memoryKib() + ",t=" + params.iterations() + ",p=" + params.parallelism()
                    + "$" + B64_ENCODER.encodeToString(salt) + "$" + B64_ENCODER.encodeToString(hash);
        } finally {
            Arrays.fill(hash, (byte) 0);
        }
    }

    /**
     * 校验密码。编码串格式不对或参数越界时抛出 {@link IllegalArgumentException}（存储损坏），
     * 而不是当作密码错误。
     */
    public boolean verify(String password, String encoded) {
        Parsed parsed = parse(encoded);
        byte[] actual = derive(password, parsed.salt(), parsed.params(), parsed.hash().length);
        try {
            return MessageDigest.isEqual(actual, parsed.hash());
        } finally {
            Arrays.fill(actual, (byte) 0);
        }
    }

    /** 编码串的参数与当前配置不同，应在下次校验成功后重新哈希。 */
    public boolean needsRehash(String encoded) {
        return !parse(encoded).params().equals(params);
    }

    private record Parsed(Params params, byte[] salt, byte[] hash) {
    }

    private static Parsed parse(String encoded) {
        if (encoded == null || !encoded.startsWith(PREFIX)) {
            throw new IllegalArgumentException("not an argon2id v19 hash");
        }
        String[] parts = encoded.substring(PREFIX.length()).split("\\$", -1);
        if (parts.length != 3) {
            throw new IllegalArgumentException("malformed argon2id hash");
        }
        String[] kv = parts[0].split(",", -1);
        if (kv.length != 3 || !kv[0].startsWith("m=") || !kv[1].startsWith("t=") || !kv[2].startsWith("p=")) {
            throw new IllegalArgumentException("malformed argon2id parameters");
        }
        Params params;
        byte[] salt;
        byte[] hash;
        try {
            params = new Params(Integer.parseInt(kv[0].substring(2)), Integer.parseInt(kv[1].substring(2)),
                    Integer.parseInt(kv[2].substring(2)));
            salt = B64_DECODER.decode(parts[1]);
            hash = B64_DECODER.decode(parts[2]);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("malformed argon2id hash", e);
        }
        if (salt.length < 8 || hash.length < 16 || hash.length > 64) {
            throw new IllegalArgumentException("argon2id salt or hash length out of range");
        }
        return new Parsed(params, salt, hash);
    }

    static byte[] derive(String password, byte[] salt, Params params, int length) {
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        try {
            Argon2BytesGenerator generator = new Argon2BytesGenerator();
            generator.init(new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                    .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withMemoryAsKB(params.memoryKib())
                    .withIterations(params.iterations())
                    .withParallelism(params.parallelism())
                    .withSalt(salt)
                    .build());
            byte[] out = new byte[length];
            generator.generateBytes(passwordBytes, out);
            return out;
        } finally {
            Arrays.fill(passwordBytes, (byte) 0);
        }
    }
}
