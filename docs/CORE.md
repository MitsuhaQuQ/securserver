# 核心逻辑（core）规划

> 依据：[AGENTS.md](../AGENTS.md)、[PROTOCOL.md](PROTOCOL.md)。
> 本文规划与 Minecraft 无关的核心层：模块划分、包结构、关键接口、线程模型、依赖、测试和实施顺序。

## 1. 原则

- **与 Minecraft 无关**：core 层不引用任何 Minecraft、加载器或 Netty 类型，只处理 `byte[]`。所有版本、所有加载器共用同一份代码，也能在普通 JUnit 中完整测试
- **纯状态机**：认证流程实现为“输入字节 → 输出字节和判定”的状态机，不碰网络 IO。时间（`Clock`）和随机数（`SecureRandom`）从外部注入，测试可以完全复现
- **不阻塞网络线程**：Argon2id 和 SQLite 都是慢操作，统一放到专用线程池，状态机以 `CompletableFuture` 返回结果
- **Java 17**：与 1.18.2 的最低 Java 版本一致；可以使用 record 和 sealed interface
- **依赖最少**：Minecraft 自带 Gson，core 只以 `compileOnly` 方式依赖它；不用 Guava

## 2. 模块划分

```
core/          协议、加密、状态机（客户端和服务端都用）
core-server/   账号服务、存储（SQLite）、限流与锁定、配置、Ping 脱敏
core-client/   服务端公钥 TOFU 记录、玩家密钥存储
common/        Minecraft 适配层（Mixin、登录 query、Netty 处理器），后续规划
fabric/ forge/ neoforge/   加载器入口，后续规划
```

`core-server` 和 `core-client` 都依赖 `core`，二者互不依赖。最终的 mod jar 同时包含两边（一个 jar 通吃客户端和服务端），运行时按环境只初始化需要的一侧。

## 3. 包结构

根包为 `com.mtmrails.trustedserver`。

### 3.1 `core`

```
com.mtmrails.trustedserver.core
├── wire/        二进制编解码
│   ├── WireReader / WireWriter      VarInt、varbytes、string、定长字段；越界或超长立即抛异常
│   └── MalformedMessageException    受检异常：收到的字节不合规，调用方按协议错误断开
├── message/     协议消息（record），对应 PROTOCOL.md 第 4、6 节
│   ├── Message (sealed)             所有消息的公共接口：type() + writeBody()
│   ├── AuthMessage (sealed)         ServerHello / ClientHello / Challenge / ClientProof / Finish / FinishAck
│   ├── PasswordMessage (sealed)     PasswordRequest / PasswordAnswer / SetPassword / SetRecoveryPassword / PasswordResult
│   ├── MessageType                  type 字节、所属频道、是否必须加密
│   ├── Channel                      AUTH = "trustedserver:auth"、PASSWORD = "trustedserver:password"
│   ├── Envelope                     magic + type + body；校验 magic、type 和频道；header 即 AEAD 的 AAD
│   ├── MessageCodec                 明文消息的整包编解码；加密消息只编解码消息体
│   └── Limits                       各字段长度上限（密码 128 码点、payload 4096 字节等）
├── crypto/
│   ├── X25519                       临时密钥对、DH，拒绝全零结果
│   ├── Ed25519                      签名、验签、公钥编解码（32 字节原始格式）
│   ├── Hkdf                         RFC 5869，基于 HmacSHA256
│   ├── SessionKeys                  按 PROTOCOL.md 4.3 派生六把密钥（auth / tunnel / password × 两个方向）
│   ├── AeadChannel                  AES-256-GCM；方向标签 + u64 序号作 nonce；序号严格递增，乱序或重放即失败
│   └── Transcript                   transcript_0 的计算
├── session/
│   ├── ServerAuthSession            服务端状态机
│   ├── ClientAuthSession            客户端状态机
│   ├── Outbound                     record(channel, payload)：要发给对方的一条 query 或回答
│   ├── AuthOutcome                  最终结果：Accepted(身份, 是否受限, 是否开隧道, notices) / Rejected(原因)
│   └── RejectReason                 枚举：NO_MOD、VERSION_MISMATCH、KEY_MISMATCH、LOCKED、TIMEOUT、BANNED、PROTOCOL_ERROR …
├── tunnel/
│   └── TunnelFrameCodec             隧道帧加解密（只处理字节块，Netty 适配放在 common）
└── ProtocolVersion                  当前版本号、支持列表、协商逻辑
```

### 3.2 `core-server`

```
com.mtmrails.trustedserver.server
├── account/
│   ├── AccountService               绑定、校验密码、设定密码（解除受限）、找回重绑、管理员 reset / trust
│   ├── Account (record)             对应 players 表
│   └── PlayerId                     正版用 UUID，离线用小写用户名
├── password/
│   └── PasswordHasher               Argon2id；PHC 格式编码串；参数可配置；支持日后升级参数时重新哈希
├── store/
│   ├── AccountStore / LockoutStore / AuditLog      接口
│   ├── sqlite/                      SQLite 实现；表结构版本号 + 迁移脚本
│   └── memory/                      内存实现，供测试使用
├── policy/
│   ├── RateLimiter                  按 IP 的令牌桶，覆盖 Ping 和登录
│   ├── LockoutPolicy                按用户名和 IP 统计密码失败次数并锁定
│   ├── BanGate                      接口，由 common 层接上原版封禁列表
│   └── OpGuard                      判断 OP 是否需要暂停权限（未设密码或受限）
├── status/
│   └── StatusSanitizer              输入真实人数，按配置输出（真实 / 固定 / 范围内随机）；去掉玩家样本列表
├── config/
│   ├── ServerConfig (record)        对应 JSON 配置
│   └── ConfigLoader                 读写 JSON、填默认值、校验，非法配置给出明确报错
└── ServerIdentity                   服务端 Ed25519 身份密钥的生成与加载
```

### 3.3 `core-client`

```
com.mtmrails.trustedserver.client
├── KnownServers                     服务器地址 → 服务端身份公钥（TOFU），检测公钥变化
├── PlayerKeyStore                   (服务端身份公钥, 用户名) → 玩家 Ed25519 密钥对；文件权限设为仅本人可读
└── PasswordPrompt                   接口：由 common 层用 GUI 实现，返回 CompletableFuture<Optional<String>>
```

## 4. 关键接口草图

```java
// 服务端：一个连接对应一个实例，由 common 层持有
public final class ServerAuthSession {
    ServerAuthSession(PlayerId id, String username, boolean onlineMode,
                      AccountService accounts, ServerConfig config,
                      ServerIdentity identity, Clock clock, SecureRandom rng);

    Outbound start();                                        // 生成 ServerHello
    CompletableFuture<Step> onAnswer(String channel, byte[] payloadOrNull);  // null 表示对方“不理解”
    Optional<SessionKeys> keys();                            // 认证成功后交给隧道和密码通道
}

public sealed interface Step {
    record Send(Outbound next) implements Step {}            // 继续发下一条 query
    record Done(AuthOutcome outcome) implements Step {}      // 结束：放行或断开
}

// 客户端
public final class ClientAuthSession {
    ClientAuthSession(String serverAddress, String username, boolean wantTunnel,
                      KnownServers known, PlayerKeyStore keys, PasswordPrompt prompt,
                      SecureRandom rng);

    CompletableFuture<Optional<byte[]>> onQuery(String channel, byte[] payload);  // 返回空表示“不理解”
}

// 游戏阶段的密码通道，接续登录阶段的密钥和序号
public final class PasswordChannel {
    byte[] seal(PasswordMessage msg);
    PasswordMessage open(byte[] payload);                     // 重放、乱序、篡改都抛异常
}
```

- 状态机内部用枚举记录当前状态，收到当前状态不期望的消息类型，一律判为 `PROTOCOL_ERROR`
- 状态机本身不处理超时；超时由 common 层计时，到点后调用 `session.timeout()` 得到 `Rejected(TIMEOUT)`
- 拒绝原因只在内部和审计日志中使用；发给客户端的文本统一由配置决定（模仿原版封禁或自定义），未装 mod 的连接看不出差别

## 5. 线程模型

```
Netty 事件循环线程（common）
   │  收到 query 回答
   ▼
ServerAuthSession.onAnswer ──► 需要慢操作？──是──► authExecutor（固定大小线程池）
   │                                                 Argon2id / SQLite
   ▼                                                      │
CompletableFuture<Step> ◄───────────────────────────────────┘
   │  common 层切回该连接的事件循环
   ▼
发送下一条 query，或断开 / 放行
```

- `authExecutor` 的线程数和排队上限可配置；队列满时新连接直接按 `RATE_LIMITED` 拒绝，避免被大量连接拖垮
- Argon2id 默认参数取 OWASP 推荐的下限：m = 19 MiB、t = 2、p = 1（可配置）。同时进行的哈希数量受线程池大小限制，内存占用可控
- 游戏阶段的 `/passwd` 同样交给 `authExecutor` 处理，结果切回服务端主线程后再改动玩家的权限状态

## 6. 依赖

| 依赖 | 用于 | 方式 |
|---|---|---|
| Bouncy Castle `bcprov` | 只用 Argon2id | shade、重定位（relocate），并裁剪为只含 Argon2 相关的类 |
| `sqlite-jdbc` | 玩家数据 | jar-in-jar 打包；自带各平台的原生库，体积约 10 MB 以上，可考虑裁剪掉少见平台 |
| Gson | JSON 配置 | `compileOnly`，运行时使用 Minecraft 自带的版本 |
| JUnit 5 | 测试 | 仅测试 |

注意：在 Forge / NeoForge 的模块化类加载环境下，`DriverManager` 可能找不到 SQLite 驱动。要直接实例化 `org.sqlite.JDBC` 来建立连接，不依赖 `DriverManager` 的自动发现。

## 7. 测试计划

- **标准测试向量**：HKDF 用 RFC 5869，X25519 用 RFC 7748，Ed25519 用 RFC 8032
- **编解码**：每种消息都做往返测试（编码再解码应得到原值）；截断、超长、未知 type、错误 magic 都必须抛异常；配合模糊测试
- **端到端握手**：客户端和服务端状态机在内存中直接对接，覆盖以下场景：
  - 新用户：在 SET 提示框中设定密码 → 不受限；点跳过 → 受限
  - 老用户：无密码；有密码且输对；有密码且输错直至锁定
  - 密钥不匹配：设过找回密码 → 重新绑定（之后还要输入登录密码）；没设过 → 断开
  - 版本协商：存在共同版本；没有共同版本
  - 隧道：双方都想开；服务端强制开；双方都不开
- **攻击场景**：
  - 中间人替换临时公钥 → 服务端签名验证失败
  - 服务端身份公钥变化 → 客户端拒绝
  - 篡改 transcript 中的用户名或正版标志 → 失败
  - 重放、乱序 → 失败
  - 密码消息出现在认证通道 → 断开
  - 登录阶段的密码消息在游戏阶段重放 → 失败
- **策略**：限流和锁定的时间窗口（注入可控的 `Clock`）；伪造人数的各种配置
- **存储**：SQLite 实现和内存实现跑同一套契约测试；测试表结构迁移

## 8. 实施顺序

| 步骤 | 内容 | 完成标准 |
|---|---|---|
| 1 | Gradle 多模块骨架（先只建 core 三个模块）、Java 17、JUnit、`.gitignore` | 空项目 `./gradlew test` 通过 |
| 2 | `wire` + `message` | 编解码测试全部通过 |
| 3 | `crypto` | 通过 RFC 测试向量；`AeadChannel` 的重放和乱序测试通过 |
| 4 | `session` 状态机 + 内存版 `AccountService` | 端到端握手和攻击场景测试通过 |
| 5 | `PasswordHasher` + SQLite 存储 | 契约测试和迁移测试通过 |
| 6 | `policy`、`status`、`config` | 策略测试通过；能生成带默认值的 JSON 配置 |
| 7 | `TunnelFrameCodec` + `PasswordChannel` | 隧道和游戏阶段密码通道的测试通过 |

core 层全部完成后，再规划 `common` 层（Mixin 插入点、Netty 适配、GUI）和多版本构建（Stonecutter）。

## 9. 风险

- **Argon2id 被用来消耗服务器资源**：攻击者装了 mod 后反复发送错误密码，迫使服务器做哈希计算。缓解：哈希前先检查限流和锁定；`authExecutor` 设上限；对同一连接限制重试次数
- **SQLite 写入竞争**：开启 WAL 模式，所有写操作集中到单一写线程
- **Gson 版本差异**：1.18.2 自带的 Gson 较旧，只能使用其中稳定的基础 API

## 10. 待确认

- Argon2id 默认参数是否沿用 OWASP 下限（m = 19 MiB、t = 2、p = 1）
- 账号身份的选择：玩家从离线模式切换到正版模式时，以用户名为准还是以 UUID 为准（是否需要迁移已有记录）
