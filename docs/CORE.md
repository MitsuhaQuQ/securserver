# 核心逻辑（core）规划

> 依据：[AGENTS.md](../AGENTS.md)、[PROTOCOL.md](PROTOCOL.md)。
> 本文规划与 Minecraft 无关的核心层：模块划分、包结构、关键接口、线程模型、依赖、测试和实施顺序。

## 1. 原则

- **威胁模型范围**：当前只实现模型 A；模型 B 仅作预留，规则暂未定义，不提供启用配置，也不推定其额外认证策略。现有密码功能仍按既定规则实现。
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
│   ├── X25519                       临时密钥对、DH；u 坐标按 RFC 7748 清最高位并模 p 约简，拒绝全零结果
│   ├── Ed25519                      普通 Ed25519；32 字节原始公钥 / 64 字节签名；拒绝非规范点编码与 S ≥ L
│   ├── HandshakeSignatures          Challenge / ClientProof 的签名与验签（"tsrv v3 server|client" || transcript_0）
│   ├── Hkdf                         RFC 5869，基于 HmacSHA256
│   ├── Transcript                   transcript_0 的计算；先严格解析两条 Hello，online_mode 取自 ServerHello
│   ├── SessionKeys                  按 PROTOCOL.md 4.3 派生六把密钥（auth / tunnel / password × 两个方向）；接管并清零共享秘密
│   ├── Aes256Gcm                    AES-256-GCM 原语，128 位标签
│   ├── Direction / Side             线上方向（S2C / C2S 及其 nonce 标签）与本端角色
│   ├── AeadStream                   一条计数流：一把密钥、一个方向、只加密或只解密；序号、使用上限，失败即永久关闭
│   ├── SecureMessageChannel         认证或密码频道上本端的加密收发（一条 SEAL 流 + 一条 OPEN 流）
│   ├── SessionHandover              认证成功后移交游戏阶段：同一个密码通道实例 + 隧道计数流（仅开隧道时）
│   ├── PresharedKeyHandshake        独立的简易双向 PSK 挑战应答；成功后才接入正式登录状态机
│   ├── OnlineTokenWire              正版 session 后的多设备令牌挑战、签发与确认
│   ├── PskWire                      `trustedserver:psk` 子协议的严格编解码与用户名上下文
│   └── CryptoException              受检异常：DH / 标签 / 上限 / 已关闭，调用方断开连接
├── session/
│   ├── ServerAuthSession            服务端状态机
│   ├── ServerAuthConfig             隧道策略、每种密码的尝试次数、密码框超时、进服提示文本（受限 / 找回提醒 / 改绑）
│   ├── RebindReason                 RECOVERY / ONLINE_MODE_IDENTITY
│   ├── AccountGateway / AccountView 服务端账号访问接口（异步）与账号快照；由 core-server 的 AccountService 实现
│   ├── ServerStep / Outbound        Send(下一条 query) / Done(结果)；query 的频道与 payload
│   ├── AuthOutcome                  Accepted(账号状态、notices、移交对象) / Rejected(原因, 是否已可信)
│   ├── RejectReason                 NO_MOD、VERSION_MISMATCH、PROTOCOL_ERROR、CRYPTO_FAILURE、INVALID_PROOF、KEY_MISMATCH、
│   │                                PASSWORD_ATTEMPTS_EXHAUSTED、ACCOUNT_CONFLICT、TIMEOUT、INTERNAL_ERROR
│   ├── ClientAuthSession            客户端状态机
│   ├── ClientEnvironment            客户端本地能力接口：TOFU 记录、公钥变更确认、玩家密钥、密码弹框
│   └── ClientStep / ClientResult / ClientFailure   Reply / Complete / Fail，及其结果与本地诊断
├── tunnel/
│   ├── TunnelEncoder                把字节流切成 ≤ 65536 字节的明文块逐帧加密；不发空帧
│   └── TunnelDecoder                接受任意分片 / 合并的输入；长度前缀读全即校验（最短编码、17–65552）；
│                                    finish() 检测截断；失败后永久失效。Netty 适配放在 common
└── ProtocolVersion                  当前版本号、支持列表、协商逻辑
```

### 3.2 `core-server`

```
com.mtmrails.trustedserver.server
├── account/
│   ├── AccountService               实现 core 的 AccountGateway；游戏内 /passwd、/recoverypasswd；管理员 reset / trust；
│   │                                登录成功记录；累计错误锁定。Argon2id 在哈希线程池执行，数据库操作在单一写线程执行
│   ├── AccountServiceConfig         线程数、排队上限、锁定阈值与时长、审计保留期
│   ├── PlayPasswordEndpoint         游戏阶段密码通道的服务端一侧：一次一个请求、每分钟 5 次；加密与发送同锁保证顺序；
│                                    非法消息 / 解密失败即踢出
│   └── AdminResult                  管理员命令结果
├── password/
│   ├── PasswordHasher               Argon2id；PHC 格式编码串；参数可配置；按串内参数校验，needsRehash 支持参数升级
│   └── PasswordPolicy               长度 6–128 码点；登录密码与找回密码不能相同
├── store/
│   ├── Account (record)             对应 players 表
│   └── SqliteStore                  players / lockouts / audit_log；user_version 迁移；WAL；直接实例化 org.sqlite.JDBC
├── policy/
│   ├── NetworkKey / Cidr            计数键（IPv4 单个地址、IPv6 /64；IPv4 映射地址按 IPv4）；字面 CIDR 网段，不做 DNS
│   ├── ConnectionGate               握手前的 IP 维度拦截：Ping 额度、登录总量额度、“未验证”额度（仅未通过可信握手的
│   │                                连接在结束时消耗）、按地址族区分的 IP 密码错误锁定、信任网段豁免；仅存内存
│   ├── NetworkPolicyConfig / RateLimit / IpLockout   网络防护参数（默认值对共享 IPv4 出口友好）
│   ├── BanGate                      接口，由 common 层接上原版封禁列表
│   └── OpGuard                      判断 OP 是否需要暂停权限（未设密码或受限）
├── status/
│   ├── StatusConfig                 人数显示模式：REAL / FIXED / RANDOM（范围、重新抽取间隔）
│   └── StatusSanitizer              输出显示人数（不超过最大人数；随机值按间隔重新抽取）；玩家样本由适配层清空
├── config/
│   ├── ServerConfig (record)        全部服务端配置
│   ├── RejectionText                对外拒绝提示：原版封禁翻译键或自定义文本
│   └── ConfigLoader / JsonSection   读写 server.json：缺键用默认值，类型 / 范围错误带完整路径报错，报告未知键
└── ServerIdentity                   服务端 Ed25519 身份密钥：首次生成，损坏拒绝启动、绝不重新生成，提供指纹
```

### 3.3 `core-client`

```
com.mtmrails.trustedserver.client
├── KnownServers                     服务器地址 → 服务端身份公钥（TOFU），文本文件；损坏时报错，绝不静默丢弃信任记录
├── KeyTarget / StoredKey            密钥定位（服务端身份公钥 + 原始用户名）与一把密钥
├── PlayerKeyStore                   每个定位一个文件，文件名为定位的 SHA-256；带校验和，原子写入，POSIX 下仅本人可读写；
│                                    损坏即报错、绝不静默重新生成；list() 供导出界面；importKey() 冲突时不覆盖
├── PlayerKeyBackup                  导出 / 导入备份文件（全部或所选密钥，可选备份密码）；逐条校验密钥对，拒绝重复定位
├── BackupException                  UNSUPPORTED_FORMAT / PASSWORD_REQUIRED / WRONG_PASSWORD_OR_CORRUPTED / CORRUPTED
├── PasswordCommand                  本地拦截 /passwd、/recoverypasswd：Set / Invalid（只在本地提示）/ NotOurs
├── PlayPasswordClient               游戏阶段密码通道的客户端一侧；同时只允许一个请求在途
└── （密码弹框与公钥变更确认属于 core 的 ClientEnvironment，由 common 层用 GUI 实现）
```

密钥备份仅包含指定“服务端身份公钥 + 用户名”下用于 `ClientProof` 的玩家 Ed25519 密钥对及识别该目标所需的元数据，不导出密码、KnownServers 的信任决定或服务端身份私钥。`core-client` 负责解析、完整性校验、原子文件写入、导入预检和冲突检测；Fabric 1.20.1 通过可选 Mod Menu 设置入口提供“导出认证 / 导入认证”、分页勾选、文件选择、冲突确认及明文导出警告。

备份文件格式（版本 1）：

```
header  = "TSKB" | u8 格式版本 = 1 | u8 保护方式
保护方式 0（明文）：header | body | SHA-256(header || body)
保护方式 1（密码）：header | salt(16) | u32 迭代次数 | nonce(12) | AES-256-GCM(key, nonce, body, aad = 此前全部字节)
                   key = PBKDF2-HMAC-SHA256(备份密码, salt, 迭代次数, 256 位)
body    = VarInt 条数（1–4096） | 条数 × (服务端身份公钥 32 | 用户名 string ≤ 256 字节 | 玩家公钥 32 | 私钥种子 32)
```

- 新导出的迭代次数为 600,000（OWASP 对 PBKDF2-HMAC-SHA256 的建议值）；导入只接受 100,000–10,000,000，防止弱参数文件，也防止恶意文件拖死客户端。备份密码留空即明文导出
- 用 PBKDF2 而不是 Argon2id：JDK 自带，客户端不必打包 Bouncy Castle
- 明文文件的 SHA-256 只用于发现意外损坏，不提供防篡改；加密文件由 GCM 认证整个文件。密码错误与加密文件被篡改无法区分，统一报 `WRONG_PASSWORD_OR_CORRUPTED`
- 文件不超过 1 MiB；本机已有不同密钥时 `importKey(…, overwrite = false)` 返回 `CONFLICT` 且不写入，玩家确认后才以 `overwrite = true` 覆盖

## 4. 关键接口草图

### 4.1 简易预共享密钥验证

`PresharedKeyHandshake` 提供基础登录门禁，不属于正式协议 v3。验证成功后由 `auth.validation.ed25519` 决定继续正式 `ServerAuthSession`，或直接进入原版登录。PSK 必须是 32 字节高熵随机值，不把人类口令直接当作 PSK。

1. 服务端生成 32 字节 `server_nonce`。
2. 客户端生成 32 字节 `client_nonce`，双方以 `server_nonce || client_nonce` 为 salt，对 PSK 做 HKDF-Extract。
3. 客户端证明为 `HKDF-Expand(prk, "tsrv psk v1 client" || SHA-256(context), 32)`；服务端证明使用独立的 `server` 标签。
4. 服务端先验证客户端证明，再返回服务端证明；客户端验证后双方才把该简易握手视为通过。比较使用常量时间方法，任一实例只能尝试验证一次。

`context` 按 PROTOCOL.md 1.1 绑定 PSK 子协议版本与登录用户名。`PskWire` 负责 `TSPK` 消息的严格编解码；服务端 `PresharedKeyFile` 和客户端 `PresharedKeys` 分别读取本地配置。PSK 逻辑不派生后续加密密钥。

第一阶段 online-mode 不分发全服 PSK。Mojang session 成功后，`OnlineTokenWire` 先挑战客户端已有的账号令牌；缺少或失效时在原版加密连接内自动签发。`OnlineTokenStore` 按正版 UUID 最多保留 8 个令牌并持久化正版用户名声明，`OnlineTokens` 按服务器身份与 UUID 保存客户端副本。session 无效时只允许以离线 UUID 进入 PSK 回退，已声明的正版同名会被拒绝。

### 4.2 正式认证状态机

```java
// 服务端：一个连接对应一个实例，由 common 层持有
public final class ServerAuthSession {
    ServerAuthSession(String accountId, String username, boolean onlineMode, boolean mojangVerified,
                      ServerAuthConfig config, Ed25519.KeyPairData identity, AccountGateway accounts,
                      SecureRandom random);

    Outbound start();                                                          // 生成 ServerHello
    CompletableFuture<ServerStep> onAnswer(Channel channel, byte[] payloadOrNull);  // null 表示对方“不理解”
    AuthOutcome timeout();                                                     // 认证总超时
}

public sealed interface ServerStep {
    record Send(Outbound next) implements ServerStep {}      // 继续发下一条 query
    record Done(AuthOutcome outcome) implements ServerStep {}  // 结束：放行或断开
}

// 客户端：onlineMode 从服务端 ServerHello 读取，参与 transcript 计算
public final class ClientAuthSession {
    ClientAuthSession(String serverAddress, String username, boolean wantTunnel,
                      ClientEnvironment environment, SecureRandom random);

    CompletableFuture<ClientStep> onQuery(Channel channel, byte[] payload);  // 非本协议频道由 common 层回答“不理解”
    void abort();
}

// 认证 / 密码频道的加密收发（第 3 步）。密码频道在认证成功后经 SessionHandover 移交游戏阶段，序号连续
public final class SecureMessageChannel {
    byte[] seal(Message msg) throws CryptoException;
    Message open(byte[] payload) throws CryptoException, MalformedMessageException;  // 重放、乱序、篡改都抛异常
}
```

- 状态机内部用枚举记录当前状态，收到当前状态不期望的消息类型，一律判为 `PROTOCOL_ERROR`
- 状态机本身不处理超时；超时由 common 层计时，到点后调用 `session.timeout()` 得到 `Rejected(TIMEOUT)`。若此时有回答仍在后台处理，清理推迟到它完成时，且结果一律改判超时
- 每个连接同时只能有一个 `onAnswer` / `onQuery` 在途；账号操作可在其他线程完成，上层须把后续动作切回该连接的事件循环
- 任何协议、密码学或账号存储失败都会废弃本连接的所有通道与会话密钥（PROTOCOL.md 4.3.3）
- 公钥不一致时：本连接通过 Mojang 验证（`mojangVerified`）可按普通新设备流程改绑（`RebindReason.ONLINE_MODE_IDENTITY`），否则须输对找回密码（`RebindReason.RECOVERY`）。`mojangVerified` 与 `onlineMode` 分开传入：正版服务器上 session 无效的连接 `onlineMode = true`、`mojangVerified = false`，按无验证回退
- 密码重设新增内存态 `ResetGrant`：正版 session + 原绑定公钥一致，或新设备找回密码验证正确时建立；绑定账号、旧/新公钥、transcript 与连接，60 秒或一次使用后失效。它不是客户端可保存的令牌
- 找回密码正确后可保留原登录密码继续验证，也可进入 RESET 设置新密码或清除密码。新设备场景使用存储层事务 `recoverAccount(expectedOldPub, newPub, passwordChange)`，以旧公钥为条件原子提交改绑与密码变更；并发更新失败返回 `ACCOUNT_CONFLICT`
- `SqliteStore.recoverAccount` 已实现上述比较并交换事务，并把密码重设后的锁定清理与恢复审计纳入同一提交；账号更新条数为 0 时不写审计，审计写入失败时回滚账号与锁定变更
- 正版快速重设必须在任何自动改绑之前检查原绑定公钥一致；新设备仅有正版 session 时仍须原登录密码，不能先改绑后重设
- `Accepted.reboundBy` 记录本次改绑原因，Finish 下发 `rebindNotice` 提示。恢复审计区分 `online_password_reset`、`recovery_rebind` 与 `recovery_password_reset`
- 账号存在但绑定已被管理员清空时（`AccountView.keyBound()` 为假），按 `RebindReason.KEY_RESET` 处理：已设登录密码则先验证，再用 `claimUnboundKey` 原子绑定，被抢先时按 `ACCOUNT_CONFLICT` 拒绝
- `setLoginPassword` 返回是否符合密码规则；不符合时重新发 SET，连续不符合达到 `maxPasswordAttempts` 次按跳过处理
- v3 的 `PasswordAnswer.Action`、`PasswordRequest.Kind.RESET` 与内存态 `ResetGrant` 已接入服务端和客户端状态机。未授权 RESET、动作与请求种类不匹配、transcript / 新公钥不匹配均拒绝；授权超过 60 秒按超时拒绝
- 账号存储线程池排满（`RejectedExecutionException`，无论同步抛出还是 future 失败）按 `SERVER_BUSY` 拒绝
- 每种密码（登录 / 找回）在一个连接上各有 `maxPasswordAttempts` 次机会；找回成功后转入登录密码时次数重新计算。跨连接的锁定由 `AccountGateway.passwordFailed(…, exhausted)` 的实现负责
- 可信握手完成前，拒绝原因只在内部和审计日志中使用；服务端对外统一使用配置的拒绝文本（模仿原版封禁或自定义）。服务端成功解密 ClientProof 并验证其对当前 transcript 的签名后，才允许提供具体原因；这只是模型 A 的协议验证边界，不代表公钥绑定、密码认证已经通过，更不能提前放行。具体错误的受保护传输格式另行定义。

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

- 哈希线程池默认 4 个线程、排队上限 64，可配置；排满时按 `SERVER_BUSY` 拒绝，避免被大量连接拖垮。数据库操作在单一线程上串行执行
- Argon2id 默认参数取 OWASP 推荐的下限：m = 19 MiB、t = 2、p = 1（可配置）。同时进行的哈希数量受线程池大小限制，内存占用可控
- 游戏阶段的 `/passwd` 同样交给 `authExecutor` 处理，结果切回服务端主线程后再改动玩家的权限状态

## 6. 依赖

| 依赖 | 用于 | 方式 |
|---|---|---|
| Bouncy Castle `bcprov-jdk18on` 1.78.1 | 只用 Argon2id | 完整 jar 约 8.3 MB；打包时 shade、重定位（relocate），并裁剪为只含 Argon2 相关的类 |
| `sqlite-jdbc` 3.46.1.0 | 玩家数据 | jar-in-jar 打包；自带各平台的原生库，约 14 MB，暂不裁剪；无其他传递依赖 |
| Gson | JSON 配置 | `compileOnly`，运行时使用 Minecraft 自带的版本 |
| JUnit 5 | 测试 | 仅测试 |

注意：在 Forge / NeoForge 的模块化类加载环境下，`DriverManager` 可能找不到 SQLite 驱动。要直接实例化 `org.sqlite.JDBC` 来建立连接，不依赖 `DriverManager` 的自动发现。

## 7. 测试计划

- **标准测试向量**：HKDF 用 RFC 5869，X25519 用 RFC 7748，Ed25519 用 RFC 8032
- **加密边界**：冻结完整 Hello → transcript → 六把密钥 → 首条密文的已知答案向量；测试方向/用途隔离、header 篡改、无效标签、空消息、4075 字节消息体边界、使用上限及失败后不可复用。隧道另测长度 AAD、分片/合并、65536 字节帧上限和截断；密码通道测试跨阶段计数连续。
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
- **客户端密钥备份**：导出后导入可恢复同一公钥；目标服务端身份或用户名不匹配、私钥与公钥不匹配、截断和篡改文件均拒绝；已有不同密钥只报告冲突，不由 core 静默覆盖
- **策略**：限流和锁定的时间窗口（注入可控的 `Clock`）；伪造人数的各种配置
- **存储**：SQLite 实现和内存实现跑同一套契约测试；测试表结构迁移

## 8. 实施顺序

| 步骤 | 内容 | 完成标准 |
|---|---|---|
| 1 | Gradle 多模块骨架（先只建 core 三个模块）、Java 17、JUnit、`.gitignore` | 空项目 `./gradlew test` 通过 |
| 2 | `wire` + `message` | 编解码测试全部通过 |
| 3 | `crypto` | 通过 RFC 测试向量；冻结的已知答案向量；`AeadStream` / `SecureMessageChannel` 的隔离、篡改、重放、乱序、长度边界与使用上限测试通过 |
| 4 | `session` 状态机 + 测试用内存账号存储 | 端到端握手和攻击场景测试通过 |
| 4b | `core-client`：`PlayerKeyStore` + `PlayerKeyBackup` | 存储、导出 / 导入、篡改、截断、冲突与迁移测试通过 |
| 5 | `PasswordHasher` + `PasswordPolicy` + `SqliteStore` + `AccountService` | 哈希向量、存储与迁移、管理员命令、锁定，以及用真实存储跑通完整握手的测试通过 |
| 6 | `policy`、`status`、`config`、`ServerIdentity` | 限流 / 锁定（含共享出口场景）、人数显示、配置读写与报错、身份密钥测试通过 |
| 7 | `TunnelEncoder` / `TunnelDecoder` + 游戏阶段密码通道（`PlayPasswordEndpoint`、`PlayPasswordClient`、`PasswordCommand`） | 隧道帧（格式、长度 AAD、分片 / 合并、65536 字节边界、截断、篡改、重放）与游戏内 /passwd 端到端测试通过 |

core 层全部完成后，再规划 `common` 层（Mixin 插入点、Netty 适配、GUI）和多版本构建（Stonecutter）。

## 9. 风险

- **Argon2id 被用来消耗服务器资源**：攻击者装了 mod 后反复发送错误密码，迫使服务器做哈希计算。缓解：哈希前先检查限流和锁定；`authExecutor` 设上限；对同一连接限制重试次数
- **SQLite 写入竞争**：开启 WAL 模式，所有写操作集中到单一写线程
- **sqlite-jdbc 的 NULL 处理**：`getObject(列, Long.class)` 遇到 NULL 会抛异常，可空整数列一律用 `getLong` + `wasNull()` 读取
- **Gson 版本差异**：1.18.2 自带的 Gson 较旧，只能使用其中稳定的基础 API

## 10. 待确认

- （第 5 步的待确认项已按默认值确定，见 AGENTS.md 第 18 条）
