# TrustedServer 认证协议设计

> 协议版本：`3`（草案）
> 需求与决策见 [AGENTS.md](../AGENTS.md)。本文只描述线上协议、密码学与状态机。

当前协议按威胁模型 A 定义。威胁模型 B 仅作预留，规则暂未定义。登录密码、找回密码及 OP 暂停规则见第 6 节和 AGENTS.md。

## 1. 总览

```
客户端                                    服务端
  | -- Handshake / Status Ping ------------> |  限流；Ping 响应脱敏
  | -- Hello(username) --------------------> |  IP / 名称封禁检查（拦截）
  |                                          |  [正版] 原版加密 + Mojang 验证（session 无效时回退为无验证，继续本协议）
  | <-- Query#1 ServerHello ---------------- |  协商版本 + 临时密钥交换
  | --> ClientHello -----------------------> |
  | <-- Query#2 Challenge (加密) ----------- |  服务端身份签名
  | --> ClientProof (加密) ----------------> |  玩家密钥签名
  | <-- Query#3 PasswordRequest (可选) ----- |  登录密码 / 找回密码（密码通道）
  | --> PasswordAnswer (加密) -------------> |
  | <-- Query#N Finish (加密) -------------- |  结果；是否开启隧道
  | --> FinishAck -------------------------> |  [隧道] 双方切换为隧道加密
  | <-- 原版 SetCompression / LoginSuccess - |  之后才进入加载器握手与游戏
```

- 全部在**登录阶段**完成，使用原版的 login query：服务端发 `ClientboundCustomQueryPacket`，客户端回 `ServerboundCustomQueryPacket`（1.20.2+ 为 `ServerboundCustomQueryAnswerPacket`）
- 频道 ID：
  - `trustedserver:auth`：握手与身份认证
  - `trustedserver:password`：**密码专用通道**，登录阶段和游戏阶段所有携带密码的消息都只走这里，使用独立派生的密钥和独立序号（见 4.3、第 6 节）
- 由服务端驱动，每一轮是一对 query / answer，用原版的 transaction id 对应
- 认证完成前，服务端**不发送** `LoginSuccess`，连接不会进入配置阶段或游戏阶段，满足“0 权限”
- 本协议的 query 必须早于加载器自身的登录握手（Forge 1.18.2–1.19.4 的 `fml:loginwrapper`），没装 mod 的连接拿不到服务端的 mod 列表

### 1.1 第一阶段 PSK 登录门禁

基础门禁在 `trustedserver:psk` 频道执行独立的 PSK 子协议 v1。PSK 只证明客户端持有共享密钥，原版封禁与登录检查仍然有效。PSK 通过后，若 `auth.validation.ed25519=true`，继续发送本章正式协议的 ServerHello；关闭时才直接继续原版及加载器登录流程。

该门禁用于 offline-mode，以及 online-mode 的 invalid-session / 会话服务不可用回退。offline-mode 没有 Mojang session 身份保证，因此基础条件是“持有服务器 PSK 且证明绑定本次登录用户名”；同一 PSK 的多个持有者仍可能尝试其他尚未声明为正版的用户名，默认开启的 Ed25519 附加层通过首次绑定与后续签名验证提供个人身份约束。Mojang session 正确的连接改走第 1.2 节账号令牌流程。

```
服务端                                      客户端
  | <-- Challenge(type=1, server_nonce) ------ |
  | --> ClientResponse(type=2, client_nonce, proof) |
  | <-- ServerProof(type=3, proof) ------------ |
  | --> Ack(type=4) --------------------------- |
  | <-- 原版 / 加载器后续登录流程 ------------- |
```

全部消息以 `TSPK` 四字节 magic 开头，随后是一个 type：

| type | 方向 | body |
|---|---|---|
| 1 | S→C | `server_nonce : 32 bytes` |
| 2 | C→S | `client_nonce : 32 bytes`、`client_proof : 32 bytes` |
| 3 | S→C | `server_proof : 32 bytes` |
| 4 | C→S | 空 |
| 5 | C→S | 空；本地缺少该服务器 PSK，请求一次人工输入等待 |

客户端收到 type 1 后若本地没有对应服务器地址的 PSK，先返回 type 5 并弹出输入框。服务端只接受一次 type 5，重新生成 challenge，并仅把该连接的等待时间延长为密码输入超时（默认 60 秒）；第二个 type 1 的响应 future 等待玩家完成输入。输入必须是解码后正好 32 字节的单行 Base64，成功后原子写入 `psk.txt` 并继续本次登录。取消、超时、重复请求或格式错误均拒绝，不把输入内容发送到日志或断开文本。

证明算法：

```
context      = ASCII("trustedserver:psk:v1") || 00 || u16be(username_utf8_length) || UTF-8(username)
prk          = HKDF-Extract(server_nonce || client_nonce, psk)
client_proof = HKDF-Expand(prk, ASCII("tsrv psk v1 client") || SHA-256(context), 32)
server_proof = HKDF-Expand(prk, ASCII("tsrv psk v1 server") || SHA-256(context), 32)
```

- 用户名取登录 Hello 的原始值，严格 UTF-8；长度不得超过 65535 字节。PSK 固定为 32 字节高熵随机值，不把人类口令直接当作 PSK。服务端文件和客户端输入均拒绝明显弱值（低多样性、重复 / 连续模式、字符类别不足、常见密码与简单 Leet 变形）；该启发式检查不能证明真实熵，默认应使用服务端自动生成值
- 双方随机数每次连接重新生成。服务端验证客户端证明后才发送服务端证明；客户端验证后才回答 Ack。证明使用常量时间比较，每个状态实例只允许一次验证
- 客户端回答“不理解”、取消输入、任一证明错误、消息长度 / magic / type 错误或认证总超时，服务端均按未可信连接使用统一拒绝文本断开。PSK、证明和具体失败原因不得写日志
- PSK 子协议有独立版本与频道，不改变后续正式认证协议版本号；旧客户端会因不理解 query 被拒绝
- PSK Ack 之前服务端不得发送任何真实加载器握手、频道注册或 mod 列表。公开状态若由加载器扩展出 mod 元数据，可返回与真实列表无关、且不参与兼容性校验的诱饵项；真实列表只在 Ack 后发送
- 已配置 PSK 与正版令牌使用独立的短超时（默认 10 秒）；只有缺少 PSK 的 mod 客户端返回一次 type 5 后，该连接才改用输入超时（默认 60 秒）。全服同时处于门禁阶段的连接数默认不超过 256，type 5 不增加额度

### 拦截未装 mod 的连接

原版客户端收到不认识的 query 时会回答“不理解”（payload 为空）；不实现 login query 的机器人会一直不回应。两种情况都直接按拒绝处理：

- 空回答：立即断开
- 无回答：认证超时后断开

断开提示使用配置的拒绝文本（默认模仿原版封禁提示）。

### 1.2 online-mode 自动令牌门禁（第一阶段）

服务端仅在 Mojang session 已返回正版 UUID 后进入本流程；令牌通过此时已经建立的原版加密连接发送。不得仅凭客户端自报用户名签发令牌，也不得把全服 PSK 下发给正版客户端。

令牌门禁完成后与 PSK 路径相同：启用 `auth.validation.ed25519` 时继续正式认证。此时 `mojangVerified=true`，玩家设备公钥变化可按第 16 条规则改绑；关闭时直接进入原版 / 加载器后续登录。

```
服务端                                              客户端
  | -- Challenge(server_identity, UUID, name, nonce) --> |
  | <-- ClientProof(has_token, proof?) ----------------- |
  |    [已有令牌且证明正确：直接放行]                    |
  | -- Issue(token) [缺失或旧令牌时] ------------------> |
  | <-- Ack(proof) ------------------------------------- |
```

频道为 `trustedserver:online_token`，消息 magic 为 `TSTK`：

| type | 方向 | body |
|---|---|---|
| 1 | S→C | 服务端身份公钥 32 字节、正版 UUID 16 字节、用户名、随机 nonce 32 字节 |
| 2 | C→S | `has_token`；为真时附 32 字节证明 |
| 3 | S→C | 新令牌 32 字节 |
| 4 | C→S | 32 字节签发确认证明 |

令牌为 32 字节 `SecureRandom` 值。证明为：

```
context = server_identity || uuid || varstring(username) || nonce
proof   = HKDF-Expand(token, ASCII("tsrv online token proof v1") || context, 32)
ack     = HKDF-Expand(token, ASCII("tsrv online token ack v1")   || context, 32)
```

- 客户端按“服务器地址 + 服务端身份公钥 + 正版 UUID + 用户名”保存令牌；文件仅本人可读写
- 服务端按正版 UUID 保存最多 8 个令牌，允许多台电脑使用。新电脑令牌缺失时凭正确 Mojang session 自动签发，不要求人工重置
- 错误或过期令牌不会在正确 session 下锁死玩家，而是自动签发新令牌；没有正确 session 的连接不能据此要求签发
- 首次签发 Ack 成功后，用户名被永久声明给该正版 UUID。离线 PSK 回退使用离线 UUID，且不得使用已声明的正版名字；恢复离线名字只能由控制台显式清除声明
- session 无效或会话服务不可用时覆盖原版立即断开，切换到第 1.1 节 PSK 流程。此回退绝不继承正版 UUID、令牌或权限

### 拒绝提示的可信边界

- 服务端成功解密 ClientProof 并验证玩家公钥对当前 transcript 的签名前，所有拒绝统一使用配置文本，不发送具体失败原因；包括版本不兼容、封禁、限流、超时和无效证明。
- 上述验证通过后，视为模型 A 的可信协议握手完成，才允许提供密钥不匹配、找回方式等具体提示。这只证明对方完成协议并持有本次提交公钥对应的私钥，不证明其拥有既有账号；绑定核对、密码验证和 FinishAck 仍须按流程完成，之前不得放行。
- 客户端自身检测到的服务端身份变化、签名错误或版本不兼容，可以在本地显示诊断；这不属于服务端向未可信连接发送详细拒绝原因。
- 可信握手后的具体错误应通过受保护的通道发送；当前尚未定义其消息格式，不能借用明文断开消息传输这些详细原因。

## 2. 密码学原语

只使用 Java 17 自带的实现，Argon2id 除外。

| 用途 | 算法 | 来源 |
|---|---|---|
| 临时密钥交换 | X25519 | JDK `XDH` |
| 身份签名（服务端、玩家） | Ed25519 | JDK `EdDSA` |
| 对称加密 | AES-256-GCM | JDK |
| 密钥派生 | HKDF-SHA256 | 基于 JDK `HmacSHA256` 自行实现（RFC 5869，约 30 行） |
| 摘要 | SHA-256 | JDK |
| 密码哈希 | Argon2id | Bouncy Castle（shade 并裁剪，只打包服务端需要的类） |
| 随机数 | `SecureRandom` | JDK |

### 2.1 密码学编码与实现约束

- X25519 公钥在线上为 RFC 7748 定义的 32 字节小端 u 坐标，不携带 X.509/DER 包装。输入按 RFC 7748 处理最高位及非规范坐标；运算结果全零或提供者拒绝该密钥时立即终止，不继续派生密钥。
- Ed25519 使用 RFC 8032 的普通 Ed25519（不是 Ed25519ph/Ed25519ctx）：公钥为 32 字节压缩点，签名为 64 字节 `R || S`，不携带 DER 包装。非法点编码、越界的 S、无效签名必须拒绝；公钥解码与验签使用 JDK 实现，不自行实现椭圆曲线运算。
- 以下公式中的字符串标签均为精确 ASCII 字节，无引号、无末尾 NUL、无长度前缀；`||` 表示直接拼接。用户名采用第 4.3 节的独立编码规则。
- 每次连接双方各自新生成 X25519 临时密钥对和 32 字节随机 nonce，均使用 `SecureRandom`；禁止缓存复用临时密钥或会话密钥。长期 Ed25519 身份密钥不能用于 DH。
- 标准依据：[RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)、[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)、[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)、[NIST SP 800-38D](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)。帧大小、标签取值及使用上限是本项目的协议选择。

## 3. 身份与密钥

### 服务端身份密钥

- Ed25519 长期密钥对，首次启动时生成，保存在 `config/trustedserver/server_identity.key`
- 客户端按 **TOFU**（首次信任，类似 SSH 的 `known_hosts`）记住服务端公钥，作用是在离线模式下**防中间人**
- 同一服务器地址的公钥发生变化时，客户端弹出明确警告并默认拒绝连接，玩家确认后才更新

### 玩家密钥

- Ed25519 密钥对，按 **（服务端身份公钥, 用户名）** 生成，每个服务器一把，避免跨服务器追踪
- 以服务端身份公钥而不是服务器地址为索引，服务器换域名或 IP 后仍然有效
- 客户端存放在 `config/trustedserver/keys/`。按决策不考虑物理接触，私钥明文保存，文件权限设为仅本用户可读
- 客户端允许按“服务端身份公钥 + 用户名”导出、导入这一玩家认证密钥对，用于设备迁移或备份。该操作完全发生在本地，不产生协议消息，也不改变服务端已有公钥绑定；导入正确的旧密钥后可继续匹配原绑定，导入其他密钥仍按密钥不匹配流程处理
- 备份不包含登录密码、找回密码、服务端身份私钥或 TOFU 信任决定。导入必须验证公私钥匹配和目标元数据；本地已有不同密钥时不得静默覆盖
- 服务端记录方式（TOFU）：
  - 正版模式按 **UUID** 记录（用户名已由 Mojang 验证）
  - 正版服务器上 session 无效而回退为无验证的连接使用哪个账号 ID，见 AGENTS.md“待确认”
  - 离线模式按**小写用户名**记录

## 4. 消息格式

所有 payload 的通用开头：

```
magic        : 4 bytes  "TSRV"
type         : u8
body         : 按 type 定义
```

编码规则（解码方一律严格校验，任何不合规都按协议错误断开）：

- 整数为大端序；`bool` 只能是 0 或 1
- `VarInt` 与 Minecraft 的编码相同，但只接受非负的 31 位值和最短编码，保证同一个值只有一种编码
- `varbytes` 指 VarInt 长度前缀加字节串，`string` 指 VarInt 长度前缀加严格 UTF-8（非法序列、不成对代理字符都拒绝）
- 单条 payload（含 magic、type、密文和认证标签）最多 4096 字节
- 每种 type 只允许出现在它所属的频道；消息体必须恰好读完，有多余字节即拒绝
- 只有 ServerHello、ClientHello 是明文；其余类型以明文形式出现即拒绝

### 4.1 ServerHello（S→C，明文，type=0x01）

```
versions       : varbytes   服务端支持的协议版本列表（每个 u16，取值 1–65535，最多 16 个）
server_eph_pub : 32 bytes   X25519 临时公钥
server_nonce   : 32 bytes
features       : u32 bitmask
                  bit0 TUNNEL_AVAILABLE  服务端允许隧道模式
                  bit1 TUNNEL_REQUIRED   服务端强制隧道模式（必须同时置位 bit0）
                  其余位必须为 0
online_mode    : bool       服务端主动发送其实际 online-mode（0 = 离线，1 = 正版）
```

客户端从 ServerHello 读取 `online_mode`，不自行猜测；服务端使用实际配置值，双方将同一值作为 transcript 中的 `online_mode_flag`（单字节 0 或 1）。该声明在 Challenge 的服务端身份签名验证通过后才被认证；它本身不是 Mojang 身份验证的证明。

### 4.2 ClientHello（C→S，明文，type=0x02）

```
version        : u16        从 versions 中选出的最高共同版本
client_eph_pub : 32 bytes
client_nonce   : 32 bytes
want_tunnel    : bool       客户端配置希望开启隧道
```

没有共同版本时，客户端回答 `version = 0`，服务端记录内部原因“版本不兼容”，对外使用统一拒绝文本。客户端可根据收到的版本列表和本地支持列表，在本地提示版本不兼容并显示双方版本号。

### 4.3 会话密钥派生

```
transcript_0 = SHA-256( server_hello_payload || client_hello_payload || username_field || online_mode_flag )
shared       = X25519(eph_priv, peer_eph_pub)        全零结果视为失败并断开
prk          = HKDF-Extract(salt = server_nonce || client_nonce, ikm = shared)
k_s2c        = HKDF-Expand(prk, "tsrv v3 auth s2c" || transcript_0, 32)
k_c2s        = HKDF-Expand(prk, "tsrv v3 auth c2s" || transcript_0, 32)
k_tun_s2c    = HKDF-Expand(prk, "tsrv v3 tunnel s2c" || transcript_0, 32)
k_tun_c2s    = HKDF-Expand(prk, "tsrv v3 tunnel c2s" || transcript_0, 32)
k_pw_s2c     = HKDF-Expand(prk, "tsrv v3 password s2c" || transcript_0, 32)
k_pw_c2s     = HKDF-Expand(prk, "tsrv v3 password c2s" || transcript_0, 32)
```

#### 4.3.1 transcript 与派生输入

- `server_hello_payload` / `client_hello_payload` 是实际发送或收到并已严格校验的完整 payload，包含 `TSRV | type | body`；不包含 Minecraft 包长度、频道名或 transaction id。不得用另一种序列化形式替代收到的字节。
- `username_field = VarInt(UTF-8 字节数) || UTF-8(username)`，采用第 4 节的最短 VarInt 与严格 UTF-8。用户名取本次原版登录 Hello 中的原始字符串，保留大小写、不做 Unicode 归一化；服务端保存这一值供握手使用。它与离线账号查询所用的小写索引是两回事。
- `online_mode_flag` 为 ServerHello 中 `online_mode` 的单字节编码：`00` 或 `01`；服务端必须发送实际配置值。该字段虽已包含在 Hello 中，仍按公式再拼接一次，以保留明确的上下文绑定。
- `transcript_0` 是 32 字节 SHA-256 原始摘要，不是十六进制字符串。Hello 的版本、模式、功能位、公钥及 nonce 因此都受签名保护。
- salt 为服务端 nonce 在前、客户端 nonce 在后的 64 字节；共享秘密使用 X25519 返回的原始 32 字节。HKDF 按 RFC 5869 的 Extract 后 Expand 执行，六个输出各 32 字节，禁止直接把 DH 输出作为 AES 密钥。
- 签名输入为第 4.4 / 4.5 节的 ASCII 标签加原始摘要；直接交给普通 Ed25519 签名，不额外做预哈希。

#### 4.3.2 AEAD 封装

认证与密码通道统一采用以下格式：

```
header    = ASCII("TSRV") || u8(type)               // 5 字节
nonce     = direction_tag || u64be(sequence)       // 12 字节，仅本地构造
ciphertext_and_tag = AES-256-GCM(key, nonce, body, aad = header)
payload   = header || ciphertext_and_tag
```

- JDK 算法为 `AES/GCM/NoPadding`，密钥 256 位，认证标签固定为 128 位（16 字节），输出顺序为密文在前、标签在后。不使用填充。
- 方向标签固定为：S→C = `53 32 43 00`（`S2C` 后接零字节），C→S = `43 32 53 00`（`C2S` 后接零字节）。发送端与接收端按同一个线上方向选标签，不按本地“发送/接收”命名。
- nonce 与序号不在线上传输。接收端只使用本地预期序号解密，不尝试前后序号或其他密钥。重放、丢帧后的错位、乱序均导致认证失败并断开。
- 每个用途、每个方向独立维护序号：auth / password / tunnel × S→C / C→S，共六条计数流，均从 0 开始。不同用途绝不共享密钥；相同方向标签可在不同密钥下使用。
- 单条完整 payload 最多 4096 字节，因此加密消息体最多 `4096 - 5 - 16 = 4075` 字节。即使各字段分别符合上限，聚合后超限也必须拒绝；Finish 的 notices 同样受此总上限约束。
- 解密前先检查总长度、magic、频道与 type；解密成功后才解码消息体并执行状态转换。GCM 标签验证完成前，不得把任何明文交给密码校验、数据库或游戏逻辑。

#### 4.3.3 序号、使用上限与失败处理

- 同一条计数流必须串行处理。发送方成功 seal 后消耗一个序号，接收方成功 open 后消耗一个序号；数据写出失败、密码学异常、无效消息体或状态不符都终止连接，不回退序号重试。
- 密码通道在登录到游戏阶段交接时移交同一个通道状态，不得仅复制密钥并重置计数。启用隧道也不影响密码通道，其消息继续独立加密。
- 每把密钥最多保护 `2^24` 条记录、累计最多 `2^36` 字节明文（64 GiB），任一上限即将被超过时，在处理该记录前断开。双端分别记录并检查相同的计数；空消息也计一条记录。这里的记录在 auth/password 中是一条消息，在 tunnel 中是一帧。
- 序号编码为无符号 u64 大端，但上述记录上限先于 u64 耗尽触发。禁止溢出回绕；不支持会话内重新协商密钥，重新连接时生成全新临时密钥和 nonce。
- 标签验证失败后永久废弃本次连接的所有通道，不允许继续试解密，不降级到明文。对外仅使用统一拒绝文本或直接关闭连接；即使此前握手可信，也不通过已失去同步的加密通道发送详细错误。
- DH 共享秘密和 HKDF 中间值在派生后尽快释放并尽力清零可变缓冲区；会话结束释放会话密钥及临时私钥。不得写入日志或持久化；Java/JCA 对象不保证所有内部副本可立即擦除。

### 4.4 Challenge（S→C，加密，type=0x03）

```
server_id_pub  : 32 bytes   服务端 Ed25519 身份公钥
server_sig     : 64 bytes   Sign(server_id, "tsrv v3 server" || transcript_0)
```

客户端先验证签名，再用 TOFU 记录核对 `server_id_pub`；首次记录只能在签名通过后写入，已有记录变化必须经过明确确认。通过服务端身份检查后，才以它为索引找到（或新生成）玩家密钥并发送 ClientProof；此前不显示密码输入请求、不发送任何密码。

### 4.5 ClientProof（C→S，加密，type=0x04）

```
player_pub     : 32 bytes
player_sig     : 64 bytes   Sign(player_key, "tsrv v3 client" || transcript_0)
```

### 4.6 服务端判定

| 状态 | 处理 |
|---|---|
| 该身份无绑定记录（新用户名） | 绑定 `player_pub`（TOFU），标记为**受限**（见 6.1），发 PasswordRequest(SET) |
| 公钥一致，受限且未设登录密码 | 发 PasswordRequest(SET) |
| 公钥一致，未受限且未设登录密码 | 进入 Finish |
| 公钥一致，已设登录密码 | 发 PasswordRequest(LOGIN)；若本连接同时通过 Mojang session 验证，可请求快速重设 |
| 账号存在但设备绑定已被管理员清空（`reset key`） | 视同身份已确认：已设登录密码则先发 PasswordRequest(LOGIN)，通过后才绑定；否则立即绑定，按“公钥一致”的规则继续。绑定为原子操作，并发连接抢先时按冲突拒绝 |
| 公钥不一致，本连接已通过 Mojang session 验证 | 视为连接可信（新设备）：已设登录密码则发 PasswordRequest(LOGIN)，通过后才改绑；否则立即改绑，按“公钥一致”的规则继续。Finish 的 `notices` 下发改绑提示 |
| 公钥不一致，未经 Mojang 验证，已设找回密码 | 发 PasswordRequest(RECOVERY)；验证成功后可保留原登录密码，或请求重设 / 清除登录密码 |
| 公钥不一致，未经 Mojang 验证，未设找回密码 | 断开，并明确提示“密钥不匹配，请联系管理员重置” |

“未经 Mojang 验证”包括离线模式，以及正版服务器上 session 无效（含 Mojang 会话服务器不可用）而回退为无验证的连接。

**Mojang 验证的作用范围**：它保证本连接的正版身份可信，可替代“设备密钥是否匹配”这一项来完成普通的新设备改绑；登录密码、错误次数与锁定仍然保留。只有当 Mojang session 与服务端原绑定设备密钥在同一连接上同时验证正确时，才额外允许快速重设登录密码。不得先改绑再授予该资格。ServerHello 中的 `online_mode` 仍是服务器配置，不表示某个连接是否通过了 Mojang 验证；后者只在服务端本地使用，不上线。

### 4.7 PasswordRequest（S→C，密码通道，type=0x05）

以频道 `trustedserver:password` 的 login query 发送，用 `k_pw_s2c` 加密。

```
kind           : u8   1 = LOGIN, 2 = RECOVERY, 3 = SET, 4 = RESET
attempts_left  : u8   SET / RESET 时无意义，固定为 0
timeout_sec    : u16
```

客户端弹出输入框，标题和说明按 `kind` 区分：

- LOGIN：输入登录密码
- RECOVERY：输入找回密码，并可选择“保留原登录密码”或“同时重设登录密码”；明确提示成功后当前设备密钥将取代旧绑定
- SET：设定登录密码，包含“密码”和“确认密码”两个输入框，两次输入一致才允许提交（在客户端本地校验）。提示“进入游戏前设定密码可免受新用户限制”，并提供“跳过”按钮
- RESET：设置新登录密码，或明确选择清除密码。客户端提示本次授权来源（正版 session + 原绑定密钥，或找回密码），但不显示任何密钥材料

### 4.8 PasswordAnswer（C→S，密码通道，type=0x06）

用 `k_pw_c2s` 加密。服务端只接受对密码通道 query 的回答里出现此类型，出现在认证通道里即断开。

```
action         : u8       0 = SUBMIT, 1 = SKIP, 2 = REQUEST_RESET, 3 = CLEAR
password       : string   最多 128 个 Unicode 码点（UTF-8 最多 512 字节）
```

- 密码只在已认证的加密通道里传输，服务端用 Argon2id 校验，客户端不保存密码
- 不采用 OPAQUE 一类的 PAKE（口令认证密钥交换）：服务端身份已固定，再加上 AEAD，足以防窃听和中间人，复杂度低很多
- 判定流程：
  - LOGIN 正确：进入 Finish
  - LOGIN + REQUEST_RESET：本次 Mojang session 已验证且 `player_pub` 与原绑定公钥一致时，直接发 PasswordRequest(RESET)。其他连接须先验证找回密码，再发 RESET。找回密码功能关闭或账号未设置找回密码时拒绝
  - RECOVERY 正确：
    - SUBMIT 且已设登录密码：发 PasswordRequest(LOGIN)，登录密码通过后以比较并交换方式改绑
    - SUBMIT 且未设登录密码：以比较并交换方式改绑，然后进入 Finish
    - REQUEST_RESET：建立仅属于当前连接的一次性恢复授权并发 PasswordRequest(RESET)，不立即改绑
    - 找回成功后转入登录密码时，登录密码的尝试次数重新计算
  - RESET + SUBMIT：校验新密码规则及其与找回密码不同，然后提交重设。新设备找回场景把新密码哈希和新设备公钥放在同一 SQLite 事务中写入；正版快速重设只更新密码哈希
  - RESET + CLEAR：经客户端二次确认后清除登录密码。新设备找回场景把清除密码和设备改绑放在同一事务中；账号恢复为仅 Ed25519 密钥验证，`restricted` 的实际执行仍由 `newPlayerRestriction` 决定
  - SET + SUBMIT：符合密码规则则用 Argon2id 保存为登录密码，**解除受限**，进入 Finish；不符合则重新发 PasswordRequest(SET)，连续不符合的次数达到登录密码尝试次数时按跳过处理（保持受限）
  - SET + SKIP：保持受限，进入 Finish
  - LOGIN / RECOVERY 错误：失败计数加 1，`attempts_left > 0` 时重发请求，否则锁定并断开

`action` 字段与 RESET kind 自协议 v3 起启用；旧客户端不得把带 action 的消息按旧 PasswordAnswer 解码。SQLite 原子恢复事务、状态机授权与 Fabric 触发界面均已接入。

动作与字段组合必须严格匹配：LOGIN 的 REQUEST_RESET 不携带密码；RECOVERY 的 REQUEST_RESET 必须携带本次要验证的找回密码；SET 只接受 SUBMIT / SKIP；RESET 只接受 SUBMIT / CLEAR。任何其他组合按协议错误拒绝，不能猜测用户意图。

### 4.8.1 一次性密码重设授权

- 授权只保存在当前 `ServerAuthSession` 内存中，不作为可复制令牌发送或展示给客户端
- 授权绑定账号标识、请求开始时的旧公钥、本次新公钥、`transcript_0` 和当前连接；最长 60 秒，断线、超时、使用一次或任何协议错误后立即销毁
- 正版快速重设的前提是 `mojangVerified=true` 且新旧公钥一致；导入备份恢复出的同一密钥符合条件
- offline / invalid-session 新设备恢复的前提是找回密码正确；最终事务使用旧公钥作为更新条件，条件不匹配时返回 `ACCOUNT_CONFLICT`
- 找回密码错误仍计入找回密码尝试、账号锁定和 IP 锁定。重设成功清零登录密码错误累计，但保留全部恢复审计
- 客户端永远只显示“本机认证密钥已验证”等用户语言，不要求玩家输入、复制或查看 Ed25519 私钥

### 4.9 Finish（S→C，加密，type=0x07）

```
result         : u8   固定为 0 = OK（失败直接断开，不发 Finish）
tunnel         : bool 是否开启隧道（TUNNEL_REQUIRED，或双方都希望开启）
notice_count   : VarInt     最多 8 条
notices        : string × notice_count   客户端进服后要显示的提示（如“尚未设置找回密码”），每条最多 1024 字节
```

### 4.10 FinishAck（C→S，加密，type=0x08）

空 body。服务端收到后：

- 若 `tunnel = true`，按第 5 节切换为隧道加密
- 继续原版流程（SetCompression → 加载器握手 → LoginSuccess）

## 5. 高安全模式：隧道

- 在 Netty 管线的最外层（原版 `encrypt` / `decrypt` 处理器的位置）插入隧道编解码器：
  - 离线模式：新增这两个处理器
  - 正版模式：替换掉原版的 AES-CFB8 处理器
- 隧道传输 Minecraft 编码后的原始字节流，不以 Minecraft 包为帧边界；接收端按顺序拼接解密结果。单个 Minecraft 包可以拆为多帧。
- 单帧明文长度为 1–65536 字节；不发送空帧。令 `L = 明文长度 + 16`（密文与 GCM 标签总长度），帧格式与 AAD 固定为：

  ```
  length_bytes = 最短 VarInt(L)
  aad          = ASCII("tsrv v3 tunnel frame") || length_bytes
  frame        = length_bytes || AES-256-GCM(k_tun_dir, nonce, plaintext, aad)
  ```

- `L` 必须在 17–65552 之间，长度前缀最多 3 字节；分配帧缓冲前即校验范围和最短编码。未收齐一帧时等待后续字节；EOF 时存在残帧视为截断。长度前缀参与认证，但只有收齐并验证标签后才能确认其完整性。
- nonce、标签长度、序号及每密钥使用上限遵循第 4.3 节。隧道第一帧使用序号 0；隧道帧不受认证 payload 的 4096 字节限制。
- 切换时机：
  - FinishAck 仍经旧传输方式完整编码；客户端在同一连接事件循环中将其排入旧编码链路后，原子切换后续出站字节及入站解码器。切换完成前禁止后续应用数据写出。
  - 服务端完整解码并验证 FinishAck 后、发送任何后续包之前，原子切换双向编解码器。隧道开启后的首个字节必须属于隧道帧。
  - 适配层必须处理 TCP 分片、合并读取及旧解码器残留缓冲，按协议边界移交尚未消费的字节；不得假定一次网络读取恰好对应一个包。若不能保证边界，关闭连接，不尝试猜测新旧格式。
- 兼容性：隧道会改变线上字节格式，所以只在双方都装了本 mod 时启用；由于不支持代理，不存在中间层解析的问题

## 6. 游戏阶段的安全通道（`/passwd`、`/recoverypasswd`）

在离线模式且未开隧道时，原版连接是明文，直接把聊天命令发出去会暴露密码。因此：

- 客户端 mod 在本地拦截 `/passwd` 和 `/recoverypasswd`，**不作为聊天命令发出**
- 改为通过自定义游戏数据包（play custom payload）在**密码通道** `trustedserver:password` 上发送，用 `k_pw_*` 加密，序号接续登录阶段
- 消息类型（均加密）：

  | type | 方向 | 消息 | 字段 |
  |---|---|---|---|
  | 0x09 | C→S | SetPassword | `password : string`，非空，限制同 4.8 |
  | 0x0A | C→S | SetRecoveryPassword | `password : string`，非空，限制同 4.8 |
  | 0x0B | S→C | PasswordResult | `status : u8`（0 OK、1 REJECTED、2 RATE_LIMITED、3 ERROR）、`message : string`（最多 1024 字节） |

- 两次输入是否一致由客户端在本地校验，线上只携带最终密码
- 客户端拦截规则：只要命令名是 `passwd` 或 `recoverypasswd`（不区分大小写），无论参数是否正确都在本地处理，并从原版聊天输入历史中排除。参数以单个空格分隔，因此密码不能包含空格
- 同一玩家同时只能有一个请求在处理，每分钟最多 5 次；超出时返回 `PasswordResult(RATE_LIMITED)`。结果按请求顺序加密发送
- 服务端在游戏阶段的密码通道上只接受 SetPassword / SetRecoveryPassword；解密失败、格式错误、重放或其他类型均按 4.3.3 踢出玩家，之后不再处理该通道的任何数据。设定登录密码成功即解除受限（6.1），设定找回密码不改变受限状态
- 服务端依然注册这两个命令，但直接通过聊天执行时一律拒绝并提示，并且**不写入命令日志**
- 管理员重置只能在服务端控制台执行。Fabric 的命令形式为 `trustedserver reset key|password|all <player>`：
  - `key`：清空设备绑定，保留密码与受限状态；下次登录直接绑定新设备（设了登录密码仍须先输对，见 4.6）
  - `password`：清除登录密码，恢复受限（6.1）
  - `all`：删除整个账号，下次按新用户处理
  - 核心账号服务还支持单独清除找回密码，Fabric 控制台入口待接入
- 密码规则（服务端配置，默认）：6–128 个 Unicode 码点；登录密码与找回密码不能相同。游戏内设定不符合规则时返回 `PasswordResult(REJECTED)`

### 6.1 新用户受限状态

新用户名首次绑定后处于**受限**状态。登录阶段会先弹出 PasswordRequest(SET)：**只要在进入游戏前设定了密码，就直接解除受限，不施加任何额外限制**。玩家跳过时才在游戏内应用以下限制（服务端本地的权限状态，不涉及线上协议）：

- **强制生存模式**：每次进服都设为生存模式；受限期间任何途径把玩家改为其他模式，都会被立即改回
- **禁止执行所有指令**：拦截该玩家作为来源的全部指令执行（包括聊天输入的指令和客户端直接发送的指令包），并向其发送空的指令树，Tab 补全看不到任何指令，也不会泄露服务器装了哪些插件或 mod
- `/passwd`、`/recoverypasswd` 不受影响：它们由客户端拦截并走密码通道，并不是服务端的指令执行
- 解除方式：
  - **玩家设定登录密码后自动解除**：进入游戏前在 SET 提示框中设定，或进入游戏后用 `/passwd` 设定。依据是威胁模型 A：自动 bot 脚本不会针对本 mod 特化，不会走密码通道设密码
  - 受限玩家每次登录都会再次弹出 SET 提示框，直到设定密码
  - 管理员也可以在服务端控制台执行 `trustedserver trust <player>` 手动解除
  - 管理员用 `trustedserver reset password|all <player>` 清除密码后，在线玩家重新登录时恢复受限
- 受限期间每次进服都通过 Finish 的 `notices` 提示“设定密码后解除限制”
- 受限玩家同时是 OP 时，以受限为准，OP 权限一并暂停
- 开启登录密码层时，未设登录密码的 OP 默认暂停权限。本次 Mojang session 验证成功且设备公钥与登录开始时的原绑定匹配时，未受限的 OP 默认豁免。设置 `auth.validation.requirePasswordForVerifiedOps=true` 可取消该豁免
- OP 暂停只影响当前连接的有效权限。设置登录密码后重新计算原版权限并刷新指令树，保留管理员在暂停期间执行的授权或撤销操作
- OP 暂停的进服提醒由 `notices.opSuspended` 配置，空字符串关闭提醒

## 7. 拦截与限流（握手之前）

按顺序执行，任何一步不通过就断开，并显示配置的拒绝文本：

1. 每个地址的连接频率限制，覆盖 status ping 和登录（IPv4 按单个地址，IPv6 按 /64 网段；信任网段除外）
2. Hello 阶段检查 IP 封禁和用户名封禁（原版封禁列表并入此处）
3. 锁定检查：账号处于密码失败锁定期，或地址处于 IP 维度的锁定期
4. 无交互 PSK / 正版令牌门禁默认 10 秒超时；后续密码输入认证总超时默认 90 秒。同时把原版 600 tick 的登录超时放宽到不小于需要的认证总时长

**共享出口（NAT）**：大量正常玩家可能共用同一个 IPv4 地址，因此 IP 维度的限制分两层：登录总量额度较宽；只有未通过可信握手的连接（没装 mod、协议错误、证明无效、握手前超时等）才消耗严格的“未验证”额度。IP 维度的密码错误锁定阈值对 IPv4 更宽、时长更短，并可整体关闭；防猜密码主要依靠账号维度的锁定。默认数值见 AGENTS.md 第 19 条。

## 8. Status Ping 脱敏

- `status.mode=normal`（默认）：去掉玩家样本列表（sample）；在线人数可以是真实值、固定伪造值或范围内随机值；保留 MOTD、favicon 与版本显示
- `status.mode=enhanced`、`disablePing=false`：现代 Ping 返回通用 MOTD、通用版本名称、空 favicon 与空样本；`playerCount=real` 时强制显示 0，fixed/random 仍按配置；附加 ServerSeekerV2 退出标记；协议号保持真实以保证兼容判断
- `status.mode=enhanced`、`disablePing=true`：收到现代 Ping 后直接断开且不回应；直接登录仍可进行
- 增强模式一律关闭旧版 Ping（1.6 及以前格式），避免绕过现代响应取得真实 MOTD / 版本字段
- 强制关闭 query 协议（`enable-query`）

## 9. 服务端存储（SQLite）

```sql
-- 表结构版本记录在 PRAGMA user_version，启动时按版本依次迁移；开启 WAL，写操作串行
CREATE TABLE players (
  id             TEXT PRIMARY KEY,   -- 正版: UUID；离线: 小写用户名
  last_name      TEXT NOT NULL,
  player_pub     BLOB,               -- Ed25519 公钥；NULL 表示已被管理员清空，等待重新绑定
  password_hash  TEXT,               -- Argon2id 编码串，NULL 表示未设置
  recovery_hash  TEXT,
  restricted     INTEGER NOT NULL DEFAULT 1,  -- 1 = 新用户受限状态
  created_at     INTEGER NOT NULL,
  last_login_at  INTEGER,
  last_ip        TEXT
);

CREATE TABLE lockouts (
  subject        TEXT PRIMARY KEY,   -- "name:<id>" 或 "ip:<addr>"
  failures       INTEGER NOT NULL,   -- 跨连接累计的密码错误次数，登录成功后清零
  locked_until   INTEGER             -- 毫秒时间戳；NULL 表示未锁定
);

CREATE TABLE audit_log (
  ts             INTEGER NOT NULL,   -- 毫秒时间戳；默认保留 90 天
  subject        TEXT NOT NULL,
  event          TEXT NOT NULL,      -- bind / bind_after_reset / login_ok / login_fail / recover / online_rebind /
                                     -- set_password / set_recovery / reset_key / reset_password / reset_recovery /
                                     -- reset_all / trust / lockout / reject
  ip             TEXT,
  detail         TEXT
);
CREATE INDEX audit_log_ts ON audit_log (ts);
```

## 10. 协议版本规则（关键版本机制）

- 草案 v2：ServerHello 新增 `online_mode` 字段；与旧 v1 格式不兼容。
- 草案 v3：PasswordAnswer 增加显式 action，PasswordRequest 增加 RESET；密钥派生、签名与隧道 AAD 域标签同步升级为 `tsrv v3`。当前实现只支持 v3。

- 协议版本号（u16）**只在**线上格式、密码学或状态机发生变化时加 1，与 mod 版本号无关
- mod 的小版本没有改动核心验证部分时，协议版本不变，新旧客户端和服务端可以互相连接
- 服务端可以同时支持多个协议版本（`versions` 列表），给客户端留出升级过渡期

## 11. 已知限制

- **用户名枚举**：装了 mod 的攻击者完成前两轮后，可以根据“新用户名直接绑定”和“密钥不匹配”这两种不同结果，判断某个用户名是否注册过。这是 TOFU 加明确提示的代价，靠限流和审计日志缓解。正版模式下用户名本来就是公开的
- **首次连接的信任**：玩家第一次连接某个服务器时，无法识别中间人，这是 TOFU 的固有限制。服主可以公布服务端公钥指纹，供玩家核对
- **不考虑物理接触**：玩家私钥明文保存在本地
