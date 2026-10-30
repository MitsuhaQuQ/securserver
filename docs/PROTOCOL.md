# TrustedServer 认证协议设计

> 协议版本：`1`（草案）
> 需求与决策见 [AGENTS.md](../AGENTS.md)。本文只描述线上协议、密码学与状态机。

## 1. 总览

```
客户端                                    服务端
  | -- Handshake / Status Ping ------------> |  限流；Ping 响应脱敏
  | -- Hello(username) --------------------> |  IP / 名称封禁检查（拦截）
  |                                          |  [正版] 原版加密 + Mojang 验证
  | <-- Query#1 ServerHello ---------------- |  协商版本 + 临时密钥交换
  | --> ClientHello -----------------------> |
  | <-- Query#2 Challenge (加密) ----------- |  服务端身份签名
  | --> ClientProof (加密) ----------------> |  玩家密钥签名
  | <-- Query#3 PasswordRequest (可选) ----- |  登录密码 / 找回密码
  | --> PasswordAnswer (加密) -------------> |
  | <-- Query#N Finish (加密) -------------- |  结果；是否开启隧道
  | --> FinishAck -------------------------> |  [隧道] 双方切换为隧道加密
  | <-- 原版 SetCompression / LoginSuccess - |  之后才进入加载器握手与游戏
```

- 全部在**登录阶段**完成，使用原版的 login query：服务端发 `ClientboundCustomQueryPacket`，客户端回 `ServerboundCustomQueryPacket`（1.20.2+ 为 `ServerboundCustomQueryAnswerPacket`）
- 频道 ID：`trustedserver:auth`
- 由服务端驱动，每一轮是一对 query / answer，用原版的 transaction id 对应
- 认证完成前，服务端**不发送** `LoginSuccess`，连接不会进入配置阶段或游戏阶段，满足“0 权限”
- 本协议的 query 必须早于加载器自身的登录握手（Forge 1.18.2–1.19.4 的 `fml:loginwrapper`），没装 mod 的连接拿不到服务端的 mod 列表

### 拦截未装 mod 的连接

原版客户端收到不认识的 query 时会回答“不理解”（payload 为空）；不实现 login query 的机器人会一直不回应。两种情况都直接按拒绝处理：

- 空回答：立即断开
- 无回答：认证超时后断开

断开提示使用配置的拒绝文本（默认模仿原版封禁提示）。

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

## 3. 身份与密钥

### 服务端身份密钥

- Ed25519 长期密钥对，首次启动时生成，保存在 `config/trustedserver/server_identity.key`
- 客户端按 **TOFU**（首次信任，类似 SSH 的 `known_hosts`）记住服务端公钥，作用是在离线模式下**防中间人**
- 同一服务器地址的公钥发生变化时，客户端弹出明确警告并默认拒绝连接，玩家确认后才更新

### 玩家密钥

- Ed25519 密钥对，按 **（服务端身份公钥, 用户名）** 生成，每个服务器一把，避免跨服务器追踪
- 以服务端身份公钥而不是服务器地址为索引，服务器换域名或 IP 后仍然有效
- 客户端存放在 `config/trustedserver/keys/`。按决策不考虑物理接触，私钥明文保存，文件权限设为仅本用户可读
- 服务端记录方式（TOFU）：
  - 正版模式按 **UUID** 记录（用户名已由 Mojang 验证）
  - 离线模式按**小写用户名**记录

## 4. 消息格式

所有 payload 的通用开头：

```
magic        : 4 bytes  "TSRV"
type         : u8
body         : 按 type 定义
```

`varbytes` 指 VarInt 长度前缀加字节串，`string` 指 VarInt 长度前缀加 UTF-8。

### 4.1 ServerHello（S→C，明文，type=0x01）

```
versions       : varbytes   服务端支持的协议版本列表（每个 u16）
server_eph_pub : 32 bytes   X25519 临时公钥
server_nonce   : 32 bytes
features       : u32 bitmask
                  bit0 TUNNEL_AVAILABLE  服务端允许隧道模式
                  bit1 TUNNEL_REQUIRED   服务端强制隧道模式
```

### 4.2 ClientHello（C→S，明文，type=0x02）

```
version        : u16        从 versions 中选出的最高共同版本
client_eph_pub : 32 bytes
client_nonce   : 32 bytes
want_tunnel    : bool       客户端配置希望开启隧道
```

没有共同版本时，客户端回答 `version = 0`，服务端以“版本不兼容”断开，并告知双方的版本号。

### 4.3 会话密钥派生

```
transcript_0 = SHA-256( ServerHello 字节 || ClientHello 字节 || username || online_mode_flag )
shared       = X25519(eph_priv, peer_eph_pub)        全零结果视为失败并断开
prk          = HKDF-Extract(salt = server_nonce || client_nonce, ikm = shared)
k_s2c        = HKDF-Expand(prk, "tsrv v1 auth s2c" || transcript_0, 32)
k_c2s        = HKDF-Expand(prk, "tsrv v1 auth c2s" || transcript_0, 32)
k_tun_s2c    = HKDF-Expand(prk, "tsrv v1 tunnel s2c" || transcript_0, 32)
k_tun_c2s    = HKDF-Expand(prk, "tsrv v1 tunnel c2s" || transcript_0, 32)
k_play_s2c   = HKDF-Expand(prk, "tsrv v1 play s2c" || transcript_0, 32)
k_play_c2s   = HKDF-Expand(prk, "tsrv v1 play c2s" || transcript_0, 32)
```

username 和正版/离线标志写进 transcript，防止中间人改用户名或降级模式。

之后的认证消息封装为：

```
magic | type | AEAD(k_dir, nonce = 4 字节方向标签 || u64 序号, plaintext, aad = magic||type)
```

每个方向的序号从 0 开始单调递增，出现重复或乱序即断开。

### 4.4 Challenge（S→C，加密，type=0x03）

```
server_id_pub  : 32 bytes   服务端 Ed25519 身份公钥
server_sig     : 64 bytes   Sign(server_id, "tsrv v1 server" || transcript_0)
```

客户端用 TOFU 记录核对 `server_id_pub` 并验证签名，然后以它为索引找到（或新生成）玩家密钥。

### 4.5 ClientProof（C→S，加密，type=0x04）

```
player_pub     : 32 bytes
player_sig     : 64 bytes   Sign(player_key, "tsrv v1 client" || transcript_0)
```

### 4.6 服务端判定

| 状态 | 处理 |
|---|---|
| 该身份无绑定记录（新用户名） | 绑定 `player_pub`（TOFU），然后进入 Finish |
| 公钥一致，未设登录密码 | 进入 Finish |
| 公钥一致，已设登录密码 | 发 PasswordRequest(LOGIN) |
| 公钥不一致，已设找回密码 | 发 PasswordRequest(RECOVERY) |
| 公钥不一致，未设找回密码 | 断开，并明确提示“密钥不匹配，请联系管理员重置” |

### 4.7 PasswordRequest（S→C，加密，type=0x05）

```
kind           : u8   1 = LOGIN, 2 = RECOVERY
attempts_left  : u8
timeout_sec    : u16
```

客户端弹出输入框，标题和说明按 `kind` 区分。RECOVERY 时明确提示“找回成功后，当前设备的新密钥将取代旧绑定”。

### 4.8 PasswordAnswer（C→S，加密，type=0x06）

```
password       : string   最长 128 个字符
```

- 密码只在已认证的加密通道里传输，服务端用 Argon2id 校验，客户端不保存密码
- 不采用 OPAQUE 一类的 PAKE（口令认证密钥交换）：服务端身份已固定，再加上 AEAD，足以防窃听和中间人，复杂度低很多
- 判定流程：
  - LOGIN 正确：进入 Finish
  - RECOVERY 正确：把绑定改为本次的 `player_pub`；如果还设了登录密码，再发一次 PasswordRequest(LOGIN)
  - 错误：失败计数加 1，`attempts_left > 0` 时重发请求，否则锁定并断开

### 4.9 Finish（S→C，加密，type=0x07）

```
result         : u8   0 = OK
tunnel         : bool 是否开启隧道（TUNNEL_REQUIRED，或双方都希望开启）
notices        : varbytes  客户端进服后要显示的提示（如“尚未设置找回密码”）
```

### 4.10 FinishAck（C→S，加密，type=0x08）

空 body。服务端收到后：

- 若 `tunnel = true`，按第 5 节切换为隧道加密
- 继续原版流程（SetCompression → 加载器握手 → LoginSuccess）

## 5. 高安全模式：隧道

- 在 Netty 管线的最外层（原版 `encrypt` / `decrypt` 处理器的位置）插入隧道编解码器：
  - 离线模式：新增这两个处理器
  - 正版模式：替换掉原版的 AES-CFB8 处理器
- 帧格式：`VarInt 长度 || AES-256-GCM(k_tun_dir, nonce = 方向标签 || u64 序号, 原始字节块)`。序号耗尽前断开连接
- 切换时机：
  - 客户端发出 FinishAck 后立刻安装编解码器
  - 服务端收到 FinishAck 后、发送下一个包之前安装
  - 登录阶段客户端在收到服务端下一个包之前不会再发包，所以不会有新旧加密混在同一个缓冲区里，与原版启用加密的时序一致
- 兼容性：隧道会改变线上字节格式，所以只在双方都装了本 mod 时启用；由于不支持代理，不存在中间层解析的问题

## 6. 游戏阶段的安全通道（`/passwd`、`/recoverypasswd`）

在离线模式且未开隧道时，原版连接是明文，直接把聊天命令发出去会暴露密码。因此：

- 客户端 mod 在本地拦截 `/passwd` 和 `/recoverypasswd`，**不作为聊天命令发出**
- 改为通过自定义游戏数据包（play custom payload，频道 `trustedserver:secure`）发送，用 `k_play_*` 加密，序号独立计数
- 消息类型：
  - `SetPassword{password}`
  - `SetRecoveryPassword{password}`
  - `Result{code, message}`
- 服务端依然注册这两个命令，但直接通过聊天执行时一律拒绝并提示，并且**不写入命令日志**
- 管理员重置只能在服务端控制台执行：`trustedserver reset <player> key|password|recovery|all`

## 7. 拦截与限流（握手之前）

按顺序执行，任何一步不通过就断开，并显示配置的拒绝文本：

1. 每个 IP 的连接频率限制，覆盖 status ping 和登录
2. Hello 阶段检查 IP 封禁和用户名封禁（原版封禁列表并入此处）
3. 锁定检查：用户名或 IP 处于密码失败锁定期
4. 认证总超时：默认 90 秒，可配置；同时把原版 600 tick 的登录超时放宽到不小于该值

## 8. Status Ping 脱敏

- 去掉玩家样本列表（sample）
- 在线人数可以是真实值、固定伪造值或范围内随机值
- 旧版 Ping（1.6 及以前的格式）同样处理
- 强制关闭 query 协议（`enable-query`）

## 9. 服务端存储（SQLite）

```sql
CREATE TABLE players (
  id             TEXT PRIMARY KEY,   -- 正版: UUID；离线: 小写用户名
  last_name      TEXT NOT NULL,
  player_pub     BLOB NOT NULL,      -- Ed25519 公钥
  password_hash  TEXT,               -- Argon2id 编码串，NULL 表示未设置
  recovery_hash  TEXT,
  created_at     INTEGER NOT NULL,
  last_login_at  INTEGER,
  last_ip        TEXT
);

CREATE TABLE lockouts (
  subject        TEXT PRIMARY KEY,   -- "name:<id>" 或 "ip:<addr>"
  failures       INTEGER NOT NULL,
  locked_until   INTEGER
);

CREATE TABLE audit_log (
  ts             INTEGER NOT NULL,
  subject        TEXT NOT NULL,
  event          TEXT NOT NULL,      -- bind / login_ok / login_fail / recover / reset / reject
  ip             TEXT
);
```

## 10. 协议版本规则（关键版本机制）

- 协议版本号（u16）**只在**线上格式、密码学或状态机发生变化时加 1，与 mod 版本号无关
- mod 的小版本没有改动核心验证部分时，协议版本不变，新旧客户端和服务端可以互相连接
- 服务端可以同时支持多个协议版本（`versions` 列表），给客户端留出升级过渡期

## 11. 已知限制

- **用户名枚举**：装了 mod 的攻击者完成前两轮后，可以根据“新用户名直接绑定”和“密钥不匹配”这两种不同结果，判断某个用户名是否注册过。这是 TOFU 加明确提示的代价，靠限流和审计日志缓解。正版模式下用户名本来就是公开的
- **首次连接的信任**：玩家第一次连接某个服务器时，无法识别中间人，这是 TOFU 的固有限制。服主可以公布服务端公钥指纹，供玩家核对
- **不考虑物理接触**：玩家私钥明文保存在本地
