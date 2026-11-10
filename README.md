# TrustedServer

面向 Minecraft Java 独立服务器的客户端/服务端安全 mod。TrustedServer 在玩家进入游戏前增加可信握手、身份绑定、密码恢复和网络限流，用于减少通用扫描器、自动登录机器人和批量漏洞利用脚本带来的风险，同时隐藏服务器列表中的玩家名称。

> 当前可运行版本为 **Fabric 1.20.1**。客户端和服务端都必须安装本 mod；未安装客户端 mod 的连接会被拒绝。本项目仍在开发中，不建议在没有备份和测试的情况下直接用于生产服务器。

## 功能概览

- 在加载器握手和游戏阶段之前完成登录门禁，未通过可信握手的连接不能进入服务器。
- 支持正版 `online-mode=true` 与离线 `online-mode=false` 服务器。
- 正版连接使用 Mojang session 和自动签发的账号令牌；离线连接及 invalid-session 回退使用每服独立的 PSK 双向挑战应答。
- 可选 Ed25519 设备密钥绑定：客户端首次登录生成玩家专属密钥，服务端以 TOFU 方式记录公钥。
- 可选登录密码和独立找回密码；密码只通过独立派生的加密通道传输。
- 新用户未设置登录密码时可限制为生存模式、禁止执行指令，并暂停不满足条件的 OP 权限。
- 隐藏服务器列表玩家样本，可显示真实、固定或随机在线人数。
- 提供普通和增强扫描防护模式；增强模式可隐藏 MOTD、图标和版本特征，或完全关闭 Ping 响应。
- 提供登录、未验证连接、服务器列表 Ping、密码错误和全服待认证连接的限流与锁定。
- 玩家数据存入 SQLite，密码使用 Argon2id；认证、恢复、重置和拒绝事件写入审计记录。
- 客户端可通过 Mod Menu 导出、导入 Ed25519 认证密钥，便于迁移电脑。

## 当前支持状态

| 平台 | 版本 | 状态 |
|---|---:|---|
| Fabric | 1.20.1 | 已接入，当前开发基准 |
| Fabric | 1.18.2+ 的其他版本 | 计划支持 |
| Forge | 1.18.2–1.19.4 | 计划支持 |
| NeoForge | 1.20.1+ | 计划支持 |

当前不支持：

- 原版客户端、基岩版和 Geyser；
- Velocity、BungeeCord 等代理；
- 其他认证 mod 共存；
- 客户端内置服务器及局域网开放的单人游戏。

高安全隧道的核心编解码已经存在，但 Fabric 适配层尚未启用整条 Minecraft 连接的隧道传输。当前默认只加密认证和密码通道，原版游戏连接保持不变。

## 工作原理

一次连接大致经过以下阶段：

```text
服务器列表 Ping
  └─ 限流、隐藏玩家样本、按配置处理人数与服务器特征

开始登录
  ├─ IP / 网段限流、原版封禁和全服待认证额度
  ├─ 正版 session 有效：账号令牌门禁
  └─ 离线或 session 无效：PSK 双向挑战应答
          ↓
可信门禁通过
  └─ 可选 Ed25519：服务端身份签名 + 客户端 TOFU + 玩家 ClientProof
          ↓
可选密码阶段
  ├─ 已设置登录密码：弹框验证
  ├─ 新用户：可在进入游戏前设置密码
  └─ 设备不匹配：按条件使用找回密码或正版恢复流程
          ↓
认证完成
  ├─ 正常放行
  └─ 未设置密码的新用户按配置进入受限状态
```

### 基础门禁

`online-mode=true` 且 Mojang session 验证成功时，服务端使用绑定正版 UUID、用户名和服务端身份的账号令牌。客户端没有令牌或令牌失效时，可凭本次有效 session 自动取得新令牌，换电脑不需要管理员先重置。

`online-mode=false` 或正版服务器发生 invalid-session 回退时，连接必须完成 PSK 双向挑战应答。PSK 是服务器级准入凭据，不代表具体玩家身份；通过后仍可继续 Ed25519 和密码验证。已被声明为正版身份的用户名不能通过离线回退冒用。

在基础门禁通过前，Fabric 的其他登录 query 会被扣下，避免向未可信探测者暴露真实加载器频道和 mod 组合。

### 玩家身份与 TOFU

启用 `auth.validation.ed25519` 后，服务端用长期身份密钥签署握手，客户端首次连接时记录服务端公钥。客户端再为“服务端身份公钥 + 用户名”生成独立 Ed25519 密钥，服务端首次见到该账号时绑定其公钥。

服务端身份公钥或玩家设备公钥发生意外变化时，连接默认拒绝。玩家迁移电脑时应使用认证密钥导出/导入功能；也可以使用找回密码，或由管理员重置设备绑定。

### 密码与恢复

登录密码是 Ed25519 之后的可选附加验证，不设置密码的老玩家仍可只使用已绑定设备密钥登录。登录密码和找回密码互相独立，且不能设置为相同内容。

所有密码消息都使用独立派生的密钥和独立消息通道，不会作为原版命令包或聊天内容发送。`/passwd` 与 `/recoverypasswd` 在客户端本地拦截；即使用法错误，也不会把输入转发到服务器聊天或命令日志。

### 威胁模型与边界

当前目标是阻止不理解 TrustedServer 协议、没有有效令牌或 PSK 的通用扫描器和自动利用脚本。它不能代替以下防护：

- 主机防火墙、上游清洗和 DDoS 防护；
- 对其他 mod 漏洞的升级与修补；
- 对已经取得正确 PSK、密码或正版账号的针对性攻击；
- 操作系统权限、服务端文件备份和密钥保管。

## 安装与首次启动

当前 Fabric 1.20.1 版本需要：

- Java 17 或更高版本；
- Fabric Loader；
- Fabric API；
- TrustedServer mod，客户端与服务端使用相同认证协议版本（推荐使用相同构建）；
- Mod Menu 为客户端可选依赖，只用于认证密钥导入/导出界面。

将构建产物放入服务端和客户端的 `mods/` 目录。服务端首次启动会在 `config/trustedserver/` 下生成配置和密钥文件。

### 离线服务器的 PSK

服务端的 `config/trustedserver/psk.key` 只包含一行 Base64 密钥。管理员需要通过安全渠道把这行密钥交给允许连接的玩家。

客户端第一次收到真实 PSK Challenge 且没有对应配置时，会弹出本地输入框并保存密钥。也可以手动编辑 `config/trustedserver/psk.txt`：

```text
# TrustedServer PSK: <server-address> <Base64 32-byte key>
mc.example.com <服务端 psk.key 中的 Base64 密钥>
mc.example.com:25566 <另一台服务器的 Base64 密钥>
```

不要把 PSK 写入公开仓库、聊天记录或服务器断开提示。PSK 必须解码为正好 32 字节，明显的弱密钥会被客户端和服务端同时拒绝。推荐始终使用服务端首次启动自动生成的随机值。

正版 session 验证成功的连接使用账号令牌门禁，不接收也不会下发全服 PSK。

## 玩家命令

以下命令必须由安装了 TrustedServer 的客户端输入。密码不能包含空格，默认长度为 6–128 个 Unicode 码点。

| 命令 | 作用 |
|---|---|
| `/passwd <密码> <确认密码>` | 设置或替换登录密码。两次输入必须一致；设置成功后立即解除新用户受限状态。默认不要求输入旧密码。 |
| `/recoverypasswd <密码> <确认密码>` | 设置或替换独立的找回密码。不能与登录密码相同。 |

示例：

```text
/passwd correct-horse correct-horse
/recoverypasswd another-secret another-secret
```

登录过程中需要输入、设置或恢复密码时，客户端会显示密码输入界面，不需要在聊天栏执行命令。

## 管理员命令

管理员命令当前只允许在独立服务端控制台执行。游戏内 OP 即使拥有最高权限也不能运行这些命令。

| 命令 | 作用 |
|---|---|
| `trustedserver fingerprint` | 显示服务端身份公钥指纹，用于客户端或管理员核对服务器身份。 |
| `trustedserver reset key <玩家>` | 清除玩家设备公钥绑定，保留登录密码和受限状态；下次登录绑定新设备，已有密码时仍需验证。 |
| `trustedserver reset password <玩家>` | 清除登录密码并恢复受限状态；在线玩家会被断开并要求重新认证。 |
| `trustedserver reset all <玩家>` | 删除整个 TrustedServer 账号，下次登录按新用户处理；在线玩家会被断开。 |
| `trustedserver trust <玩家>` | 手动解除新用户受限状态；在线时立即刷新有效权限。 |
| `trustedserver clear-online-claim <用户名>` | 清除“用户名 → 正版 UUID”声明及该名字的账号令牌，允许管理员明确恢复该名字的离线使用。 |

正版服务器解析玩家时优先使用在线玩家和本地玩家缓存；必要时也可以向 `<玩家>` 传入 UUID。离线服务器按不区分大小写的用户名保存账号。

> 核心服务已经实现找回密码重置操作，但当前 Fabric 控制台尚未注册 `trustedserver reset recovery` 命令。

## 配置与数据文件

### 服务端

| 路径 | 内容 |
|---|---|
| `config/trustedserver/server.json` | 主配置。不存在时写出完整默认配置；格式或依赖关系非法时拒绝启动，未知键只警告。 |
| `config/trustedserver/server_identity.key` | 服务端长期身份私钥。损坏时拒绝启动，不会自动覆盖或重新生成。 |
| `config/trustedserver/psk.key` | 离线/回退连接使用的 32 字节随机 PSK。 |
| `config/trustedserver/players.db` | SQLite 玩家账号、设备绑定、密码哈希、锁定和审计数据。 |

常用配置项：

- `auth.validation.*`：Ed25519、登录密码、找回密码、新用户限制和已验证 OP 的密码要求；
- `password.*`：密码长度与 Argon2id 参数；
- `accounts.*`：哈希线程、队列、账号锁定、审计保留和数据库路径；
- `network.*`：Ping/登录/未验证限流、待认证上限、IP 锁定和信任网段；
- `status.*`：`normal`/`enhanced`、是否关闭 Ping、在线人数显示方式；
- `rejection.*`：认证可信前统一使用的拒绝文本；
- `notices.*`：受限、找回提醒、重新绑定和 OP 暂停提示。

非法的验证层组合会导致服务器拒绝启动。例如关闭 Ed25519 时，登录密码、找回密码、新用户限制和隧道不能继续启用。

### 客户端

| 路径 | 内容 |
|---|---|
| `config/trustedserver/psk.txt` | 服务器地址到 PSK 的映射。 |
| `config/trustedserver/online_tokens.txt` | 正版账号令牌。 |
| `config/trustedserver/known_servers.txt` | TOFU 记录的服务端身份公钥。 |
| `config/trustedserver/keys/` | 按服务端身份和用户名保存的玩家 Ed25519 密钥。 |

客户端密钥备份只包含玩家 Ed25519 认证密钥，不包含登录密码、找回密码、PSK 或服务端私钥。可在 Mod Menu → TrustedServer 中选择导出范围，并选择使用 PBKDF2-HMAC-SHA256 + AES-256-GCM 加密备份。明文导出的文件可被持有者用于冒充玩家，请妥善保管。

## 构建

Windows：

```powershell
.\gradlew.bat build
```

Linux/macOS：

```bash
./gradlew build
```

Fabric 1.20.1 的可安装 jar 输出到：

```text
fabric-1.20.1/build/libs/trustedserver-fabric-1.20.1-<版本>.jar
```

项目使用 Gradle 8.12 和 Java 17 toolchain。模块划分如下：

- `core`：协议消息、密码通道、密码学、认证状态机和隧道编解码；
- `core-client`：客户端 TOFU、设备密钥、PSK/令牌存储和密钥备份；
- `core-server`：配置、策略、SQLite、Argon2id、账号与审计服务；
- `fabric-1.20.1`：Minecraft/Fabric 登录、GUI、命令、权限和服务器列表适配。

## 进一步阅读

- [认证协议设计](docs/PROTOCOL.md)
- [核心逻辑与存储](docs/CORE.md)
- [Minecraft 适配层](docs/ADAPTER.md)
- [项目约束与设计决策](AGENTS.md)
