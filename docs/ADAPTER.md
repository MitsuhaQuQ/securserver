# Minecraft 适配层规划

> 依据：[AGENTS.md](../AGENTS.md)、[PROTOCOL.md](PROTOCOL.md)、[CORE.md](CORE.md)。
> 核心层（`core`、`core-server`、`core-client`）已完成；本文规划把它接入 Minecraft。

## 1. 决定

- **先做 Fabric 1.20.1**：1.20.2 加入配置阶段之前的最后一个版本，登录流程与更早的版本一致，作为基准
- **先单版本模块** `fabric-1.20.1`，跑通后再引入 Stonecutter 扩展到其他版本与加载器
- **Mojang 官方映射**（`loom.officialMojangMappings()`）：类名与 NeoForge 一致，便于以后迁移
- **工具版本**：Fabric Loom 1.10.5（兼容 Gradle 8.12）、Fabric Loader 0.16.14、Fabric API 0.92.12+1.20.1
- **核心层以 jar-in-jar 方式随 mod 打包**，Bouncy Castle 与 sqlite-jdbc 同样随包携带（裁剪留到发布前）
- **只在独立服务端启用**：服务端逻辑放在 `server` 入口（`DedicatedServerModInitializer`），单人游戏与局域网的内置服务器不会加载

## 2. 服务端接入点（1.20.1）

| 环节 | 接入方式 |
|---|---|
| 登录 query 收发 | Fabric API `ServerLoginNetworking` / `ServerLoginConnectionEvents.QUERY_START`。开始时登记一个只在“放行”时才完成的 future：Fabric 在“没有等待中的 future 且没有在途 query”时就会放行，而在途 query 要等实际写出后才登记，逐轮补发会留下提前放行的窗口 |
| 握手前拦截 | 两段：收到登录 Hello 时（Mojang 验证之前，mixin）做 `ConnectionGate.beginLogin` 与 IP 封禁，使所有登录连接都计入限流；`QUERY_START`（验证之后）做名字 / UUID 封禁与账号锁定 |
| 拒绝提示 | `disconnect(Component.translatable("multiplayer.disconnect.banned"))` 或自定义文本 |
| 登录超时 | Mixin 放宽 `ServerLoginPacketListenerImpl` 的 600 tick 限制，并由我们按配置计时 |
| invalid session 回退 | Mixin 拦截 Mojang 验证失败时的断开，改为按第 17 条确定账号与 UUID 后继续 |
| 连接结束 | `ConnectionGate.endLogin(地址, 是否完成可信握手)`；放行后 `AccountService.recordLogin` |
| 新用户受限 / OP 暂停 | 玩家加入后：强制生存模式、拦截该玩家的全部指令、下发空指令树；`OpGuard` 暂停 OP |
| 游戏内密码通道 | Fabric API `ServerPlayNetworking`，每位玩家一个 `PlayPasswordEndpoint` |
| 控制台命令 | `trustedserver reset/trust/fingerprint`，只允许控制台来源 |
| 服务器列表 | Mixin `ServerStatusPacketListenerImpl` 与旧版 Ping 处理：限流、清空玩家样本、`StatusSanitizer` 人数；强制关闭 query |
| 隧道模式 | Netty 管线切换（最外层），放在最后单独实现与验证 |

## 3. 客户端接入点（1.20.1）

| 环节 | 接入方式 |
|---|---|
| 登录 query | Fabric API `ClientLoginNetworking`，交给 `ClientAuthSession` |
| PSK 登录门禁 | 客户端按当前服务器地址读取 `psk.txt`；完成 Ack 后按配置继续 Ed25519，只有全部启用层完成后才释放被扣下的加载器 query |
| 加载器信息隐藏 | PSK 通过前扣下所有 Fabric 注册 / 同步 query；Fabric 本身没有独立 mod 列表，因此当前版本无需构造诱饵列表 |
| TOFU 记录 | `core-client` 新增 `KnownServers`（文件存储） |
| 玩家密钥 | `PlayerKeyStore`（已实现） |
| 密码输入 / 设定框、公钥变更确认 | 自定义 `Screen`，在客户端主线程弹出，结果以 future 交回状态机 |
| `/passwd`、`/recoverypasswd` | Fabric API 客户端命令发送事件中用 `PasswordCommand` 拦截，经 `PlayPasswordClient` 发送 |
| 进服提示 | 进入游戏后在聊天栏显示 Finish 的 notices |
| 导出 / 导入认证 | Mod Menu 设置界面中的按钮（`PlayerKeyBackup`） |

## 4. 第一阶段：隐藏玩家信息与拦截自动破坏脚本

第一阶段只修正原版服务器列表的玩家信息泄漏，并用共享秘密拦截能够伪装协议但不知道 PSK 的自动破坏脚本：

| 包含 | 说明 |
|---|---|
| PSK 登录门禁 | 没装 mod、未配置 / 配错 PSK、协议错误或超时的连接以统一拒绝文本断开；通过后继续原版登录 |
| 握手前拦截 | `ConnectionGate` 限流（共享出口友好）、原版封禁、账号与 IP 锁定 |
| 服务器列表脱敏 | 清空玩家样本、人数按配置、旧版 Ping 同样处理与限流、强制关闭 query |
| 扫描增强模式 | 默认 normal；enhanced 返回通用诱饵状态并关闭旧版 Ping，可选 `disablePing` 让现代 Ping 也静默断开 |
| 服务端身份与配置 | 身份密钥、`server.json`、启动时打印指纹 |
| 客户端最小实现 | 按服务器地址读取 PSK；缺少条目时弹框输入、校验并保存，然后完成双向挑战应答 |

| 推迟 | 第一阶段的处理 |
|---|---|
| 正式认证协议 | Ed25519 / TOFU / SQLite 玩家公钥绑定已接入；密码界面、找回、受限状态执行与游戏内密码通道仍为后续阶段 |
| 服务端公钥变更确认界面 | 默认拒绝并在断开界面说明 |
| 受限 / OP 暂停 / 游戏内 `/passwd` | 不生效（账号仍按规则记为受限，后续阶段上线后再提示设密码） |
| 隧道模式 | 强制关闭；配置为 optional / required 时打印警告 |
| invalid session 回退 | 已纳入第一阶段：切换为离线 UUID 后必须通过 PSK；已声明的正版同名禁止回退 |
| 导出 / 导入按钮 | 后续阶段 |

当前 `server.json` 的分级开关默认值为：

```json
"auth": {
  "validation": {
    "ed25519": true,
    "loginPassword": false,
    "recoveryPassword": false,
    "newPlayerRestriction": false
  }
}
```

后三项已有核心状态机约束，但 Fabric 密码界面、找回流程和游戏阶段权限执行尚未完成，因此不默认开启。依赖关系非法时配置加载直接失败。

### 4.1 第一阶段的实现与验证

- 服务端：`PresharedKeyFile` 首次启动生成 `config/trustedserver/psk.key`；offline-mode 与 invalid-session 回退发送 PSK Challenge。Mojang session 正确时改由 `OnlineTokenStore` 验证或签发正版 UUID 的客户端令牌
- 客户端：`PresharedKeys` 从 `config/trustedserver/psk.txt` 按服务器地址读取密钥并原子保存界面输入；缺少条目时 `PskLoginHandler` 发送一次 PromptRequest、弹出输入框，再完成离线双向证明。`OnlineTokenLoginHandler` 把正版 session 自动取得的令牌写入 `online_tokens.txt`，换机缺少令牌时自动补发
- 核心：`PresharedKeyHandshake` 实现一次性双向证明，`PskWire` 严格检查 magic、type、长度和多余字节；用户名包含在证明上下文中。`PresharedKeyPolicy` 在服务端加载与客户端录入两侧统一拒绝明显弱密钥和常见密码组合
- PSK / 正版令牌通过前，其他登录 query 由 `ConnectionHoldQueriesMixin` 扣下；启用 Ed25519 时继续由 `ClientAuthSession` / `ServerAuthSession` 完成服务端身份签名、TOFU、玩家证明与账号绑定，只有 FinishAck 后才按顺序补发并继续原版 / Fabric 登录
- Forge / NeoForge 的公开 mod 元数据诱饵在相应适配模块实现：未可信探测只看到不参与兼容性校验的随机诱饵，真实握手列表仍在 PSK 通过后原样发送。不得向实际依赖校验列表插入虚假必需项
- 服务器列表脱敏、Ping / 登录限流、原版 IP / 玩家封禁和统一拒绝文本继续生效
- 开发运行默认带 `-Dtrustedserver.auditMixins=true`，启动时立即应用全部 mixin，注入点错误会直接报出
- 自动测试覆盖：正确密钥的完整 Challenge → Response → Proof → Ack、错误密钥、上下文不匹配、证明篡改、跨挑战重放、消息截断 / 多余字节、服务端密钥生成与损坏拒绝、客户端地址映射与损坏拒绝
- 正版名字声明在首次令牌 Ack 后持久化；同名离线回退随后拒绝。声明不会自动清除，控制台命令 `trustedserver clear-online-claim <用户名>` 同时删除声明和该名字的令牌

### 4.2 第一阶段手工联调

已在 `online-mode=false` 的 Fabric 1.20.1 开发服务端完成验证：

- 正确 PSK 完成 Challenge → Response → Proof → Ack 后通过基础门禁；关闭 Ed25519 时进入原版登录，默认配置则继续正式认证
- 默认配置随后完成 ServerHello → ClientHello → Challenge → ClientProof → Finish → FinishAck；首次绑定写入 SQLite，同名但不同玩家公钥的离线重连被拒绝
- 错误 PSK，以及对 `trustedserver:psk` 回答“不理解”的未安装客户端，均收到同一条配置拒绝文本；服务端日志不包含密钥、证明或可供探测者区分的详细原因
- Fabric 的其他登录 query 只在 PSK Ack 后出现；认证前探测只能看到 `trustedserver:psk`
- 服务器列表状态响应的玩家样本为空，未泄漏在线玩家名

已在 `online-mode=true` 对 session 无效的加密调试客户端完成回退验证：正确 PSK 必须先完成门禁才进入，错误 PSK 收到统一拒绝；其他 Fabric query 仍只在 PSK Ack 后出现。原版 session 失败不再能绕过 synchronizer。

尚未完成的手工项是使用真实 Mojang session 验证首次令牌签发 / 第二次令牌证明，以及旧版 Ping 的真实客户端验证；自动构建和 mixin 注入审计均已通过。Forge / NeoForge 的公开元数据诱饵随对应适配模块实现，不阻塞当前 Fabric 第一阶段。

### 4.3 网络自动攻击检查（2026-11-10）

| 主要路径 | 证据与影响 | 当前处理 | 仍需处理 |
|---|---|---|---|
| 扫描与协议指纹 | `node-minecraft-protocol` 公开支持状态 Ping、版本探测、online/offline、加密和完整登录，可直接作为批量扫描底层 | 状态样本清空、Ping / 登录限流、query 强制关闭；PSK / 令牌前隐藏加载器 query | Forge / NeoForge 公开元数据诱饵 |
| 通用脚本机器人 | Mineflayer 公开提供聊天、移动、攻击、挖掘、放置、容器和指令能力，普通协议兼容已足以自动破坏 | 未实现 TrustedServer 子协议的客户端在进入 play 状态前被拒；invalid-session 回退仍必须通过 PSK | 持有正确 PSK 或正版 session 的针对性机器人不属于模型 A，后续用受限新用户、密码或模型 B 处理 |
| 登录慢连接与分布式耗尽 | 单 IP 限流不能覆盖多出口 botnet，长认证超时会占用连接与验证资源 | 新增全服 `maxPendingLogins=256` 与无交互 `gateTimeoutSeconds=10`；原有每地址总量 / 未验证额度继续生效 | 大规模 DDoS 必须在主机、防火墙或上游清洗，Java mod 无法独立解决 |
| 已知 mod 自定义包 / 脚本 RCE | RebornCore、LogisticsPipes 的官方安全公告证明不安全反序列化可由恶意客户端触发；Integrated Scripting 的 CVE-2025-27107 在 1.20.1 旧版中允许已入服玩家执行任意代码 | 未认证者到不了 play 自定义频道；真实 mod 列表认证前不可见，降低批量定向命中率 | 认证不能修复有权限玩家可触发的 mod 漏洞；必须更新受影响 mod，并增加启动时版本审计 / 阻断清单 |
| Log4Shell 扫描 | Mojang 官方公告要求 1.18 升级到 1.18.1；本项目最低 1.18.2 已越过该原版受影响基线 | 不支持 1.18.0；登录前不接受聊天或游戏载荷 | 第三方启动器或重新打包依赖仍需供应链扫描，不靠文本过滤代替升级 |

资料：Mojang [Log4j 安全公告](https://www.minecraft.net/en-us/article/important-message--security-vulnerability-java-edition)、PrismarineJS [node-minecraft-protocol](https://github.com/PrismarineJS/node-minecraft-protocol) 与 [Mineflayer API](https://github.com/PrismarineJS/mineflayer/blob/master/docs/api.md)、RebornCore [GHSA-r7pg-4xrf-7mrm](https://github.com/TechReborn/RebornCore/security/advisories/GHSA-r7pg-4xrf-7mrm)、LogisticsPipes [GHSA-mcp7-xf3v-25x3](https://github.com/RS485/LogisticsPipes/security/advisories/GHSA-mcp7-xf3v-25x3)、NVD [CVE-2025-27107](https://nvd.nist.gov/vuln/detail/CVE-2025-27107)。

## 5. 实施顺序

| 步骤 | 内容 | 完成标准 |
|---|---|---|
| A | 模块骨架：Loom、映射、入口、mod 元数据、核心层打包 | `./gradlew build` 产出可加载的 mod jar |
| B | 第一阶段 PSK 登录门禁：双向证明、超时、统一拒绝、隐藏其他 query | online/offline 开发环境中正确 PSK 可进入，错误、缺失或原版客户端被拒 |
| C | 后续正式认证：TOFU、玩家密钥、密码与确认界面、invalid session 回退 | 新用户设密码、老用户登录、密钥变更确认可在开发环境走通 |
| D | 游戏阶段：受限、OP 暂停、游戏内密码通道、进服提示、控制台命令 | 受限玩家无法执行指令，`/passwd` 后解除 |
| E | 服务器列表脱敏、旧版 Ping、关闭 query | Ping 不再泄露玩家名 |
| F | 隧道模式 | 双端开启隧道后可正常游戏，抓包看不到明文 |
| G | 设置界面：导出 / 导入认证 | 两台客户端之间迁移成功 |
| H | 引入 Stonecutter，扩展版本与加载器 | 按支持矩阵逐个构建通过 |
