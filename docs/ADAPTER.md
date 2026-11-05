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
| TOFU 记录 | `core-client` 新增 `KnownServers`（文件存储） |
| 玩家密钥 | `PlayerKeyStore`（已实现） |
| 密码输入 / 设定框、公钥变更确认 | 自定义 `Screen`，在客户端主线程弹出，结果以 future 交回状态机 |
| `/passwd`、`/recoverypasswd` | Fabric API 客户端命令发送事件中用 `PasswordCommand` 拦截，经 `PlayPasswordClient` 发送 |
| 进服提示 | 进入游戏后在聊天栏显示 Finish 的 notices |
| 导出 / 导入认证 | Mod Menu 设置界面中的按钮（`PlayerKeyBackup`） |

## 4. 第一阶段：防自动扫描机器人

先只做威胁模型 A 的核心防线，让服务器在不改变玩家体验的前提下拦住扫描器与自动漏洞利用：

| 包含 | 说明 |
|---|---|
| 强制协议握手 | 没装 mod、协议错误、超时的连接以统一拒绝文本断开，进不了配置 / 游戏阶段 |
| 握手前拦截 | `ConnectionGate` 限流（共享出口友好）、原版封禁、账号与 IP 锁定 |
| 服务器列表脱敏 | 清空玩家样本、人数按配置、旧版 Ping 同样处理与限流、强制关闭 query |
| 服务端身份与配置 | 身份密钥、`server.json`、启动时打印指纹 |
| 客户端最小实现 | 应答握手、TOFU 记录、玩家密钥；进服后显示 notices |

| 推迟 | 第一阶段的处理 |
|---|---|
| 密码界面 | SET 一律按“跳过”回答；遇到 LOGIN / RECOVERY 时客户端本地提示“暂不支持”并断开（第一阶段无法设密码，正常不会出现） |
| 服务端公钥变更确认界面 | 默认拒绝并在断开界面说明 |
| 受限 / OP 暂停 / 游戏内 `/passwd` | 不生效（账号仍按规则记为受限，后续阶段上线后再提示设密码） |
| 隧道模式 | 强制关闭；配置为 optional / required 时打印警告 |
| invalid session 回退 | 保持原版行为（直接断开），是安全的默认 |
| 导出 / 导入按钮 | 后续阶段 |

### 4.1 第一阶段的实现与验证

- 服务端：`TrustedServerRuntime`（配置、身份、账号服务、限流、人数显示）、`LoginFlow`（每个登录连接一个）、控制台命令 `trustedserver fingerprint | reset key <玩家> | reset all <玩家>`；mixin：Hello 阶段拦截、登录超时、新版 / 旧版 Ping、关闭 query
- 客户端：`ClientLoginHandler`、`FabricClientEnvironment`（`KnownServers` + `PlayerKeyStore`，位于 `config/trustedserver/`）；本地失败直接断开并在断开界面说明原因
- 版本不兼容时客户端直接本地断开并显示双方版本，而不是先回答 `version = 0` 再等服务端断开：后者只会让玩家看到统一拒绝文本
- 开发运行默认带 `-Dtrustedserver.auditMixins=true`，启动时立即应用全部 mixin，注入点错误会直接报出
- `tools/probe_server.py`：只用标准库模拟扫描器 / 机器人，检查 Ping 脱敏、旧版 Ping、机器人登录被拒、Ping 限流
- `tools/ProbeClient.java`：用核心层完成真实认证握手的无界面客户端（`java -cp core.jar:core-client.jar tools/ProbeClient.java`），验证认证通过后的完整登录路径

### 4.2 第一阶段实测（开发服务端，离线模式，`tools/probe_server.py`）

| 检查 | 结果 |
|---|---|
| 新版服务器列表 Ping | 玩家样本为空，人数 0/20 |
| 旧版 Ping | 正常回复，人数 0/20 |
| 机器人登录（对 `trustedserver:auth` 回答“不理解”） | 被 `{"translate":"multiplayer.disconnect.banned"}` 断开，与真实封禁一致 |
| 同一地址连续 11 次机器人登录 | 前 10 次在握手处被拒；第 11 次在 Hello 阶段即被拒，收不到握手请求 |
| 连续 Ping | 与前两项合计第 20 次后被断开（Ping 额度可连发 20 次） |

实测中修正：离线模式下 `QUERY_START` 时玩家资料尚无 UUID，现按原版规则（`OfflinePlayer:<名字>`）提前算出，用于封禁检查与会话登记。

**隐藏其他登录 query**：Fabric API 自身会在登录阶段发出 `fabric-networking-api-v1:early_registration`、`fabric:custom_ingredient_sync` 等 query，机器人可据此判断服务器使用 Fabric。现在认证通过之前，所有非本 mod 的登录 query 都被扣下（`Connection.send` 的 mixin + `LoginFlow.holdOutgoing`）；通过时按原顺序补发后才放行，被拒时丢弃并释放缓冲。Fabric 在发送时同步登记在途 query，因此先补发、再完成“认证完成” future，Fabric 会等这些 query 的回答后才接受玩家。

| 检查 | 结果 |
|---|---|
| 机器人登录 | 握手前只看到 `trustedserver:auth`，随后被统一拒绝文本断开 |
| `tools/ProbeClient.java`（用核心层完成真实握手、无图形界面）：新玩家 | 握手完成后才收到两条 Fabric query，回答“不理解”后登录成功，服务端显示玩家进入游戏 |
| 同上：老玩家（同名、同一把密钥） | 密钥匹配；账号仍受限，再次提示设定密码（按第一阶段规则跳过），登录成功 |

图形界面客户端仍未实测。

## 5. 实施顺序

| 步骤 | 内容 | 完成标准 |
|---|---|---|
| A | 模块骨架：Loom、映射、入口、mod 元数据、核心层打包 | `./gradlew build` 产出可加载的 mod jar |
| B | 服务端登录：拦截、认证、超时、拒绝、invalid session 回退、登录记录 | 开发环境中原版客户端被拒、装 mod 的客户端可完成认证 |
| C | 客户端登录：TOFU、密钥、密码与确认界面 | 新用户设密码、老用户登录、密钥变更确认可在开发环境走通 |
| D | 游戏阶段：受限、OP 暂停、游戏内密码通道、进服提示、控制台命令 | 受限玩家无法执行指令，`/passwd` 后解除 |
| E | 服务器列表脱敏、旧版 Ping、关闭 query | Ping 不再泄露玩家名 |
| F | 隧道模式 | 双端开启隧道后可正常游戏，抓包看不到明文 |
| G | 设置界面：导出 / 导入认证 | 两台客户端之间迁移成功 |
| H | 引入 Stonecutter，扩展版本与加载器 | 按支持矩阵逐个构建通过 |
