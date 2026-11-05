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
| 登录 query 收发 | Fabric API `ServerLoginNetworking` / `ServerLoginConnectionEvents.QUERY_START`；用 `LoginSynchronizer.waitFor` 推迟放行，直到认证结束 |
| 握手前拦截 | `QUERY_START` 时：`ConnectionGate.beginLogin`、封禁（`PlayerList.canPlayerLogin`）、账号与 IP 锁定 |
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

## 4. 实施顺序

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
