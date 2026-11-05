dependencies {
    "api"(project(":core"))
    // 仅用其 Argon2id；打包进 mod 时 shade、重定位并裁剪（见 docs/CORE.md 第 6 节）
    "implementation"("org.bouncycastle:bcprov-jdk18on:1.78.1")
    // 打包进 mod 时以 jar-in-jar 方式携带
    "implementation"("org.xerial:sqlite-jdbc:3.46.1.0")
    // 运行时使用 Minecraft 自带的 Gson；只用 1.18.2 自带的 2.8.9 也有的基础 API
    "compileOnly"("com.google.code.gson:gson:2.8.9")
    "testImplementation"("com.google.code.gson:gson:2.8.9")
    // 端到端测试需要客户端一侧的游戏内密码通道
    "testImplementation"(project(":core-client"))
}
