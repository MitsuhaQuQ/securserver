dependencies {
    "api"(project(":core"))
    // 仅用其 Argon2id；打包进 mod 时 shade、重定位并裁剪（见 docs/CORE.md 第 6 节）
    "implementation"("org.bouncycastle:bcprov-jdk18on:1.78.1")
    // 打包进 mod 时以 jar-in-jar 方式携带
    "implementation"("org.xerial:sqlite-jdbc:3.46.1.0")
}
