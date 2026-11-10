plugins {
    id("fabric-loom") version "1.10.5"
}

base {
    archivesName = "trustedserver-fabric-1.20.1"
}

repositories {
    maven("https://maven.fabricmc.net/")
    maven("https://maven.terraformersmc.com/releases/")
}

sourceSets.main {
    java.srcDir("../fabric-legacy/src/main/java")
}

dependencies {
    "minecraft"("com.mojang:minecraft:1.20.1")
    "mappings"(loom.officialMojangMappings())
    "modImplementation"("net.fabricmc:fabric-loader:0.16.14")
    "modImplementation"("net.fabricmc.fabric-api:fabric-api:0.92.12+1.20.1")
    "modCompileOnly"("com.terraformersmc:modmenu:7.1.0")
    "modLocalRuntime"("com.terraformersmc:modmenu:7.1.0")

    // 核心层与其依赖以 jar-in-jar 方式随 mod 打包
    for (module in listOf(":core", ":core-client", ":core-server")) {
        "implementation"(project(module))
        "include"(project(module))
    }
    "include"("org.bouncycastle:bcprov-jdk18on:1.78.1")
    "include"("org.xerial:sqlite-jdbc:3.46.1.0")
}

loom {
    runs {
        // 开发运行时立即应用全部 mixin，尽早发现注入点错误
        configureEach {
            vmArg("-Dtrustedserver.auditMixins=true")
        }
    }
}

tasks.processResources {
    inputs.property("version", project.version)
    inputs.property("minecraft_dependency", "~1.20.1")
    inputs.property("java_dependency", ">=17")
    inputs.property("java_compatibility", "JAVA_17")
    filesMatching("fabric.mod.json") {
        expand("version" to project.version, "minecraft_dependency" to "~1.20.1", "java_dependency" to ">=17")
    }
    filesMatching("trustedserver.mixins.json") {
        expand("java_compatibility" to "JAVA_17")
    }
}

// Minecraft 与 Mixin 注解处理器会产生无关警告，本模块不把警告视为错误
tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.removeAll(listOf("-Xlint:all", "-Werror"))
}
