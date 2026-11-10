plugins {
    id("fabric-loom") version "1.10.5"
}

base {
    archivesName = "trustedserver-fabric-1.21.1"
}

repositories {
    maven("https://maven.fabricmc.net/")
    maven("https://maven.terraformersmc.com/releases/")
}

dependencies {
    "minecraft"("com.mojang:minecraft:1.21.1")
    "mappings"(loom.officialMojangMappings())
    "modImplementation"("net.fabricmc:fabric-loader:0.16.14")
    "modImplementation"("net.fabricmc.fabric-api:fabric-api:0.116.18+1.21.1")
    "modCompileOnly"("com.terraformersmc:modmenu:11.0.3") {
        isTransitive = false
    }

    for (module in listOf(":core", ":core-client", ":core-server")) {
        "implementation"(project(module))
        "include"(project(module))
    }
    "include"("org.bouncycastle:bcprov-jdk18on:1.78.1")
    "include"("org.xerial:sqlite-jdbc:3.46.1.0")
}

sourceSets {
    main {
        java.setSrcDirs(listOf("../fabric-1.20.1/src/main/java", "src/main/java"))
        resources.setSrcDirs(listOf("../fabric-1.20.1/src/main/resources"))
    }
}

java {
    toolchain.languageVersion = JavaLanguageVersion.of(21)
}

loom {
    runs {
        configureEach {
            vmArg("-Dtrustedserver.auditMixins=true")
        }
    }
}

tasks.processResources {
    inputs.property("version", project.version)
    inputs.property("minecraft_dependency", "~1.21.1")
    inputs.property("java_dependency", ">=21")
    inputs.property("java_compatibility", "JAVA_21")
    filesMatching("fabric.mod.json") {
        expand("version" to project.version, "minecraft_dependency" to "~1.21.1", "java_dependency" to ">=21")
    }
    filesMatching("trustedserver.mixins.json") {
        expand("java_compatibility" to "JAVA_21")
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.removeAll(listOf("-Xlint:all", "-Werror"))
}
