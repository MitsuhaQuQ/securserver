plugins {
    id("fabric-loom") version "1.10.5"
}

base {
    archivesName = "trustedserver-fabric-1.20.2"
}

repositories {
    maven("https://maven.fabricmc.net/")
    maven("https://maven.terraformersmc.com/releases/")
}

dependencies {
    "minecraft"("com.mojang:minecraft:1.20.2")
    "mappings"(loom.officialMojangMappings())
    "modImplementation"("net.fabricmc:fabric-loader:0.16.14")
    "modImplementation"("net.fabricmc.fabric-api:fabric-api:0.91.6+1.20.2")
    "modCompileOnly"("com.terraformersmc:modmenu:8.0.1") {
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
        java.setSrcDirs(listOf("../fabric-1.20.1/src/main/java", "../fabric-legacy/src/main/java"))
        resources.setSrcDirs(listOf("../fabric-1.20.1/src/main/resources"))
    }
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
    inputs.property("minecraft_dependency", "~1.20.2")
    inputs.property("java_dependency", ">=17")
    inputs.property("java_compatibility", "JAVA_17")
    filesMatching("fabric.mod.json") {
        expand("version" to project.version, "minecraft_dependency" to "~1.20.2", "java_dependency" to ">=17")
    }
    filesMatching("trustedserver.mixins.json") {
        expand("java_compatibility" to "JAVA_17")
    }
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.removeAll(listOf("-Xlint:all", "-Werror"))
}
