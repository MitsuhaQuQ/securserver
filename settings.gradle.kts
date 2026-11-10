pluginManagement {
    repositories {
        maven("https://maven.fabricmc.net/") { name = "Fabric" }
        gradlePluginPortal()
    }
}

rootProject.name = "trustedserver"

include("core", "core-server", "core-client")
include("fabric-1.20.1", "fabric-1.20.2", "fabric-1.20.4", "fabric-1.21.1")
