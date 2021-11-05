pluginManagement {
    repositories {
        gradlePluginPortal()
        google()
    }
}
plugins {
    id("com.gradle.enterprise").version("3.7.1")
}
gradleEnterprise {
    buildScan {
        if (!System.getenv("CI").isNullOrEmpty()) {
            publishOnFailure()
        }
    }
}
rootProject.name = "awala-keystore-file"
