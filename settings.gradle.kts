import java.util.Properties

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
        val localProperties = Properties()
        val localPropertiesFile = File(settings.rootDir, "local.properties")
        if (localPropertiesFile.isFile) {
            localPropertiesFile.inputStream().use { input ->
                localProperties.load(input)
            }
        }

        val localMavenPath = localProperties.getProperty("local_maven_path")
        if (!localMavenPath.isNullOrBlank()) {
            maven {
                url = uri(localMavenPath)
                println("Using local Maven repository: $url")
            }
        }
        maven(url="https://androidx.dev/snapshots/builds/14144115/artifacts/repository")
    }
}

rootProject.name = "CMWallet"
include(":app")