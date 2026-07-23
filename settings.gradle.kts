@file:Suppress("UnstableApiUsage")

pluginManagement {
  repositories {
    gradlePluginPortal()
    mavenCentral()
  }
}

dependencyResolutionManagement {
  repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
  repositories {
    maven {
      name = "SonatypeSnapshots"
      url = uri("https://central.sonatype.com/repository/maven-snapshots/")
      mavenContent { snapshotsOnly() }
    }
    mavenCentral()
  }
}

rootProject.name = "ecc-demo"

include("server")

include("client")
