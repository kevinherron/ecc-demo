import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinJvmProjectExtension

plugins {
  kotlin("jvm") version "2.3.21" apply false
  id("com.diffplug.spotless") version "8.5.1" apply false
}

group = "com.digitalpetri"

version = "0.1.0-SNAPSHOT"

val miloVersion = "1.1.4-SNAPSHOT"
val bouncycastleVersion = "1.84"
val cliktVersion = "5.1.0"
val mordantVersion = "3.0.2"
val slf4jVersion = "2.0.17"

extra["miloVersion"] = miloVersion

extra["bouncycastleVersion"] = bouncycastleVersion

extra["cliktVersion"] = cliktVersion

extra["mordantVersion"] = mordantVersion

extra["slf4jVersion"] = slf4jVersion

allprojects {
  pluginManager.apply("com.diffplug.spotless")

  extensions.configure<com.diffplug.gradle.spotless.SpotlessExtension> {
    kotlinGradle {
      target("*.gradle.kts")
      ktfmt().metaStyle()
    }
  }
}

subprojects {
  group = rootProject.group
  version = rootProject.version

  pluginManager.apply("org.jetbrains.kotlin.jvm")

  extensions.configure<com.diffplug.gradle.spotless.SpotlessExtension> {
    kotlin {
      target("src/**/*.kt")
      ktfmt().metaStyle()
    }
  }

  extensions.configure<JavaPluginExtension> {
    toolchain { languageVersion.set(JavaLanguageVersion.of(25)) }
  }

  extensions.configure<KotlinJvmProjectExtension> {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_25) }
  }

  tasks.withType<JavaCompile>().configureEach { options.release.set(25) }
}
