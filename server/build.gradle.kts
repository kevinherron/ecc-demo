plugins {
  application
  id("com.gradleup.shadow") version "9.4.1"
}

val miloVersion: String by rootProject.extra
val bouncycastleVersion: String by rootProject.extra
val cliktVersion: String by rootProject.extra
val mordantVersion: String by rootProject.extra
val slf4jVersion: String by rootProject.extra

dependencies {
  implementation("org.eclipse.milo:milo-sdk-server:$miloVersion")
  implementation("org.eclipse.milo:milo-dtd-core:$miloVersion")
  implementation("org.eclipse.milo:milo-dtd-manager:$miloVersion")
  implementation("org.bouncycastle:bcprov-jdk18on:$bouncycastleVersion")
  implementation("org.slf4j:slf4j-simple:$slf4jVersion")
  implementation("com.github.ajalt.clikt:clikt:$cliktVersion")
  implementation("com.github.ajalt.mordant:mordant:$mordantVersion")
}

application {
  mainClass.set("com.digitalpetri.opcua.ecc.server.ServerMainKt")
  applicationDefaultJvmArgs =
      listOf(
          "--enable-native-access=ALL-UNNAMED",
          "--sun-misc-unsafe-memory-access=allow",
          "-Dorg.slf4j.simpleLogger.defaultLogLevel=warn",
      )
}

tasks.named<com.github.jengelman.gradle.plugins.shadow.tasks.ShadowJar>("shadowJar") {
  archiveBaseName.set("ecc-demo-server")
  archiveClassifier.set("all")
  exclude("META-INF/*.DSA", "META-INF/*.RSA", "META-INF/*.SF")
  manifest { attributes("Main-Class" to application.mainClass.get()) }
}
