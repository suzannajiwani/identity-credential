import org.jetbrains.dokka.gradle.DokkaMultiModuleTask

plugins {
    id("org.jetbrains.dokka") version "1.9.0" apply false

    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlinx.serialization.plugin) apply false
    alias(libs.plugins.sonarqube) apply false
    alias(libs.plugins.jacoco) apply false
    alias(libs.plugins.navigation.safe.args) apply false
    alias(libs.plugins.kapt) apply false
    alias(libs.plugins.parcelable) apply false
}

// The versioning plugin must be applied in all submodules
subprojects {
    repositories {
        mavenCentral()
    }
    apply {
//        plugin("org.jetbrains.kotlin.jvm")
        plugin("org.jetbrains.dokka")
    }
    val dokkaPlugin by configurations
    dependencies {
        dokkaPlugin("org.jetbrains.dokka:versioning-plugin:1.9.0")
    }
}

val currentVersion = "1.0"
val previousVersionsDirectory = project.rootProject.projectDir.resolve("build/older_versions_dir").invariantSeparatorsPath

tasks.dokkaHtmlMultiModule {
    pluginConfiguration<org.jetbrains.dokka.versioning.VersioningPlugin, org.jetbrains.dokka.versioning.VersioningConfiguration> {
        version = currentVersion
        olderVersionsDir = file(previousVersionsDirectory)
    }
}