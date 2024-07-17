import com.google.cloud.tools.gradle.appengine.standard.AppEngineStandardExtension

buildscript {      // Configuration for building
    dependencies {
        classpath("com.google.cloud.tools:appengine-gradle-plugin:2.8.1")
        classpath("org.gretty:gretty:4.1.5")
    }
}

plugins {
    alias(libs.plugins.gretty)
    id("war")
    id("java-library")
    id("org.jetbrains.kotlin.jvm")
    id("maven-publish")
    alias(libs.plugins.ksp)
}

apply(plugin = "com.google.cloud.tools.appengine-appenginewebxml")


kotlin {
    jvmToolchain(17)
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    ksp(project(":processor"))
    implementation(project(":identity"))
    implementation(project(":identity-flow"))
    implementation(project(":processor-annotations"))
    implementation(project(":identity-issuance"))

    implementation(libs.javax.servlet.api)
    implementation(libs.kotlinx.datetime)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.kotlinx.io.bytestring)
    implementation(libs.bouncy.castle.bcprov)
    implementation(libs.hsqldb)
    implementation(libs.mysql)
    implementation(libs.ktor.client.core)
    implementation(libs.ktor.client.java)

    implementation("com.zaxxer:HikariCP:5.1.0")
    implementation("com.google.cloud:google-cloud-storage")
    implementation(platform("com.google.cloud:libraries-bom:26.22.0"))
    implementation("com.google.appengine:appengine-api-1.0-sdk:2.0.4")
    providedCompile("com.google.appengine:appengine:+")
    implementation("com.google.cloud.sql:mysql-socket-factory-connector-j-8:1.19.1")
    implementation("com.google.apis:google-api-services-sqladmin:v1-rev20240711-2.0.0")
    implementation("com.google.cloud:google-cloud-secretmanager:2.47.0")
    testImplementation(libs.junit)
}

configure<AppEngineStandardExtension> {
    deploy {
        projectId = "mdoc-reader-external"
        version = "v1"
        stopPreviousVersion = true
        promote = true
    }
}

gretty {}
