rootProject.name = "IdentityCredential"
enableFeaturePreview("TYPESAFE_PROJECT_ACCESSORS")

pluginManagement {
    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
    resolutionStrategy {
        eachPlugin {
            if (requested.id.id.startsWith("com.google.cloud.tools.appengine")) {
                useModule("com.google.cloud.tools:appengine-gradle-plugin:${requested.version}")
            }
        }
    }
}

dependencyResolutionManagement {
    repositories {
        google {
            mavenContent {
                includeGroupAndSubgroups("androidx")
                includeGroupAndSubgroups("com.android")
                includeGroupAndSubgroups("com.google")
            }
        }
        mavenCentral()
        jcenter() {
            content {
                includeGroup("com.budiyev.android")
            }
        }
    }
}

include(":processor")
include(":processor-annotations")
include(":identity")
include(":identity:SwiftBridge")
include(":identity-flow")
include(":identity-mdoc")
include(":identity-sdjwt")
include(":identity-doctypes")
include(":identity-android")
include(":identity-android-legacy")
include(":identity-issuance")
include(":identity-appsupport")
include(":identityctl")
include(":mrtd-reader")
include(":mrtd-reader-android")
include(":jpeg2k")
include(":samples:testapp")
include(":samples:preconsent-mdl")
include(":samples:age-verifier-mdl")
include(":samples:simple-verifier")
include(":wallet")
include(":server")
include(":appverifier")
include(":appholder")
