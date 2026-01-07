plugins {
    id("com.android.library")
    id("maven-publish")
}

val publishVersion = System.getenv("VERSION") ?: "0.0.0-ci"

group = "com.ecliptix.protocol"
version = publishVersion

android {
    namespace = "com.ecliptix.protocol"
    compileSdk = 34

    defaultConfig {
        minSdk = 34
        consumerProguardFiles("consumer-rules.pro")
    }

    sourceSets {
        getByName("main").jniLibs.srcDirs("src/main/jniLibs")
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

publishing {
    publications {
        create<MavenPublication>("release") {
            groupId = project.group.toString()
            artifactId = "ecliptix-protocol"
            version = project.version.toString()
            afterEvaluate {
                from(components["release"])
            }
        }
    }
    repositories {
        maven {
            name = "GitHubPackages"
            val repo = System.getenv("GITHUB_REPOSITORY")
                ?: "oleksandrmelnychenko/Ecliptix.Protected.Protocol"
            url = uri("https://maven.pkg.github.com/$repo")
            credentials {
                username = System.getenv("GITHUB_ACTOR")
                password = System.getenv("GITHUB_TOKEN")
            }
        }
    }
}
