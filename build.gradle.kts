plugins {
    kotlin("jvm") version "2.2.0"
    application
    kotlin("plugin.serialization") version "2.2.0" apply false
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "com.nickcoblentz"
version = "0.1"

repositories {
    mavenCentral()
    maven(url="https://jitpack.io") {
        content {
            includeGroup("com.github.ncoblentz")
        }
    }


}

dependencies {
    implementation("com.github.ajalt.clikt:clikt:5.0.3")
    // optional support for rendering markdown in help messages
    implementation("com.github.ajalt.clikt:clikt-markdown:5.0.3")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")
    implementation("com.github.ajalt.mordant:mordant:3.0.2")
    implementation("com.github.ajalt.mordant:mordant-coroutines:3.0.2")
    implementation("com.github.ajalt.mordant:mordant-markdown:3.0.2")
    implementation("com.jsoizo:kotlin-csv-jvm:1.10.0")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.19.1")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.19.1")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-csv:2.19.1")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:2.19.1")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.19.1")
    implementation("com.github.ncoblentz:PentestLibrary:v0.1.3")
    implementation("aws.sdk.kotlin:iam:1.4.109")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("aws.sdk.kotlin:lambda:1.4.109")
    implementation("io.ktor:ktor-client-cio:3.2.0")
}


application {
    mainClass.set("com.nickcoblentz.aws.CLIKt")
}

tasks {
    jar {
        manifest {
            attributes["Main-Class"] = "com.nickcoblentz.aws.CLIKt"
        }
    }
}

kotlin {
    jvmToolchain(21)
}