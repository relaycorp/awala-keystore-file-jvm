import org.gradle.internal.os.OperatingSystem
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

group = "tech.relaycorp"

plugins {
    // Apply the Kotlin JVM plugin to add support for Kotlin.
    id("org.jetbrains.kotlin.jvm") version "1.9.0"

    // Apply the java-library plugin for API and implementation separation.
    `java-library`

    id("org.jlleitschuh.gradle.ktlint") version "11.5.0"

    jacoco

    signing
    `maven-publish`
    id("io.github.gradle-nexus.publish-plugin") version "1.3.0"
}

repositories {
    mavenCentral()
}

dependencies {
    val kotlinCoroutinesVersion = "1.7.2"

    // Align versions of all Kotlin components
    implementation(platform("org.jetbrains.kotlin:kotlin-bom"))

    api("tech.relaycorp:awala:[1.66.4,2.0.0)")
    testImplementation("tech.relaycorp:awala-testing:1.5.13")

    implementation("org.mongodb:bson:4.10.2")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:$kotlinCoroutinesVersion")
    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("org.junit.jupiter:junit-jupiter:5.9.3")
    testImplementation("org.junit.jupiter:junit-jupiter-params:5.9.3")
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:$kotlinCoroutinesVersion")
}

java {
    withJavadocJar()
    withSourcesJar()
}

kotlin {
    explicitApi()
}

jacoco {
    toolVersion = "0.8.8"
}

tasks.jacocoTestReport {
    reports {
        xml.required.set(true)
        html.required.set(true)
        html.outputLocation.set(file("$buildDir/reports/coverage"))
    }
}

tasks.jacocoTestCoverageVerification {
    violationRules {
        rule {
            limit {
                counter = "CLASS"
                value = "MISSEDCOUNT"
                maximum = 0.toBigDecimal()
            }
            limit {
                counter = "METHOD"
                value = "MISSEDCOUNT"
                maximum = 1.toBigDecimal()
            }

            limit {
                counter = "BRANCH"
                value = "MISSEDCOUNT"

                // Filesystem readability/writability checks don't work on Windows
                maximum = (if (OperatingSystem.current().isWindows) 13 else 1).toBigDecimal()
            }
        }
    }
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
    }
    finalizedBy("jacocoTestReport")
    doLast {
        println("View code coverage at:")
        println("file://$buildDir/reports/coverage/index.html")
    }
}

tasks.withType<KotlinCompile>().configureEach {
    kotlinOptions {
        jvmTarget = "1.8"
        allWarningsAsErrors = true
        freeCompilerArgs = freeCompilerArgs + arrayOf(
            "-opt-in=kotlin.RequiresOptIn"
        )
    }
}

signing {
    useGpgCmd()
    setRequired {
        gradle.taskGraph.allTasks.any { it is PublishToMavenRepository }
    }
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications)
}
publishing {
    publications {
        create<MavenPublication>("default") {
            from(components["java"])

            pom {
                name.set(rootProject.name)
                description.set(
                    "JVM implementation of file-based Private and Public Key Stores for Awala"
                )
                url.set("https://github.com/relaycorp/awala-keystore-file-jvm")
                developers {
                    developer {
                        id.set("relaycorp")
                        name.set("Relaycorp, Inc.")
                        email.set("no-reply@relaycorp.tech")
                    }
                }
                licenses {
                    license {
                        name.set("Apache-2.0")
                    }
                }
                scm {
                    connection.set(
                        "scm:git:https://github.com/relaycorp/awala-keystore-file-jvm.git"
                    )
                    developerConnection.set(
                        "scm:git:https://github.com/relaycorp/awala-keystore-file-jvm.git"
                    )
                    url.set("https://github.com/relaycorp/awala-keystore-file-jvm")
                }
            }
        }
    }
    repositories {
        maven {
            url = uri("https://s01.oss.sonatype.org/service/local/staging/deploy/maven2/")
            credentials {
                username = System.getenv("MAVEN_USERNAME")
                password = System.getenv("MAVEN_PASSWORD")
            }
        }
    }
}
nexusPublishing {
    repositories {
        sonatype {
            nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
            snapshotRepositoryUrl.set(
                uri("https://s01.oss.sonatype.org/content/repositories/snapshots/")
            )
            username.set(System.getenv("MAVEN_USERNAME"))
            password.set(System.getenv("MAVEN_PASSWORD"))
        }
    }
}
tasks.publish {
    finalizedBy("closeAndReleaseSonatypeStagingRepository")
}

configure<org.jlleitschuh.gradle.ktlint.KtlintExtension> {
    version.set("0.42.1")
}

gradleEnterprise {
    buildScan {
        termsOfServiceUrl = "https://gradle.com/terms-of-service"
        termsOfServiceAgree = "yes"
    }
}
