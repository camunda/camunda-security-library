// Parallel Gradle build. Maven (pom.xml) remains the source of truth: all versions are read from
// the root POM here. See ADR-0034.
import io.camunda.gradle.pom.SettingsPomResolver

pluginManagement { includeBuild("gradle/build-logic") }

plugins { id("io.camunda.gradle.settings-pom-resolver") }

val settingsPomResolver = extensions.getByType(SettingsPomResolver::class.java)

val pomProperties: Map<String, String> = settingsPomResolver.propertiesForPom("pom.xml")

// Resolve per key: some POM properties (e.g. license.header.file) are unresolvable in Gradle.
fun pomVersion(key: String) = settingsPomResolver.resolveProperty(key, pomProperties)

rootProject.name = "camunda-security-library"

// Each project owns its version; capture plain Strings so the callback is configuration-cache safe.
settingsPomResolver.projectVersionForPom("pom.xml").let { versionFromMaven ->
  gradle.lifecycle.beforeProject {
    group = "io.camunda"
    version = versionFromMaven
  }
}

dependencyResolutionManagement {
  repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS

  repositories { mavenCentral() }

  versionCatalogs {
    create("libs") {
      version("java-release", pomVersion("maven.compiler.release"))
      version("spring-boot", pomVersion("spring-boot.version"))
      version("testcontainers", pomVersion("testcontainers.version"))
      version("archunit", pomVersion("archunit.version"))
      version("nimbus-jose-jwt", pomVersion("nimbus-jose-jwt.version"))
      version("commons-validator", pomVersion("commons-validator.version"))
      // Used by the later formatting/lint tasks.
      version("google-java-format", pomVersion("plugin.version.google-java-format"))
      version("checkstyle", pomVersion("version.checkstyle"))

      // BOMs
      library("spring-boot-dependencies", "org.springframework.boot", "spring-boot-dependencies")
        .versionRef("spring-boot")
      library("testcontainers-bom", "org.testcontainers", "testcontainers-bom")
        .versionRef("testcontainers")

      // Versions pinned in the root POM's dependencyManagement
      library("archunit", "com.tngtech.archunit", "archunit").versionRef("archunit")
      library("archunit-junit5-api", "com.tngtech.archunit", "archunit-junit5-api")
        .versionRef("archunit")
      library("archunit-junit5-engine", "com.tngtech.archunit", "archunit-junit5-engine")
        .versionRef("archunit")
      library("nimbus-jose-jwt", "com.nimbusds", "nimbus-jose-jwt").versionRef("nimbus-jose-jwt")
      library("commons-validator", "commons-validator", "commons-validator")
        .versionRef("commons-validator")

      // Versions managed by the BOMs
      library("json-path", "com.jayway.jsonpath", "json-path").withoutVersion()
      library("slf4j-api", "org.slf4j", "slf4j-api").withoutVersion()
      library("spring-boot", "org.springframework.boot", "spring-boot").withoutVersion()
      library("spring-boot-autoconfigure", "org.springframework.boot", "spring-boot-autoconfigure")
        .withoutVersion()
      library("spring-boot-starter-validation", "org.springframework.boot", "spring-boot-starter-validation")
        .withoutVersion()
      library("spring-boot-test", "org.springframework.boot", "spring-boot-test").withoutVersion()
      library("spring-context", "org.springframework", "spring-context").withoutVersion()
      library("spring-web", "org.springframework", "spring-web").withoutVersion()
      library("spring-core", "org.springframework", "spring-core").withoutVersion()
      library("spring-beans", "org.springframework", "spring-beans").withoutVersion()
      library("spring-test", "org.springframework", "spring-test").withoutVersion()
      library("spring-session-core", "org.springframework.session", "spring-session-core")
        .withoutVersion()
      library("spring-security-config", "org.springframework.security", "spring-security-config")
        .withoutVersion()
      library("spring-security-web", "org.springframework.security", "spring-security-web")
        .withoutVersion()
      library("spring-security-core", "org.springframework.security", "spring-security-core")
        .withoutVersion()
      library("spring-security-crypto", "org.springframework.security", "spring-security-crypto")
        .withoutVersion()
      library(
          "spring-security-oauth2-client",
          "org.springframework.security",
          "spring-security-oauth2-client",
        )
        .withoutVersion()
      library(
          "spring-security-oauth2-core",
          "org.springframework.security",
          "spring-security-oauth2-core",
        )
        .withoutVersion()
      library(
          "spring-security-oauth2-resource-server",
          "org.springframework.security",
          "spring-security-oauth2-resource-server",
        )
        .withoutVersion()
      library(
          "spring-security-oauth2-jose",
          "org.springframework.security",
          "spring-security-oauth2-jose",
        )
        .withoutVersion()
      library("jakarta-servlet-api", "jakarta.servlet", "jakarta.servlet-api").withoutVersion()
      library("jakarta-annotation-api", "jakarta.annotation", "jakarta.annotation-api")
        .withoutVersion()
      library("jackson-core", "com.fasterxml.jackson.core", "jackson-core").withoutVersion()
      library("jackson-databind", "com.fasterxml.jackson.core", "jackson-databind")
        .withoutVersion()
      library("caffeine", "com.github.ben-manes.caffeine", "caffeine").withoutVersion()
      library("micrometer-core", "io.micrometer", "micrometer-core").withoutVersion()
      library("junit-jupiter-api", "org.junit.jupiter", "junit-jupiter-api").withoutVersion()
      library("junit-jupiter-engine", "org.junit.jupiter", "junit-jupiter-engine").withoutVersion()
      library("junit-jupiter-params", "org.junit.jupiter", "junit-jupiter-params").withoutVersion()
      library("junit-platform-launcher", "org.junit.platform", "junit-platform-launcher")
        .withoutVersion()
      library("assertj-core", "org.assertj", "assertj-core").withoutVersion()
      library("mockito-core", "org.mockito", "mockito-core").withoutVersion()
      library("mockito-junit-jupiter", "org.mockito", "mockito-junit-jupiter").withoutVersion()
      library("logback-classic", "ch.qos.logback", "logback-classic").withoutVersion()
      library("logback-core", "ch.qos.logback", "logback-core").withoutVersion()
    }
  }
}

// Gradle project names equal the Maven artifactIds.
fun registerProject(name: String, directory: String) {
  include(name)
  project(":$name").projectDir = file(directory)
}

registerProject("camunda-security-library-api", "api")

registerProject("camunda-security-library-core", "core")

registerProject("camunda-security-library-validation", "validation")

registerProject("camunda-security-library-spring-boot-starter", "spring-boot-starter")
