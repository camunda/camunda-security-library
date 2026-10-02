plugins {
  id("csl.java-conventions")
  id("com.autonomousapps.dependency-analysis")
}

dependencies {
  api(project(":camunda-security-library-api"))
  api(project(":camunda-security-library-core"))
  api(libs.spring.boot)
  api(libs.spring.boot.autoconfigure)
  api(libs.spring.context)
  // Runtime activation of Hibernate Validator so @Validated on @ConfigurationProperties classes
  // enforces constraints at startup. No source reference.
  api(libs.spring.boot.starter.validation)
  api(libs.spring.session.core)
  api(libs.spring.security.config)
  api(libs.spring.security.web)
  api(libs.spring.security.core)
  // PasswordEncoder / PasswordEncoderFactories for the basic-auth UserDetailsService
  api(libs.spring.security.crypto)
  api(libs.spring.security.oauth2.client)
  api(libs.spring.security.oauth2.core)
  implementation(libs.spring.security.oauth2.resource.server)
  api(libs.spring.security.oauth2.jose)
  // Nimbus JOSE+JWT is referenced directly by CompositeJWKSource and the composite JwtDecoder
  // path; version pinned in the root POM.
  api(libs.nimbus.jose.jwt)
  api(libs.spring.web)
  api(libs.spring.core)
  api(libs.spring.beans)
  // Maven scope "provided".
  compileOnly(libs.jakarta.servlet.api)
  testImplementation(libs.jakarta.servlet.api)
  api(libs.jakarta.annotation.api)
  implementation(libs.jackson.core)
  api(libs.jackson.databind)
  // Backing cache for CachingOidcClaimsProvider.
  implementation(libs.caffeine)
  api(libs.micrometer.core)
  implementation(libs.slf4j.api)

  testImplementation(libs.spring.boot.test)
  testImplementation(libs.junit.jupiter.api)
  testRuntimeOnly(libs.junit.jupiter.engine)
  testImplementation(libs.junit.jupiter.params)
  testImplementation(libs.assertj.core)
  testImplementation(libs.spring.test)
  testImplementation(libs.mockito.core)
  testImplementation(libs.mockito.junit.jupiter)
  testImplementation(libs.logback.classic)
  testImplementation(libs.logback.core)
}

// Mirrors Maven ignoredUnusedDeclaredDependencies: runtime activation of Hibernate Validator, no
// source reference.
dependencyAnalysis {
  issues {
    onUnusedDependencies { exclude(libs.spring.boot.starter.validation) }
  }
}
