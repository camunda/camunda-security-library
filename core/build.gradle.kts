plugins {
  id("csl.java-conventions")
  id("com.autonomousapps.dependency-analysis")
}

dependencies {
  api(project(":camunda-security-library-api"))
  implementation(libs.json.path)
  implementation(libs.slf4j.api)

  testImplementation(libs.archunit)
  testImplementation(libs.archunit.junit5.api)
  testRuntimeOnly(libs.archunit.junit5.engine)
  testImplementation(libs.junit.jupiter.api)
  testRuntimeOnly(libs.junit.jupiter.engine)
  testImplementation(libs.assertj.core)
  testImplementation(libs.mockito.core)
  testImplementation(libs.mockito.junit.jupiter)
}
