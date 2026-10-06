plugins {
  id("csl.java-conventions")
  id("com.autonomousapps.dependency-analysis")
}

dependencies {
  api(project(":camunda-security-library-api"))
  implementation(libs.commons.validator)

  testImplementation(libs.junit.jupiter.api)
  testRuntimeOnly(libs.junit.jupiter.engine)
  testImplementation(libs.junit.jupiter.params)
  testImplementation(libs.assertj.core)
}
