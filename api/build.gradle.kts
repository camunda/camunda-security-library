plugins {
  id("csl.java-conventions")
  id("com.autonomousapps.dependency-analysis")
}

dependencies {
  testImplementation(libs.junit.jupiter.api)
  testRuntimeOnly(libs.junit.jupiter.engine)
  testImplementation(libs.junit.jupiter.params)
  testImplementation(libs.assertj.core)
  testImplementation(libs.archunit)
  testImplementation(libs.archunit.junit5.api)
  testRuntimeOnly(libs.archunit.junit5.engine)
}
