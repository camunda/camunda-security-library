// Forked from camunda/camunda#52869 (commit 42422bbb6675899f46d494414fc17cfd8177abb0).

plugins {
  `kotlin-dsl`
}

group = "io.camunda.gradle"

repositories {
  mavenCentral()
}

dependencies {
  testImplementation(platform(libs.junit.bom))
  testImplementation(libs.junit.jupiter)
  testRuntimeOnly(libs.junit.platform.launcher)
}

tasks.test {
  useJUnitPlatform()
}
