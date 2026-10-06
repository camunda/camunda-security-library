// Forked from camunda/camunda#52869 (commit 42422bbb6675899f46d494414fc17cfd8177abb0).

plugins {
  `base`
  `kotlin-dsl`
}

repositories {
  mavenCentral()
  gradlePluginPortal()
}

gradlePlugin {
  plugins {
    create("settingsPomResolver") {
      id = "io.camunda.gradle.settings-pom-resolver"
      implementationClass = "io.camunda.gradle.pom.SettingsPomResolverPlugin"
    }
  }
}

dependencies {
  implementation(project(":pom-resolution"))
  implementation("com.diffplug.spotless:spotless-plugin-gradle:8.10.3")
}
