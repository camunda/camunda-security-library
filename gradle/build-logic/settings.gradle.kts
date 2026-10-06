// Forked from camunda/camunda#52869 (commit 42422bbb6675899f46d494414fc17cfd8177abb0).

rootProject.name = "build-logic"

val rootPom =
  providers.fileContents(layout.settingsDirectory.file("../../pom.xml")).asText.get()
val junitVersion =
  Regex("<junit\\.version>([^<]+)</junit\\.version>")
    .find(rootPom)
    ?.groupValues
    ?.get(1)
    ?: error("Missing junit.version in root pom.xml")

dependencyResolutionManagement {
  versionCatalogs {
    create("libs") {
      version("junit", junitVersion)
      library("junit-bom", "org.junit", "junit-bom").versionRef("junit")
      library("junit-jupiter", "org.junit.jupiter", "junit-jupiter").withoutVersion()
      library("junit-platform-launcher", "org.junit.platform", "junit-platform-launcher")
        .withoutVersion()
    }
  }
}

include("pom-resolution")
