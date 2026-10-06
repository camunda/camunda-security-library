import io.camunda.gradle.rules.PomAlignedLog4jMetadataRule

// Shared Java conventions for all CSL modules. Mirrors what the Maven parent POM configures.

plugins {
  `java-library`
  checkstyle
  id("com.diffplug.spotless")
}

// Precompiled script plugins cannot use the type-safe `libs.` accessors.
val libs = extensions.getByType<VersionCatalogsExtension>().named("libs")

fun lib(alias: String) = libs.findLibrary(alias).get()

fun versionOf(alias: String) = libs.findVersion(alias).get().requiredVersion

tasks.withType<JavaCompile>().configureEach {
  options.release = versionOf("java-release").toInt()
  options.encoding = "UTF-8"
}

tasks.withType<Test>().configureEach { useJUnitPlatform() }

// Equivalent of maven-jar-plugin addDefaultImplementationEntries (Maven uses the POM <name>).
val implementationTitle = project.name
val implementationVersion = project.version.toString()

tasks.jar {
  manifest {
    attributes(
      "Implementation-Title" to implementationTitle,
      "Implementation-Version" to implementationVersion,
    )
  }
}

// Equivalent of Maven <dependencyManagement>: BOM imports plus forced versions for the artifacts
// the parent POM pins. Maven's managed versions always win (even downgrading a transitive), so the
// BOMs are enforced platforms and the pins are `strictly`; a plain platform would only be a lower
// bound under Gradle's highest-wins conflict resolution.
val cslDependencyManagement =
  configurations.create("cslDependencyManagement") {
    isCanBeConsumed = false
    isCanBeResolved = false
  }

listOf("compileClasspath", "runtimeClasspath", "testCompileClasspath", "testRuntimeClasspath")
  .forEach { configurations.named(it) { extendsFrom(cslDependencyManagement) } }

dependencies {
  cslDependencyManagement(enforcedPlatform(lib("spring-boot-dependencies")))
  cslDependencyManagement(enforcedPlatform(lib("testcontainers-bom")))

  constraints {
    listOf(
        "nimbus-jose-jwt" to "nimbus-jose-jwt",
        "commons-validator" to "commons-validator",
        "archunit" to "archunit",
        "archunit-junit5-api" to "archunit",
        "archunit-junit5-engine" to "archunit",
      )
      .forEach { (alias, versionAlias) ->
        val pinned = versionOf(versionAlias)
        // Must be a constraint (not a dependency) so pinned artifacts only apply when pulled in.
        add("cslDependencyManagement", lib(alias).get().module.toString()) {
          version { strictly(pinned) }
        }
      }
  }

  testRuntimeOnly(lib("junit-platform-launcher"))

  // Maven reads the POM, Gradle reads the .module file; align them where they disagree.
  listOf("org.apache.logging.log4j:log4j-api", "org.apache.logging.log4j:log4j-to-slf4j").forEach {
    components.withModule(it, PomAlignedLog4jMetadataRule::class.java) {
      params(
        setOf(
          "org.jspecify:jspecify",
          "biz.aQute.bnd:biz.aQute.bnd.annotation",
          "com.google.errorprone:error_prone_annotations",
          "org.osgi:org.osgi.annotation.bundle",
          "org.osgi:org.osgi.annotation.versioning",
        )
      )
    }
  }
}

// Equivalent of spotless-maven-plugin (Java rules only; the POM-format rules are release hygiene).
val rootDirectory = isolated.rootProject.projectDirectory

spotless {
  java {
    googleJavaFormat(versionOf("google-java-format")).style("GOOGLE")
    licenseHeaderFile(rootDirectory.file("COPYING-HEADER.txt"))
  }
}

// Equivalent of maven-checkstyle-plugin (main and test sources, any violation fails the build).
checkstyle {
  toolVersion = versionOf("checkstyle")
  configFile = rootDirectory.file("config/checkstyle/checkstyle.xml").asFile
  isIgnoreFailures = false
  maxWarnings = 0
  maxErrors = 0
}

// Equivalent of maven-javadoc-plugin verify-javadoc: doclint html,syntax, quiet.
tasks.javadoc {
  options.encoding = "UTF-8"
  (options as StandardJavadocDocletOptions).apply {
    addStringOption("Xdoclint:html,syntax", "-quiet")
  }
}

tasks.check { dependsOn(tasks.javadoc) }

// Equivalent of maven-enforcer dependencyConvergence: fail on conflicting versions of the same
// module instead of silently picking the highest. BOM-managed and pinned versions are enforced
// above, so only genuinely unmanaged conflicts surface.
listOf("compileClasspath", "runtimeClasspath", "testCompileClasspath", "testRuntimeClasspath")
  .forEach { configurations.named(it) { resolutionStrategy.failOnVersionConflict() } }

// Equivalent of maven-dependency-plugin analyze-only: the dependency-analysis plugin is applied by
// each module (version is declared once, at the root), and its per-project check gates `check`.
pluginManager.withPlugin("com.autonomousapps.dependency-analysis") {
  tasks.check { dependsOn("projectHealth") }
}
