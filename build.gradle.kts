// The root project has no sources: Java conventions live in gradle/build-logic and the module build
// files. Versions come from pom.xml via settings.gradle.kts. The dependency-analysis plugin version
// is declared once here; modules apply it without a version.
plugins { id("com.autonomousapps.dependency-analysis") version "3.19.2" }

// Equivalent of maven-dependency-plugin analyze-only with failOnWarning: unused declared and used
// undeclared dependencies fail the build. Incorrect-configuration advice also fails: it catches a
// compile-scope dependency used only by tests (Maven: "Non-test scoped test only dependencies") and
// keeps `api` limited to dependencies whose types appear in a module's public API.
dependencyAnalysis {
  issues {
    all {
      onUnusedDependencies { severity("fail") }
      onUsedTransitiveDependencies { severity("fail") }
      onIncorrectConfiguration { severity("fail") }
      onCompileOnly { severity("ignore") }
      onRuntimeOnly { severity("ignore") }
      onUnusedAnnotationProcessors { severity("fail") }
    }
  }
}
