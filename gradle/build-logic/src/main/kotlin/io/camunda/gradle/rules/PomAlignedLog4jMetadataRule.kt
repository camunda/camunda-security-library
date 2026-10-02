package io.camunda.gradle.rules

import javax.inject.Inject
import org.gradle.api.artifacts.CacheableRule
import org.gradle.api.artifacts.ComponentMetadataContext
import org.gradle.api.artifacts.ComponentMetadataRule

/**
 * Aligns the Gradle module metadata of Log4j artifacts with the POM that Maven reads.
 *
 * Maven is the source of truth for dependency resolution (ADR-0034). The Log4j POMs declare their
 * annotation-only artifacts (jspecify, OSGi, bnd, error_prone_annotations) as `provided`/optional
 * or not at all, so Maven never resolves them transitively. The Gradle `.module` files, however,
 * publish them as `apiElements` dependencies. Gradle then sees them, at versions that clash with
 * other modules (for example error_prone_annotations 2.38.0 versus 2.49.0 from caffeine), which
 * Maven's `dependencyConvergence` never sees.
 *
 * The rule removes exactly the given `group:module` dependencies from every variant. It names no
 * versions, so it stays valid across Log4j upgrades. Real dependencies (for example log4j-api or
 * slf4j-api of log4j-to-slf4j) are untouched.
 */
@CacheableRule
abstract class PomAlignedLog4jMetadataRule @Inject constructor(private val dropped: Set<String>) :
  ComponentMetadataRule {
  override fun execute(context: ComponentMetadataContext) {
    context.details.allVariants {
      withDependencies { removeAll { "${it.group}:${it.name}" in dropped } }
    }
  }
}
