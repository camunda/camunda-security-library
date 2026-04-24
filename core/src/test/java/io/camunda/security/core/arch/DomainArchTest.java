/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.arch;

import static com.tngtech.archunit.base.DescribedPredicate.and;
import static com.tngtech.archunit.core.domain.JavaClass.Predicates.resideInAPackage;
import static com.tngtech.archunit.core.domain.JavaClass.Predicates.resideOutsideOfPackage;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

/**
 * Enforces the hexagonal boundary for the CSL core module: classes in {@code
 * io.camunda.security.core..} must not depend on anything in {@code io.camunda.security.api..} or
 * {@code io.camunda.security.autoconfigure..}, and must not depend on framework runtime types
 * (Spring, Jakarta Servlet, Jakarta Persistence, Jackson runtime).
 *
 * <p>{@code jackson-annotations} ({@code com.fasterxml.jackson.annotation..}) is explicitly
 * permitted — see {@code .claude/docs/guardrails.md}.
 *
 * <p>The import option excludes test classes so this rule only applies to production code in {@code
 * core}.
 */
@AnalyzeClasses(
    packages = "io.camunda.security.core",
    importOptions = ImportOption.DoNotIncludeTests.class)
class DomainArchTest {

  @ArchTest
  static final ArchRule CORE_MUST_NOT_DEPEND_ON_API =
      noClasses()
          .that()
          .resideInAPackage("io.camunda.security.core..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage("io.camunda.security.api..")
          .allowEmptyShould(true);

  @ArchTest
  static final ArchRule CORE_MUST_NOT_DEPEND_ON_STARTER =
      noClasses()
          .that()
          .resideInAPackage("io.camunda.security.core..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage("io.camunda.security.autoconfigure..")
          .allowEmptyShould(true);

  @ArchTest
  static final ArchRule CORE_MUST_NOT_DEPEND_ON_SPRING =
      noClasses()
          .that()
          .resideInAPackage("io.camunda.security.core..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage("org.springframework..")
          .allowEmptyShould(true);

  @ArchTest
  static final ArchRule CORE_MUST_NOT_DEPEND_ON_JAKARTA_SERVLET =
      noClasses()
          .that()
          .resideInAPackage("io.camunda.security.core..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage("jakarta.servlet..")
          .allowEmptyShould(true);

  @ArchTest
  static final ArchRule CORE_MUST_NOT_DEPEND_ON_JAKARTA_PERSISTENCE =
      noClasses()
          .that()
          .resideInAPackage("io.camunda.security.core..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage("jakarta.persistence..")
          .allowEmptyShould(true);

  @ArchTest
  static final ArchRule CORE_MUST_NOT_DEPEND_ON_JACKSON_RUNTIME =
      noClasses()
          .that()
          .resideInAPackage("io.camunda.security.core..")
          .should()
          .dependOnClassesThat(
              and(
                  resideInAPackage("com.fasterxml.jackson.."),
                  resideOutsideOfPackage("com.fasterxml.jackson.annotation..")))
          .allowEmptyShould(true);
}
