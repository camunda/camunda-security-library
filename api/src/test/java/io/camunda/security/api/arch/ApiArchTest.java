/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.arch;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

/**
 * Enforces the framework-free boundary for the CSL api module: classes in {@code
 * io.camunda.security.api..} carry the public, host-facing surface and must not depend on {@code
 * io.camunda.security.core..}, {@code io.camunda.security.spring..}, or framework types (Spring,
 * Jakarta Servlet, Jakarta Persistence, Jackson — including {@code jackson-annotations} — or
 * zeebe-protocol).
 *
 * <p>This is the api-side mirror of {@code DomainArchTest} on {@code core}: keeping {@code api}
 * free of frameworks lets adopters consume the public types without pulling Spring or other runtime
 * dependencies into their classpath.
 *
 * <p>Domain records stay Jackson-free; hosts that need custom JSON shape for a CSL type register a
 * Jackson mixin on their own {@code ObjectMapper} (see {@code .claude/docs/guardrails.md} and
 * ADR-0028).
 *
 * <p>The import option excludes test classes so this rule only applies to production code in {@code
 * api}.
 */
@AnalyzeClasses(
    packages = "io.camunda.security.api",
    importOptions = ImportOption.DoNotIncludeTests.class)
class ApiArchTest {

  @ArchTest
  static final ArchRule API_MUST_NOT_DEPEND_ON_CORE =
      noClasses()
          .that()
          .resideInAPackage("io.camunda.security.api..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage("io.camunda.security.core..")
          .allowEmptyShould(true);

  @ArchTest
  static final ArchRule API_MUST_NOT_DEPEND_ON_STARTER =
      noClasses()
          .that()
          .resideInAPackage("io.camunda.security.api..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage("io.camunda.security.spring..")
          .allowEmptyShould(true);

  @ArchTest
  static final ArchRule API_MUST_NOT_DEPEND_ON_SPRING =
      noClasses()
          .that()
          .resideInAPackage("io.camunda.security.api..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage("org.springframework..")
          .allowEmptyShould(true);

  @ArchTest
  static final ArchRule API_MUST_NOT_DEPEND_ON_JAKARTA_SERVLET =
      noClasses()
          .that()
          .resideInAPackage("io.camunda.security.api..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage("jakarta.servlet..")
          .allowEmptyShould(true);

  @ArchTest
  static final ArchRule API_MUST_NOT_DEPEND_ON_JAKARTA_PERSISTENCE =
      noClasses()
          .that()
          .resideInAPackage("io.camunda.security.api..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage("jakarta.persistence..")
          .allowEmptyShould(true);

  @ArchTest
  static final ArchRule API_MUST_NOT_DEPEND_ON_JACKSON =
      noClasses()
          .that()
          .resideInAPackage("io.camunda.security.api..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage("com.fasterxml.jackson..")
          .allowEmptyShould(true);

  @ArchTest
  static final ArchRule API_MUST_NOT_DEPEND_ON_ZEEBE_PROTOCOL =
      noClasses()
          .that()
          .resideInAPackage("io.camunda.security.api..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage("io.camunda.zeebe.protocol..")
          .allowEmptyShould(true);
}
