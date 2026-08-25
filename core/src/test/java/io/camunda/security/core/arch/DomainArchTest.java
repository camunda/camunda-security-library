/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.arch;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

/**
 * Enforces the hexagonal boundary for the CSL core module: classes in {@code
 * io.camunda.security.core..} must not depend on anything in {@code io.camunda.security.spring..},
 * and must not depend on framework types (Spring, Jakarta Servlet, Jakarta Persistence, Jackson —
 * including {@code jackson-annotations} — or zeebe-protocol).
 *
 * <p>{@code core} is permitted to depend on {@code io.camunda.security.api..}: the public model
 * records (e.g. {@code CamundaAuthentication}) live in {@code api/model/}, and {@code core} ports
 * speak those domain types per the architecture doc.
 *
 * <p>Domain records stay Jackson-free; hosts that need custom JSON shape for a CSL type register a
 * Jackson mixin on their own {@code ObjectMapper} (see {@code .claude/docs/guardrails.md} and
 * ADR-0017).
 *
 * <p>The import option excludes test classes so this rule only applies to production code in {@code
 * core}.
 */
@AnalyzeClasses(
    packages = "io.camunda.security.core",
    importOptions = ImportOption.DoNotIncludeTests.class)
class DomainArchTest {

  @ArchTest
  static final ArchRule CORE_MUST_NOT_DEPEND_ON_STARTER =
      noClasses()
          .that()
          .resideInAPackage("io.camunda.security.core..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage("io.camunda.security.spring..")
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
  static final ArchRule CORE_MUST_NOT_DEPEND_ON_JACKSON =
      noClasses()
          .that()
          .resideInAPackage("io.camunda.security.core..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage("com.fasterxml.jackson..")
          .allowEmptyShould(true);

  @ArchTest
  static final ArchRule CORE_MUST_NOT_DEPEND_ON_ZEEBE_PROTOCOL =
      noClasses()
          .that()
          .resideInAPackage("io.camunda.security.core..")
          .should()
          .dependOnClassesThat()
          .resideInAPackage("io.camunda.zeebe.protocol..")
          .allowEmptyShould(true);
}
