/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client.arch;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

/**
 * Keeps the {@code client} module usable on a plain Java thread: classes in {@code
 * io.camunda.security.client..} must not depend on Spring, Jakarta Servlet, or any other CSL
 * module. Full package names are used on purpose: the shorthand {@code ..core..} would also match
 * {@code com.fasterxml.jackson.core}.
 */
@AnalyzeClasses(
    packages = "io.camunda.security.client",
    importOptions = ImportOption.DoNotIncludeTests.class)
class ClientArchTest {

  @ArchTest
  static final ArchRule CLIENT_MUST_NOT_DEPEND_ON_SPRING =
      noClassesDependOn("org.springframework..");

  @ArchTest
  static final ArchRule CLIENT_MUST_NOT_DEPEND_ON_JAKARTA_SERVLET =
      noClassesDependOn("jakarta.servlet..");

  @ArchTest
  static final ArchRule CLIENT_MUST_NOT_DEPEND_ON_API =
      noClassesDependOn("io.camunda.security.api..");

  @ArchTest
  static final ArchRule CLIENT_MUST_NOT_DEPEND_ON_CORE =
      noClassesDependOn("io.camunda.security.core..");

  @ArchTest
  static final ArchRule CLIENT_MUST_NOT_DEPEND_ON_STARTER =
      noClassesDependOn("io.camunda.security.spring..");

  private static ArchRule noClassesDependOn(final String forbiddenPackage) {
    return noClasses()
        .that()
        .resideInAPackage("io.camunda.security.client..")
        .should()
        .dependOnClassesThat()
        .resideInAPackage(forbiddenPackage);
  }
}
