/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring;

import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition;
import org.jspecify.annotations.NullMarked;

/**
 * Enforces the nullness convention of ADR-0035: every production package of the {@code
 * spring-boot-starter} module carries {@code @NullMarked}. JSpecify's {@code @NullMarked} does not
 * cascade to subpackages, so each package needs its own {@code package-info.java}.
 */
@AnalyzeClasses(
    packages = "io.camunda.security.spring",
    importOptions = ImportOption.DoNotIncludeTests.class)
class NullMarkedArchTest {

  @ArchTest
  static final ArchRule PRODUCTION_PACKAGES_MUST_BE_NULL_MARKED =
      ArchRuleDefinition.classes().should(resideInNullMarkedPackage()).allowEmptyShould(true);

  private static ArchCondition<JavaClass> resideInNullMarkedPackage() {
    return new ArchCondition<>("reside in a package annotated with @NullMarked") {
      @Override
      public void check(final JavaClass javaClass, final ConditionEvents events) {
        if (!javaClass.getPackage().isAnnotatedWith(NullMarked.class)) {
          events.add(
              SimpleConditionEvent.violated(
                  javaClass,
                  "package "
                      + javaClass.getPackageName()
                      + " of "
                      + javaClass.getName()
                      + " is not annotated with @NullMarked (add a package-info.java)"));
        }
      }
    };
  }
}
