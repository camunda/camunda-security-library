/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.arch;

import static com.tngtech.archunit.lang.SimpleConditionEvent.violated;

import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaField;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition;
import java.lang.reflect.Constructor;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * ArchUnit rules for records under {@code io.camunda.security.api.model.user..}.
 *
 * <p>Records exposed on the CSL public surface must default collection-typed components to non-null
 * empty instances in their compact constructor so adopters can call {@code .stream()} / {@code
 * .isEmpty()} on the getters without null-checking. Immutable defaults (e.g. {@code List.of()},
 * {@code Map.of()}) are acceptable — readers are not expected to mutate the returned collections.
 *
 * <p>The rule is intentionally narrow (one package) and fails on an empty match so that removing
 * the only record in the package is caught: the safeguard is dead weight without classes to check,
 * and silently passing would hide a regression the next time a DTO is added back. This mirrors the
 * equivalent rule that previously lived in the Orchestration Cluster repo's {@code
 * SearchEntityArchTest} prior to the Inc-13 migration of {@code CamundaUserDTO} into CSL.
 */
@AnalyzeClasses(
    packages = "io.camunda.security.api.model.user",
    importOptions = ImportOption.DoNotIncludeTests.class)
final class UserModelRecordsArchTest {

  @ArchTest
  static final ArchRule USER_MODEL_RECORDS_DEFAULT_COLLECTIONS_TO_NON_NULL =
      ArchRuleDefinition.classes()
          .that()
          .resideInAPackage("io.camunda.security.api.model.user..")
          .and()
          .areRecords()
          .should(
              new ArchCondition<>(
                  "initialize collection-type fields with non-null defaults in a compact"
                      + " constructor") {
                @Override
                public void check(final JavaClass item, final ConditionEvents events) {
                  final var collectionFields =
                      item.getFields().stream()
                          .filter(UserModelRecordsArchTest::isCollectionField)
                          .toList();

                  if (collectionFields.isEmpty()) {
                    return;
                  }

                  final Object instance;
                  try {
                    instance = instantiateRecordWithNulls(item);
                  } catch (final Exception e) {
                    events.add(
                        violated(
                            item,
                            String.format(
                                "Record '%s': could not reflectively instantiate to verify "
                                    + "collection defaults: %s",
                                item.getSimpleName(), e.getMessage())));
                    return;
                  }

                  for (final JavaField field : collectionFields) {
                    try {
                      final var reflectField =
                          instance.getClass().getDeclaredField(field.getName());
                      reflectField.setAccessible(true);
                      final Object value = reflectField.get(instance);

                      if (value == null) {
                        events.add(
                            violated(
                                item,
                                String.format(
                                    "Record '%s': collection field '%s' (type %s) is null when "
                                        + "constructed with null — add a compact constructor that "
                                        + "assigns an empty default "
                                        + "(e.g. List.of(), Map.of(), new ArrayList<>())",
                                    item.getSimpleName(),
                                    field.getName(),
                                    field.getRawType().getSimpleName())));
                      }
                    } catch (final NoSuchFieldException | IllegalAccessException e) {
                      events.add(
                          violated(
                              item,
                              String.format(
                                  "Record '%s': could not read field '%s': %s",
                                  item.getSimpleName(), field.getName(), e.getMessage())));
                    }
                  }
                }
              })
          .because(
              "public user-model records must default collection fields to non-null empty "
                  + "instances so adopters can dereference the getters without null checks");

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private static final Set<Class<?>> COLLECTION_TYPES =
      Set.of(List.class, Set.class, Map.class, Collection.class);

  // sun.misc.Unsafe access for allocating non-null sentinel instances of arbitrary reference types
  // without invoking their constructors. Used to populate non-collection record components when
  // their compact constructor enforces a non-null guard (e.g. Objects.requireNonNull); the rule
  // only cares about how *collection* components default, so other components must be non-null to
  // get past the canonical constructor. sun.misc.Unsafe lives in jdk.unsupported, which is open
  // for reflection without --add-opens on current JDKs. The catch is broad so the rule degrades
  // gracefully if a future JDK removes the class (JEP 471 has deprecated most of Unsafe).
  private static final Object UNSAFE;
  private static final java.lang.reflect.Method UNSAFE_ALLOCATE;

  static {
    Object unsafe;
    java.lang.reflect.Method allocate;
    try {
      final Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
      final java.lang.reflect.Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");
      theUnsafe.setAccessible(true);
      unsafe = theUnsafe.get(null);
      allocate = unsafeClass.getMethod("allocateInstance", Class.class);
    } catch (final Exception e) {
      unsafe = null;
      allocate = null;
    }
    UNSAFE = unsafe;
    UNSAFE_ALLOCATE = allocate;
  }

  private static boolean isCollectionField(final JavaField field) {
    try {
      final Class<?> fieldClass = Class.forName(field.getRawType().getName());
      return COLLECTION_TYPES.stream().anyMatch(ct -> ct.isAssignableFrom(fieldClass));
    } catch (final ClassNotFoundException e) {
      return false;
    }
  }

  /**
   * Reflectively creates an instance of the given record class. Passes {@code null} for all
   * collection-typed parameters (so the compact constructor's defaulting logic is exercised), and
   * non-null sentinel values for every other reference parameter (so compact-constructor null
   * guards on required fields don't interfere with this test).
   */
  private static Object instantiateRecordWithNulls(final JavaClass archClass) throws Exception {
    final Class<?> recordClass = Class.forName(archClass.getName());
    final var components = recordClass.getRecordComponents();
    final Class<?>[] componentTypes = new Class<?>[components.length];
    for (int i = 0; i < components.length; i++) {
      componentTypes[i] = components[i].getType();
    }
    final Constructor<?> canonicalCtor = recordClass.getDeclaredConstructor(componentTypes);
    canonicalCtor.setAccessible(true);

    final Object[] args = new Object[componentTypes.length];
    for (int i = 0; i < componentTypes.length; i++) {
      args[i] = defaultValueFor(componentTypes[i]);
    }
    return canonicalCtor.newInstance(args);
  }

  private static Object defaultValueFor(final Class<?> type) {
    if (type.isPrimitive()) {
      if (type == boolean.class) {
        return false;
      }
      if (type == byte.class) {
        return (byte) 0;
      }
      if (type == short.class) {
        return (short) 0;
      }
      if (type == int.class) {
        return 0;
      }
      if (type == long.class) {
        return 0L;
      }
      if (type == float.class) {
        return 0.0f;
      }
      if (type == double.class) {
        return 0.0;
      }
      if (type == char.class) {
        return '\0';
      }
      return null;
    }
    // Collection-typed parameters must be passed as null so the compact ctor's defaulting logic
    // is exercised and verified.
    if (COLLECTION_TYPES.stream().anyMatch(ct -> ct.isAssignableFrom(type))) {
      return null;
    }
    if (type == String.class) {
      return "";
    }
    if (type.isEnum()) {
      final Object[] constants = type.getEnumConstants();
      return constants != null && constants.length > 0 ? constants[0] : null;
    }
    if (type.isArray()) {
      return java.lang.reflect.Array.newInstance(type.getComponentType(), 0);
    }
    if (UNSAFE_ALLOCATE == null) {
      return null;
    }
    try {
      return UNSAFE_ALLOCATE.invoke(UNSAFE, type);
    } catch (final Exception e) {
      return null;
    }
  }
}
