/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.beans.IntrospectionException;
import java.beans.Introspector;
import java.beans.PropertyDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Type;
import java.net.URL;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * Guards that {@code META-INF/spring-configuration-metadata.json} stays in sync with the {@code
 * camunda.security.*} configuration tree. Three things are checked against the live config beans:
 *
 * <ul>
 *   <li>the set of {@code groups} (intermediate configuration beans) with their declared types;
 *   <li>the set of leaf {@code properties} with their declared types;
 *   <li>which leaf properties carry a {@code defaultValue} — a property is expected to declare one
 *       exactly when its bean has a non-null, non-empty runtime default.
 * </ul>
 *
 * <p>The test walks the bean hierarchy starting from a fresh {@link
 * CamundaSecurityLibraryProperties} instance using Java Beans introspection: a class from the
 * {@code io.camunda.security.api.model.config} packages is a group (recurse); anything else with a
 * write method is a leaf. Type strings are derived the way Spring Boot's configuration processor
 * emits them — primitives boxed to their wrappers, generic signatures rendered without spaces. The
 * {@code defaultValue} presence (not its rendered value) is compared: full value-equality would
 * require re-implementing Spring's value rendering (e.g. {@code Duration.ofSeconds(60)} renders as
 * {@code PT1M}, not {@code PT60S}), so the test only asserts that a default is documented when —
 * and only when — one exists at runtime.
 *
 * <p>A mismatch in any of the three checks fails the test and requires updating the hand-authored
 * file.
 */
class SpringConfigurationMetadataCompletenessTest {

  private static final String METADATA_RESOURCE = "META-INF/spring-configuration-metadata.json";
  private static final String ROOT_PREFIX = "camunda.security";
  private static final String CONFIG_PACKAGE_PREFIX = "io.camunda.security.api.model.config";

  private static final Map<Class<?>, Class<?>> PRIMITIVE_WRAPPERS =
      Map.of(
          boolean.class, Boolean.class,
          byte.class, Byte.class,
          char.class, Character.class,
          short.class, Short.class,
          int.class, Integer.class,
          long.class, Long.class,
          float.class, Float.class,
          double.class, Double.class);

  @Test
  void metadataMatchesConfigTreeLeavesAndGroups() throws Exception {
    final Reflected reflected = new Reflected();
    reflected.groups.put(ROOT_PREFIX, CamundaSecurityLibraryProperties.class.getName());
    walkBean(
        CamundaSecurityLibraryProperties.class,
        new CamundaSecurityLibraryProperties(),
        ROOT_PREFIX,
        reflected);

    final Metadata fromFile = readMetadata();

    assertThat(fromFile.groups)
        .as(
            "groups[] in %s must match the config-tree groups (name -> type) exactly. "
                + "Add, remove, or correct the type of entries in the hand-authored metadata file.",
            METADATA_RESOURCE)
        .containsExactlyInAnyOrderEntriesOf(reflected.groups);

    assertThat(fromFile.properties)
        .as(
            "properties[] in %s must match the config-tree leaves (name -> type) exactly. "
                + "Add, remove, or correct the type of entries in the hand-authored metadata file.",
            METADATA_RESOURCE)
        .containsExactlyInAnyOrderEntriesOf(reflected.properties);

    assertThat(fromFile.propertiesWithDefault)
        .as(
            "defaultValue in %s must be declared for exactly those properties whose bean has a "
                + "non-null, non-empty runtime default. Add a missing defaultValue, or remove a "
                + "stale one whose property no longer defaults to a value.",
            METADATA_RESOURCE)
        .containsExactlyInAnyOrderElementsOf(reflected.propertiesWithDefault);
  }

  private static void walkBean(
      final Class<?> clazz, final Object instance, final String prefix, final Reflected reflected)
      throws IntrospectionException, ReflectiveOperationException {
    for (final PropertyDescriptor pd :
        Introspector.getBeanInfo(clazz, Object.class).getPropertyDescriptors()) {
      // Only settable properties are covered. Spring Boot also binds getter-only nested beans
      // (mutating in place); none exist today, but such a bean's subtree would be silently skipped.
      if (pd.getWriteMethod() == null) {
        continue;
      }
      final String path = prefix + "." + toKebabCase(pd.getName());
      final Class<?> type = pd.getPropertyType();
      if (isConfigBean(type)) {
        reflected.groups.put(path, type.getName());
        final Object child = readValue(pd, instance);
        walkBean(type, child != null ? child : newInstance(type), path, reflected);
      } else {
        reflected.properties.put(path, leafType(pd));
        if (hasMeaningfulDefault(readValue(pd, instance))) {
          reflected.propertiesWithDefault.add(path);
        }
      }
    }
  }

  private static boolean isConfigBean(final Class<?> type) {
    if (type == null || type.isEnum()) {
      return false;
    }
    return type.getPackageName().startsWith(CONFIG_PACKAGE_PREFIX);
  }

  /**
   * Derives the property type string as Spring Boot's configuration processor renders it: a
   * primitive is reported as its boxed wrapper, and a generic signature is rendered without the
   * spaces {@link Type#getTypeName()} inserts after commas.
   */
  private static String leafType(final PropertyDescriptor pd) {
    final Method reader = pd.getReadMethod();
    final Type generic =
        reader != null
            ? reader.getGenericReturnType()
            : pd.getWriteMethod().getGenericParameterTypes()[0];
    if (generic instanceof final Class<?> raw && raw.isPrimitive()) {
      return PRIMITIVE_WRAPPERS.get(raw).getName();
    }
    return generic.getTypeName().replace(" ", "");
  }

  /** A non-null scalar, or a non-empty collection/map, counts as a documented default. */
  private static boolean hasMeaningfulDefault(final Object value) {
    if (value == null) {
      return false;
    }
    if (value instanceof final Collection<?> collection) {
      return !collection.isEmpty();
    }
    if (value instanceof final Map<?, ?> map) {
      return !map.isEmpty();
    }
    return true;
  }

  private static Object readValue(final PropertyDescriptor pd, final Object instance)
      throws ReflectiveOperationException {
    final Method reader = pd.getReadMethod();
    return reader == null ? null : reader.invoke(instance);
  }

  private static Object newInstance(final Class<?> clazz) throws ReflectiveOperationException {
    return clazz.getDeclaredConstructor().newInstance();
  }

  private static String toKebabCase(final String camel) {
    return camel.replaceAll("([a-z0-9])([A-Z])", "$1-$2").toLowerCase();
  }

  private static Metadata readMetadata() throws IOException {
    final Metadata metadata = new Metadata();
    final ObjectMapper mapper = new ObjectMapper();
    final Enumeration<URL> resources =
        SpringConfigurationMetadataCompletenessTest.class
            .getClassLoader()
            .getResources(METADATA_RESOURCE);
    while (resources.hasMoreElements()) {
      try (final InputStream in = resources.nextElement().openStream()) {
        final JsonNode root = mapper.readTree(in);
        for (final JsonNode group : root.path("groups")) {
          final String name = group.path("name").asText("");
          if (name.startsWith(ROOT_PREFIX)) {
            metadata.groups.put(name, group.path("type").asText(""));
          }
        }
        for (final JsonNode property : root.path("properties")) {
          final String name = property.path("name").asText("");
          if (name.startsWith(ROOT_PREFIX)) {
            metadata.properties.put(name, property.path("type").asText(""));
            if (property.has("defaultValue")) {
              metadata.propertiesWithDefault.add(name);
            }
          }
        }
      }
    }
    assertThat(metadata.properties)
        .as(
            "No camunda.security.* properties found in %s on the classpath. "
                + "Ensure spring-boot-starter/src/main/resources/META-INF/spring-configuration-metadata.json exists.",
            METADATA_RESOURCE)
        .isNotEmpty();
    return metadata;
  }

  private static final class Reflected {
    private final TreeMap<String, String> groups = new TreeMap<>();
    private final TreeMap<String, String> properties = new TreeMap<>();
    private final TreeSet<String> propertiesWithDefault = new TreeSet<>();
  }

  private static final class Metadata {
    private final TreeMap<String, String> groups = new TreeMap<>();
    private final TreeMap<String, String> properties = new TreeMap<>();
    private final TreeSet<String> propertiesWithDefault = new TreeSet<>();
  }
}
