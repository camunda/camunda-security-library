/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.scim;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validates and normalizes an incoming User representation per RFC 7643 §2-§4 and RFC 7644 §3.3:
 * schema declaration, required attributes, data types, canonical attribute names, read-only
 * attributes being ignored, and at most one {@code primary} per multi-valued attribute.
 *
 * <p>Deliberate leniency, because real IdPs need it: boolean values sent as the strings {@code
 * "true"}/{@code "false"} (any case) are accepted, and unknown attributes are ignored (RFC 7643 §2
 * lets a provider ignore what it does not support) rather than rejected.
 */
public final class ScimUserValidator {

  private static final Logger LOG = LoggerFactory.getLogger(ScimUserValidator.class);

  /** Attributes a client may send but the server owns; silently ignored on input. */
  private static final Set<String> IGNORED_ON_INPUT = Set.of("schemas", "id", "meta", "groups");

  /**
   * Validates a full request body (POST/PUT): checks {@code schemas}, then normalizes attributes.
   *
   * @return the canonical attribute tree without {@code schemas}/{@code id}/{@code meta}
   */
  public Map<String, Object> validateBody(final Map<String, Object> body) {
    if (body == null) {
      throw ScimException.invalidSyntax("Request body is required");
    }
    validateSchemas(body.get(schemasKey(body)));
    final Map<String, Object> attributes = normalizeAttributes(body);
    LOG.debug("Validated User body; attributes={}", attributes.keySet());
    return attributes;
  }

  /**
   * Normalizes an attribute tree (also used to re-validate the result of a PATCH). Throws when
   * {@code userName} is missing or a value has the wrong type.
   */
  public Map<String, Object> normalizeAttributes(final Map<String, Object> input) {
    final Map<String, Object> result = new LinkedHashMap<>();
    for (final Map.Entry<String, Object> entry : input.entrySet()) {
      normalizeTopLevel(entry.getKey(), entry.getValue(), result);
    }
    final Object userName = result.get("userName");
    if (!(userName instanceof String s) || s.isBlank()) {
      throw ScimException.invalidValue("'userName' is required and must be a non-empty string");
    }
    return result;
  }

  private void normalizeTopLevel(
      final String key, final Object value, final Map<String, Object> result) {
    if (IGNORED_ON_INPUT.contains(key.toLowerCase(Locale.ROOT))) {
      return;
    }
    final var extension = ScimSchema.extension(key);
    if (extension.isPresent()) {
      final Map<String, Object> normalized = normalizeExtension(extension.get(), value);
      if (!normalized.isEmpty()) {
        result.put(extension.get().urn(), normalized);
      }
      return;
    }
    final var attribute = ScimSchema.USER.attribute(key);
    if (attribute.isEmpty()) {
      LOG.debug("Ignoring unknown User attribute '{}'", key);
      return;
    }
    if (value == null || "password".equals(attribute.get().name())) {
      // password is write-only and this POC never stores credentials
      return;
    }
    result.put(attribute.get().name(), normalizeValue(attribute.get(), value));
  }

  private Map<String, Object> normalizeExtension(final ScimSchema schema, final Object value) {
    if (!(value instanceof Map<?, ?> map)) {
      throw ScimException.invalidValue("'" + schema.urn() + "' must be an object");
    }
    final Map<String, Object> result = new LinkedHashMap<>();
    for (final Map.Entry<?, ?> entry : map.entrySet()) {
      final var attribute = schema.attribute(String.valueOf(entry.getKey()));
      if (attribute.isPresent() && entry.getValue() != null) {
        result.put(attribute.get().name(), normalizeValue(attribute.get(), entry.getValue()));
      }
    }
    return result;
  }

  private Object normalizeValue(final ScimAttribute attribute, final Object value) {
    if (attribute.multiValued()) {
      return normalizeMulti(attribute, value);
    }
    if (attribute.type() == ScimAttribute.Type.COMPLEX) {
      return normalizeComplex(attribute, value);
    }
    return coerceSimple(attribute, value);
  }

  private List<Object> normalizeMulti(final ScimAttribute attribute, final Object value) {
    if (!(value instanceof List<?> list)) {
      throw ScimException.invalidValue("'" + attribute.name() + "' must be an array");
    }
    final List<Object> result = new ArrayList<>();
    int primaries = 0;
    for (final Object element : list) {
      final Map<String, Object> normalized = normalizeComplex(attribute, element);
      if (Boolean.TRUE.equals(normalized.get("primary"))) {
        primaries++;
      }
      result.add(normalized);
    }
    if (primaries > 1) {
      throw ScimException.invalidValue(
          "'" + attribute.name() + "' must not have more than one 'primary' value");
    }
    return result;
  }

  private Map<String, Object> normalizeComplex(final ScimAttribute attribute, final Object value) {
    if (!(value instanceof Map<?, ?> map)) {
      throw ScimException.invalidValue("'" + attribute.name() + "' must be an object");
    }
    final Map<String, Object> result = new LinkedHashMap<>();
    for (final Map.Entry<?, ?> entry : map.entrySet()) {
      final var sub = attribute.sub(String.valueOf(entry.getKey()));
      if (sub.isPresent() && entry.getValue() != null) {
        result.put(
            sub.get().name(), coerceSimple(sub.get(), entry.getValue(), attribute.name() + "."));
      }
    }
    return result;
  }

  private Object coerceSimple(final ScimAttribute attribute, final Object value) {
    return coerceSimple(attribute, value, "");
  }

  private Object coerceSimple(
      final ScimAttribute attribute, final Object value, final String prefix) {
    final String name = prefix + attribute.name();
    return switch (attribute.type()) {
      case STRING -> {
        if (!(value instanceof String)) {
          throw ScimException.invalidValue("'" + name + "' must be a string");
        }
        yield value;
      }
      case BOOLEAN -> coerceBoolean(name, value);
      default -> throw ScimException.invalidValue("Unsupported type for '" + name + "'");
    };
  }

  private Boolean coerceBoolean(final String name, final Object value) {
    if (value instanceof Boolean b) {
      return b;
    }
    if (value instanceof String s && (s.equalsIgnoreCase("true") || s.equalsIgnoreCase("false"))) {
      LOG.debug("Coercing string value of boolean attribute '{}'", name);
      return Boolean.parseBoolean(s);
    }
    throw ScimException.invalidValue("'" + name + "' must be a boolean");
  }

  private static String schemasKey(final Map<String, Object> body) {
    final String key = ScimTrees.findKey(body, "schemas");
    return key == null ? "schemas" : key;
  }

  private void validateSchemas(final Object schemas) {
    if (!(schemas instanceof List<?> list) || list.isEmpty()) {
      throw ScimException.invalidSyntax("'schemas' is required and must be a non-empty array");
    }
    boolean hasCore = false;
    for (final Object urn : list) {
      if (!(urn instanceof String s)) {
        throw ScimException.invalidSyntax("'schemas' must contain only strings");
      }
      if (s.equalsIgnoreCase(ScimSchemas.USER)) {
        hasCore = true;
      } else if (ScimSchema.extension(s).isEmpty()) {
        throw ScimException.invalidValue("Unsupported schema '" + s + "'");
      }
    }
    if (!hasCore) {
      throw ScimException.invalidSyntax("'schemas' must contain '" + ScimSchemas.USER + "'");
    }
  }
}
