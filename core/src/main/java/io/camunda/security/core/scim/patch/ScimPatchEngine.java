/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.scim.patch;

import io.camunda.security.core.scim.ScimAttribute;
import io.camunda.security.core.scim.ScimException;
import io.camunda.security.core.scim.ScimSchema;
import io.camunda.security.core.scim.ScimSchemas;
import io.camunda.security.core.scim.ScimTrees;
import io.camunda.security.core.scim.ScimUserValidator;
import io.camunda.security.core.scim.filter.ScimFilter;
import io.camunda.security.core.scim.filter.ScimFilterEvaluator;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Applies an RFC 7644 §3.5.2 PatchOp request ({@code add}, {@code replace}, {@code remove}) to a
 * User attribute tree. After all operations the result is re-validated, so type, required attribute
 * and single-{@code primary} rules hold for patched resources exactly as for created ones.
 *
 * <p>Tolerances for real IdPs (notably Entra ID): operation names are case-insensitive, path-less
 * operations accept dotted/URN keys such as {@code "name.givenName"}, and an {@code add} whose
 * value-filter matches nothing (for example {@code emails[type eq "work"].value}) creates the
 * element from the filter's equality terms.
 */
public final class ScimPatchEngine {

  private static final Logger LOG = LoggerFactory.getLogger(ScimPatchEngine.class);

  private final ScimUserValidator validator;

  public ScimPatchEngine(final ScimUserValidator validator) {
    this.validator = validator;
  }

  /**
   * @param current the current attribute tree (not modified)
   * @param request the PatchOp message
   * @return the validated, patched attribute tree
   */
  public Map<String, Object> apply(
      final Map<String, Object> current, final Map<String, Object> request) {
    if (request == null) {
      throw ScimException.invalidSyntax("Request body is required");
    }
    requirePatchSchema(request);
    final List<Map<String, Object>> operations = operations(request);
    final Map<String, Object> working = ScimTrees.deepCopy(current);
    int index = 0;
    for (final Map<String, Object> operation : operations) {
      applyOperation(working, operation, index++);
    }
    return validator.normalizeAttributes(working);
  }

  private void requirePatchSchema(final Map<String, Object> request) {
    final String key = ScimTrees.findKey(request, "schemas");
    final boolean ok =
        key != null
            && request.get(key) instanceof List<?> l
            && l.stream().anyMatch(s -> ScimSchemas.PATCH_OP.equalsIgnoreCase(String.valueOf(s)));
    if (!ok) {
      throw ScimException.invalidSyntax("'schemas' must contain '" + ScimSchemas.PATCH_OP + "'");
    }
  }

  @SuppressWarnings("unchecked")
  private List<Map<String, Object>> operations(final Map<String, Object> request) {
    final String key = ScimTrees.findKey(request, "Operations");
    if (key == null || !(request.get(key) instanceof List<?> list) || list.isEmpty()) {
      throw ScimException.invalidSyntax("'Operations' is required and must be a non-empty array");
    }
    final List<Map<String, Object>> result = new ArrayList<>();
    for (final Object o : list) {
      if (!(o instanceof Map<?, ?> m)) {
        throw ScimException.invalidSyntax("Every entry of 'Operations' must be an object");
      }
      result.add((Map<String, Object>) m);
    }
    return result;
  }

  private void applyOperation(
      final Map<String, Object> working, final Map<String, Object> operation, final int index) {
    final String opKey = ScimTrees.findKey(operation, "op");
    final String op =
        opKey != null && operation.get(opKey) instanceof String s ? s.toLowerCase(Locale.ROOT) : "";
    final String pathKey = ScimTrees.findKey(operation, "path");
    final Object rawPath = pathKey == null ? null : operation.get(pathKey);
    final String valueKey = ScimTrees.findKey(operation, "value");
    final Object value = valueKey == null ? null : operation.get(valueKey);
    if (rawPath != null && !(rawPath instanceof String)) {
      throw ScimException.invalidPath("Operation " + index + ": 'path' must be a string");
    }
    final PatchPath path = rawPath == null ? null : PatchPath.parse((String) rawPath);
    LOG.debug("PATCH operation {}: op={} path={}", index, op, rawPath);
    switch (op) {
      case "add", "replace" -> write(working, op, path, value);
      case "remove" -> remove(working, path);
      default ->
          throw ScimException.invalidSyntax(
              "Operation " + index + ": 'op' must be add, remove or replace");
    }
  }

  // ---- add / replace -------------------------------------------------------------------------

  private void write(
      final Map<String, Object> working,
      final String op,
      final PatchPath path,
      final Object value) {
    if (path == null) {
      writeWithoutPath(working, op, value);
      return;
    }
    if (value == null) {
      remove(working, path);
      return;
    }
    if (path.attribute() == null) {
      writeExtension(working, op, path, value);
      return;
    }
    final ScimAttribute def = definition(path);
    if (def.readOnly()) {
      throw ScimException.mutability("Attribute '" + def.name() + "' is read-only");
    }
    final Map<String, Object> scope = scope(working, path.schemaUrn(), true);
    if (path.filter() != null) {
      writeFiltered(scope, def, op, path, value);
    } else if (path.sub() != null) {
      writeSub(scope, def, path, value);
    } else if (def.multiValued()) {
      writeMulti(scope, def, op, value);
    } else if (def.type() == ScimAttribute.Type.COMPLEX && op.equals("add")) {
      writeMergedComplex(scope, def, value);
    } else {
      scope.put(existingKey(scope, def.name()), value);
    }
  }

  private void writeWithoutPath(
      final Map<String, Object> working, final String op, final Object value) {
    if (!(value instanceof Map<?, ?> map)) {
      throw ScimException.invalidValue("'value' must be an object when 'path' is omitted");
    }
    for (final Map.Entry<?, ?> entry : map.entrySet()) {
      final String key = String.valueOf(entry.getKey());
      final PatchPath target =
          ScimSchema.extension(key).isPresent()
              ? new PatchPath(ScimSchema.extension(key).get().urn(), null, null, null)
              : PatchPath.parse(key);
      write(working, op, target, entry.getValue());
    }
  }

  private void writeExtension(
      final Map<String, Object> working,
      final String op,
      final PatchPath path,
      final Object value) {
    if (!(value instanceof Map<?, ?> map)) {
      throw ScimException.invalidValue("'value' must be an object for '" + path.schemaUrn() + "'");
    }
    for (final Map.Entry<?, ?> entry : map.entrySet()) {
      write(
          working,
          op,
          new PatchPath(path.schemaUrn(), String.valueOf(entry.getKey()), null, null),
          entry.getValue());
    }
  }

  private void writeSub(
      final Map<String, Object> scope,
      final ScimAttribute def,
      final PatchPath path,
      final Object value) {
    if (def.multiValued() || def.type() != ScimAttribute.Type.COMPLEX) {
      throw ScimException.invalidPath(
          "'" + def.name() + "." + path.sub() + "' is not addressable without a filter");
    }
    final ScimAttribute subDef = subDefinition(def, path.sub());
    final String key = existingKey(scope, def.name());
    final Map<String, Object> complex = mutableMap(scope, key);
    complex.put(subDef.name(), value);
  }

  private void writeMulti(
      final Map<String, Object> scope,
      final ScimAttribute def,
      final String op,
      final Object value) {
    final List<?> incoming = value instanceof List<?> l ? l : List.of(value);
    final String key = existingKey(scope, def.name());
    final List<Object> target = op.equals("replace") ? new ArrayList<>() : mutableList(scope, key);
    for (final Object element : incoming) {
      final Object copy = ScimTrees.copyValue(element);
      if (!target.contains(copy)) {
        target.add(copy);
      }
      enforceSinglePrimary(target, copy);
    }
    scope.put(key, target);
  }

  private void writeMergedComplex(
      final Map<String, Object> scope, final ScimAttribute def, final Object value) {
    if (!(value instanceof Map<?, ?> map)) {
      throw ScimException.invalidValue("'" + def.name() + "' must be an object");
    }
    final Map<String, Object> complex = mutableMap(scope, existingKey(scope, def.name()));
    map.forEach((k, v) -> complex.put(String.valueOf(k), v));
  }

  private void writeFiltered(
      final Map<String, Object> scope,
      final ScimAttribute def,
      final String op,
      final PatchPath path,
      final Object value) {
    requireMultiValued(def, path);
    ScimFilterEvaluator.validate(new ScimFilter.ValuePath(attributePath(path), path.filter()));
    final String key = existingKey(scope, def.name());
    final List<Object> list = mutableList(scope, key);
    final List<Map<String, Object>> matched = matching(list, path.filter());
    if (matched.isEmpty()) {
      if (!op.equals("add") || !createFromFilter(list, def, path, value)) {
        throw ScimException.noTarget("No '" + def.name() + "' value matches the path filter");
      }
      scope.put(key, list);
      return;
    }
    for (final Map<String, Object> element : matched) {
      updateElement(element, def, path.sub(), value);
      enforceSinglePrimary(list, element);
    }
    scope.put(key, list);
  }

  private void updateElement(
      final Map<String, Object> element,
      final ScimAttribute def,
      final String sub,
      final Object value) {
    if (sub != null) {
      element.put(subDefinition(def, sub).name(), value);
    } else if (value instanceof Map<?, ?> map) {
      map.forEach((k, v) -> element.put(String.valueOf(k), v));
    } else {
      throw ScimException.invalidValue("'value' must be an object when no sub-attribute is given");
    }
  }

  private boolean createFromFilter(
      final List<Object> list, final ScimAttribute def, final PatchPath path, final Object value) {
    final Map<String, Object> element = new LinkedHashMap<>();
    if (!equalityTerms(path.filter(), element) || element.isEmpty()) {
      return false;
    }
    updateElement(element, def, path.sub(), value);
    list.add(element);
    enforceSinglePrimary(list, element);
    LOG.debug("PATCH add created a new '{}' element from the path filter", def.name());
    return true;
  }

  private boolean equalityTerms(final ScimFilter filter, final Map<String, Object> out) {
    if (filter instanceof ScimFilter.And and) {
      return equalityTerms(and.left(), out) && equalityTerms(and.right(), out);
    }
    if (filter instanceof ScimFilter.Compare c
        && c.operator() == ScimFilter.Operator.EQ
        && c.path().sub() == null
        && c.value() != null) {
      out.put(c.path().attribute(), c.value());
      return true;
    }
    return false;
  }

  // ---- remove --------------------------------------------------------------------------------

  private void remove(final Map<String, Object> working, final PatchPath path) {
    if (path == null) {
      throw ScimException.noTarget("'path' is required for 'remove'");
    }
    if (path.attribute() == null) {
      final String key = ScimTrees.findKey(working, path.schemaUrn());
      if (key != null) {
        working.remove(key);
      }
      return;
    }
    final ScimAttribute def = definition(path);
    if (def.readOnly() || def.required()) {
      throw ScimException.mutability("Attribute '" + def.name() + "' cannot be removed");
    }
    final Map<String, Object> scope = scope(working, path.schemaUrn(), false);
    final String key = scope == null ? null : ScimTrees.findKey(scope, def.name());
    if (key == null) {
      return;
    }
    if (path.filter() != null) {
      removeFiltered(scope, key, def, path);
    } else if (path.sub() != null) {
      removeSub(scope, key, def, path.sub());
    } else {
      scope.remove(key);
    }
  }

  private void removeFiltered(
      final Map<String, Object> scope,
      final String key,
      final ScimAttribute def,
      final PatchPath path) {
    requireMultiValued(def, path);
    ScimFilterEvaluator.validate(new ScimFilter.ValuePath(attributePath(path), path.filter()));
    final List<Object> list = mutableList(scope, key);
    final List<Map<String, Object>> matched = matching(list, path.filter());
    if (matched.isEmpty()) {
      throw ScimException.noTarget("No '" + def.name() + "' value matches the path filter");
    }
    if (path.sub() == null) {
      list.removeAll(matched);
    } else {
      final String subName = subDefinition(def, path.sub()).name();
      matched.forEach(e -> e.remove(subName));
    }
    scope.put(key, list);
  }

  private void removeSub(
      final Map<String, Object> scope,
      final String key,
      final ScimAttribute def,
      final String sub) {
    final String subName = subDefinition(def, sub).name();
    final Object value = scope.get(key);
    if (value instanceof Map<?, ?>) {
      mutableMap(scope, key).remove(subName);
    } else if (value instanceof List<?>) {
      mutableList(scope, key).forEach(e -> asMap(e).remove(subName));
    }
  }

  // ---- helpers -------------------------------------------------------------------------------

  private ScimAttribute definition(final PatchPath path) {
    final ScimSchema schema =
        path.schemaUrn() == null
            ? ScimSchema.USER
            : ScimSchema.extension(path.schemaUrn()).orElseThrow();
    return schema
        .attribute(path.attribute())
        .orElseThrow(
            () -> ScimException.invalidPath("Unknown attribute '" + path.attribute() + "'"));
  }

  private ScimAttribute subDefinition(final ScimAttribute def, final String sub) {
    return def.sub(sub)
        .orElseThrow(
            () ->
                ScimException.invalidPath(
                    "Unknown sub-attribute '" + sub + "' of '" + def.name() + "'"));
  }

  private void requireMultiValued(final ScimAttribute def, final PatchPath path) {
    if (!def.multiValued()) {
      throw ScimException.invalidPath(
          "'" + def.name() + "' is not multi-valued; a value filter is not allowed");
    }
  }

  private ScimFilter.AttributePath attributePath(final PatchPath path) {
    return new ScimFilter.AttributePath(path.schemaUrn(), path.attribute(), null);
  }

  private Map<String, Object> scope(
      final Map<String, Object> working, final String urn, final boolean create) {
    if (urn == null) {
      return working;
    }
    final String key = ScimTrees.findKey(working, urn);
    if (key != null) {
      return mutableMap(working, key);
    }
    if (!create) {
      return null;
    }
    final Map<String, Object> created = new LinkedHashMap<>();
    working.put(urn, created);
    return created;
  }

  private String existingKey(final Map<String, Object> scope, final String name) {
    final String key = ScimTrees.findKey(scope, name);
    return key == null ? name : key;
  }

  private List<Map<String, Object>> matching(final List<Object> list, final ScimFilter filter) {
    final List<Map<String, Object>> matched = new ArrayList<>();
    for (final Object element : list) {
      final Map<String, Object> map = asMap(element);
      if (ScimFilterEvaluator.matches(filter, map)) {
        matched.add(map);
      }
    }
    return matched;
  }

  /** Keeps at most one {@code primary=true} element: {@code keeper} wins when it is primary. */
  private void enforceSinglePrimary(final List<Object> list, final Object keeper) {
    if (!(keeper instanceof Map<?, ?> k) || !Boolean.TRUE.equals(k.get("primary"))) {
      return;
    }
    for (final Object other : list) {
      if (other != keeper && other instanceof Map<?, ?>) {
        asMap(other).computeIfPresent("primary", (n, v) -> Boolean.TRUE.equals(v) ? false : v);
      }
    }
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> asMap(final Object value) {
    if (value instanceof Map<?, ?> m) {
      return (Map<String, Object>) m;
    }
    throw ScimException.invalidValue("Expected an object but found '" + value + "'");
  }

  private Map<String, Object> mutableMap(final Map<String, Object> scope, final String key) {
    final Object existing = scope.get(key);
    if (existing instanceof Map<?, ?>) {
      return asMap(existing);
    }
    final Map<String, Object> created = new LinkedHashMap<>();
    scope.put(key, created);
    return created;
  }

  @SuppressWarnings("unchecked")
  private List<Object> mutableList(final Map<String, Object> scope, final String key) {
    final Object existing = scope.get(key);
    if (existing instanceof List<?>) {
      return (List<Object>) existing;
    }
    final List<Object> created = new ArrayList<>();
    scope.put(key, created);
    return created;
  }
}
