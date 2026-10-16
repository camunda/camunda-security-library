/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.scim.filter;

import io.camunda.security.core.scim.ScimAttribute;
import io.camunda.security.core.scim.ScimException;
import io.camunda.security.core.scim.ScimSchema;
import io.camunda.security.core.scim.ScimSchemas;
import io.camunda.security.core.scim.ScimTrees;
import io.camunda.security.core.scim.filter.ScimFilter.AttributePath;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Evaluates a {@link ScimFilter} against the neutral attribute tree of a resource. */
public final class ScimFilterEvaluator {

  private ScimFilterEvaluator() {}

  /** Rejects filters that reference attributes the User schema does not define. */
  public static void validate(final ScimFilter filter) {
    switch (filter) {
      case ScimFilter.Present p -> validatePath(p.path(), null);
      case ScimFilter.Compare c -> validatePath(c.path(), null);
      case ScimFilter.And a -> {
        validate(a.left());
        validate(a.right());
      }
      case ScimFilter.Or o -> {
        validate(o.left());
        validate(o.right());
      }
      case ScimFilter.Not n -> validate(n.filter());
      case ScimFilter.ValuePath v -> {
        validatePath(v.path(), null);
        validateInner(v.filter(), attributeOf(v.path()));
      }
    }
  }

  private static void validateInner(final ScimFilter filter, final ScimAttribute parent) {
    switch (filter) {
      case ScimFilter.Present p -> validateSub(p.path(), parent);
      case ScimFilter.Compare c -> validateSub(c.path(), parent);
      case ScimFilter.And a -> {
        validateInner(a.left(), parent);
        validateInner(a.right(), parent);
      }
      case ScimFilter.Or o -> {
        validateInner(o.left(), parent);
        validateInner(o.right(), parent);
      }
      case ScimFilter.Not n -> validateInner(n.filter(), parent);
      case ScimFilter.ValuePath v ->
          throw ScimException.invalidFilter("Nested value paths are not supported");
    }
  }

  private static void validateSub(final AttributePath path, final ScimAttribute parent) {
    if (parent != null && parent.sub(path.attribute()).isEmpty()) {
      throw ScimException.invalidFilter(
          "Unknown sub-attribute '" + path.attribute() + "' of '" + parent.name() + "'");
    }
  }

  private static void validatePath(final AttributePath path, final ScimAttribute ignored) {
    if (attributeOf(path) == null) {
      throw ScimException.invalidFilter("Unknown attribute '" + path + "'");
    }
  }

  private static ScimAttribute attributeOf(final AttributePath path) {
    final ScimSchema schema =
        path.schemaUrn() == null || path.schemaUrn().equalsIgnoreCase(ScimSchemas.USER)
            ? ScimSchema.USER
            : ScimSchema.extension(path.schemaUrn()).orElse(null);
    if (schema == null) {
      return null;
    }
    final ScimAttribute attribute = schema.attribute(path.attribute()).orElse(null);
    if (attribute != null && path.sub() != null && attribute.sub(path.sub()).isEmpty()) {
      return null;
    }
    return attribute;
  }

  /** Whether {@code document} satisfies {@code filter}. */
  public static boolean matches(final ScimFilter filter, final Map<String, Object> document) {
    return switch (filter) {
      case ScimFilter.And a -> matches(a.left(), document) && matches(a.right(), document);
      case ScimFilter.Or o -> matches(o.left(), document) || matches(o.right(), document);
      case ScimFilter.Not n -> !matches(n.filter(), document);
      case ScimFilter.Present p -> resolve(p.path(), document).stream().anyMatch(v -> isPresent(v));
      case ScimFilter.Compare c -> matchesCompare(c, document);
      case ScimFilter.ValuePath v -> matchesValuePath(v, document);
    };
  }

  private static boolean matchesValuePath(
      final ScimFilter.ValuePath filter, final Map<String, Object> document) {
    final Map<String, Object> scope = scopeOf(filter.path().schemaUrn(), document);
    final String key = scope == null ? null : ScimTrees.findKey(scope, filter.path().attribute());
    if (key == null) {
      return false;
    }
    final Object value = scope.get(key);
    final List<?> elements = value instanceof List<?> l ? l : List.of(value);
    for (final Object element : elements) {
      if (element instanceof Map<?, ?> m && matches(filter.filter(), cast(m))) {
        return true;
      }
    }
    return false;
  }

  private static boolean matchesCompare(
      final ScimFilter.Compare compare, final Map<String, Object> document) {
    final List<Object> values = resolve(compare.path(), document);
    final boolean caseExact = isCaseExact(compare.path());
    if (compare.operator() == ScimFilter.Operator.NE) {
      return values.stream()
          .noneMatch(v -> compare(v, ScimFilter.Operator.EQ, compare.value(), caseExact));
    }
    if (compare.value() == null) {
      return values.isEmpty() && compare.operator() == ScimFilter.Operator.EQ;
    }
    return values.stream()
        .anyMatch(v -> compare(v, compare.operator(), compare.value(), caseExact));
  }

  private static boolean isCaseExact(final AttributePath path) {
    final ScimAttribute attribute = attributeOf(path);
    return attribute != null && path.sub() == null && attribute.caseExact();
  }

  private static boolean compare(
      final Object actual,
      final ScimFilter.Operator op,
      final Object expected,
      final boolean caseExact) {
    if (actual instanceof String a && expected instanceof String e) {
      return compareStrings(a, op, e, caseExact);
    }
    if (actual instanceof Number a && expected instanceof Number e) {
      return applyOrdering(Double.compare(a.doubleValue(), e.doubleValue()), op);
    }
    if (actual instanceof Boolean a && expected instanceof Boolean e) {
      return op == ScimFilter.Operator.EQ && a.equals(e);
    }
    return false;
  }

  private static boolean compareStrings(
      final String actual,
      final ScimFilter.Operator op,
      final String expected,
      final boolean caseExact) {
    final String a = caseExact ? actual : actual.toLowerCase(Locale.ROOT);
    final String e = caseExact ? expected : expected.toLowerCase(Locale.ROOT);
    return switch (op) {
      case CO -> a.contains(e);
      case SW -> a.startsWith(e);
      case EW -> a.endsWith(e);
      default -> applyOrdering(a.compareTo(e), op);
    };
  }

  private static boolean applyOrdering(final int cmp, final ScimFilter.Operator op) {
    return switch (op) {
      case EQ -> cmp == 0;
      case GT -> cmp > 0;
      case GE -> cmp >= 0;
      case LT -> cmp < 0;
      case LE -> cmp <= 0;
      default -> false;
    };
  }

  private static boolean isPresent(final Object value) {
    if (value == null) {
      return false;
    }
    if (value instanceof String s) {
      return !s.isEmpty();
    }
    if (value instanceof List<?> l) {
      return !l.isEmpty();
    }
    return !(value instanceof Map<?, ?> m) || !m.isEmpty();
  }

  private static List<Object> resolve(final AttributePath path, final Map<String, Object> doc) {
    final Map<String, Object> scope = scopeOf(path.schemaUrn(), doc);
    final List<Object> result = new ArrayList<>();
    if (scope == null) {
      return result;
    }
    final String key = ScimTrees.findKey(scope, path.attribute());
    if (key == null || scope.get(key) == null) {
      return result;
    }
    final Object value = scope.get(key);
    final List<?> elements = value instanceof List<?> l ? l : List.of(value);
    for (final Object element : elements) {
      if (path.sub() == null) {
        result.add(element);
      } else if (element instanceof Map<?, ?> m) {
        final Map<String, Object> map = cast(m);
        final String subKey = ScimTrees.findKey(map, path.sub());
        if (subKey != null && map.get(subKey) != null) {
          result.add(map.get(subKey));
        }
      }
    }
    return result;
  }

  private static Map<String, Object> scopeOf(final String urn, final Map<String, Object> doc) {
    if (urn == null || urn.equalsIgnoreCase(ScimSchemas.USER)) {
      return doc;
    }
    final String key = ScimTrees.findKey(doc, urn);
    return key != null && doc.get(key) instanceof Map<?, ?> m ? cast(m) : null;
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> cast(final Map<?, ?> map) {
    return (Map<String, Object>) map;
  }
}
