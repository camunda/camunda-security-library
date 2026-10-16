/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.scim.filter;

/** AST of an RFC 7644 §3.4.2.2 filter expression. */
public sealed interface ScimFilter {

  /** Comparison operators (excluding {@code pr}, which is {@link Present}). */
  enum Operator {
    EQ,
    NE,
    CO,
    SW,
    EW,
    GT,
    GE,
    LT,
    LE
  }

  /**
   * An attribute path in a filter, optionally schema-qualified and with a sub-attribute.
   *
   * @param schemaUrn extension schema URN or {@code null}
   * @param attribute the attribute name
   * @param sub the sub-attribute name or {@code null}
   */
  record AttributePath(String schemaUrn, String attribute, String sub) {

    @Override
    public String toString() {
      return (schemaUrn == null ? "" : schemaUrn + ":")
          + attribute
          + (sub == null ? "" : "." + sub);
    }
  }

  /** {@code attr pr}. */
  record Present(AttributePath path) implements ScimFilter {}

  /** {@code attr op value}; {@code value} is a String, Boolean, Number or {@code null}. */
  record Compare(AttributePath path, Operator operator, Object value) implements ScimFilter {}

  /** {@code left and right}. */
  record And(ScimFilter left, ScimFilter right) implements ScimFilter {}

  /** {@code left or right}. */
  record Or(ScimFilter left, ScimFilter right) implements ScimFilter {}

  /** {@code not (filter)}. */
  record Not(ScimFilter filter) implements ScimFilter {}

  /** {@code attr[filter]}: the filter is evaluated against each element of the attribute. */
  record ValuePath(AttributePath path, ScimFilter filter) implements ScimFilter {}
}
