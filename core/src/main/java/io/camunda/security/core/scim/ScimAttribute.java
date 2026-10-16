/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.scim;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Attribute characteristics from RFC 7643 §2 that drive validation, filtering and PATCH.
 *
 * @param name canonical attribute name
 * @param type the attribute data type
 * @param multiValued whether the attribute holds a list
 * @param readOnly {@code mutability = readOnly}: ignored on input, rejected by PATCH
 * @param required whether the attribute must be present
 * @param caseExact whether string comparison is case sensitive
 * @param subAttributes sub-attributes of a complex attribute
 */
public record ScimAttribute(
    String name,
    Type type,
    boolean multiValued,
    boolean readOnly,
    boolean required,
    boolean caseExact,
    List<ScimAttribute> subAttributes) {

  /** SCIM attribute data types (reference/binary/dateTime are carried as strings). */
  public enum Type {
    STRING,
    BOOLEAN,
    INTEGER,
    DECIMAL,
    COMPLEX
  }

  public ScimAttribute {
    subAttributes = List.copyOf(subAttributes);
  }

  public static ScimAttribute string(final String name) {
    return new ScimAttribute(name, Type.STRING, false, false, false, false, List.of());
  }

  public static ScimAttribute bool(final String name) {
    return new ScimAttribute(name, Type.BOOLEAN, false, false, false, false, List.of());
  }

  public static ScimAttribute complex(final String name, final ScimAttribute... subs) {
    return new ScimAttribute(name, Type.COMPLEX, false, false, false, false, List.of(subs));
  }

  public static ScimAttribute multi(final String name, final ScimAttribute... subs) {
    return new ScimAttribute(name, Type.COMPLEX, true, false, false, false, List.of(subs));
  }

  public ScimAttribute asRequired() {
    return new ScimAttribute(name, type, multiValued, readOnly, true, caseExact, subAttributes);
  }

  public ScimAttribute asReadOnly() {
    return new ScimAttribute(name, type, multiValued, true, required, caseExact, subAttributes);
  }

  public ScimAttribute asCaseExact() {
    return new ScimAttribute(name, type, multiValued, readOnly, required, true, subAttributes);
  }

  public Optional<ScimAttribute> sub(final String subName) {
    final String wanted = subName.toLowerCase(Locale.ROOT);
    return subAttributes.stream()
        .filter(s -> s.name.toLowerCase(Locale.ROOT).equals(wanted))
        .findFirst();
  }
}
