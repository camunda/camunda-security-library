/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.scim;

import io.camunda.security.core.scim.ScimAttribute.Type;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * A SCIM schema: its URN and top-level attributes.
 *
 * @param urn the schema URN
 * @param attributes the top-level attribute definitions
 */
public record ScimSchema(String urn, List<ScimAttribute> attributes) {

  private static final ScimAttribute[] MULTI_SIMPLE = {
    ScimAttribute.string("value"),
    ScimAttribute.string("display"),
    ScimAttribute.string("type"),
    ScimAttribute.bool("primary")
  };

  /**
   * RFC 7643 §4.1 core User schema, plus the common {@code id}, {@code externalId}, {@code meta}.
   */
  public static final ScimSchema USER =
      new ScimSchema(
          ScimSchemas.USER,
          List.of(
              ScimAttribute.string("id").asReadOnly().asCaseExact(),
              ScimAttribute.string("externalId").asCaseExact(),
              ScimAttribute.complex("meta").asReadOnly(),
              ScimAttribute.string("userName").asRequired(),
              ScimAttribute.complex(
                  "name",
                  ScimAttribute.string("formatted"),
                  ScimAttribute.string("familyName"),
                  ScimAttribute.string("givenName"),
                  ScimAttribute.string("middleName"),
                  ScimAttribute.string("honorificPrefix"),
                  ScimAttribute.string("honorificSuffix")),
              ScimAttribute.string("displayName"),
              ScimAttribute.string("nickName"),
              ScimAttribute.string("profileUrl"),
              ScimAttribute.string("title"),
              ScimAttribute.string("userType"),
              ScimAttribute.string("preferredLanguage"),
              ScimAttribute.string("locale"),
              ScimAttribute.string("timezone"),
              ScimAttribute.bool("active"),
              ScimAttribute.string("password"),
              ScimAttribute.multi("emails", MULTI_SIMPLE),
              ScimAttribute.multi("phoneNumbers", MULTI_SIMPLE),
              ScimAttribute.multi("ims", MULTI_SIMPLE),
              ScimAttribute.multi("photos", MULTI_SIMPLE),
              ScimAttribute.multi(
                  "addresses",
                  ScimAttribute.string("formatted"),
                  ScimAttribute.string("streetAddress"),
                  ScimAttribute.string("locality"),
                  ScimAttribute.string("region"),
                  ScimAttribute.string("postalCode"),
                  ScimAttribute.string("country"),
                  ScimAttribute.string("type"),
                  ScimAttribute.bool("primary")),
              ScimAttribute.multi(
                      "groups",
                      ScimAttribute.string("value"),
                      ScimAttribute.string("$ref"),
                      ScimAttribute.string("display"),
                      ScimAttribute.string("type"))
                  .asReadOnly(),
              ScimAttribute.multi("entitlements", MULTI_SIMPLE),
              ScimAttribute.multi("roles", MULTI_SIMPLE),
              ScimAttribute.multi("x509Certificates", MULTI_SIMPLE)));

  /** RFC 7643 §4.3 enterprise User extension. */
  public static final ScimSchema ENTERPRISE_USER =
      new ScimSchema(
          ScimSchemas.ENTERPRISE_USER,
          List.of(
              ScimAttribute.string("employeeNumber"),
              ScimAttribute.string("costCenter"),
              ScimAttribute.string("organization"),
              ScimAttribute.string("division"),
              ScimAttribute.string("department"),
              ScimAttribute.complex(
                  "manager",
                  ScimAttribute.string("value"),
                  ScimAttribute.string("$ref"),
                  ScimAttribute.string("displayName"))));

  /** Schemas a User resource may carry: core first, then extensions. */
  public static final List<ScimSchema> USER_EXTENSIONS = List.of(ENTERPRISE_USER);

  public ScimSchema {
    attributes = List.copyOf(attributes);
  }

  public Optional<ScimAttribute> attribute(final String name) {
    final String wanted = name.toLowerCase(Locale.ROOT);
    return attributes.stream()
        .filter(a -> a.name().toLowerCase(Locale.ROOT).equals(wanted))
        .findFirst();
  }

  /** Resolves an extension schema by (case-insensitive) URN. */
  public static Optional<ScimSchema> extension(final String urn) {
    return USER_EXTENSIONS.stream().filter(s -> s.urn().equalsIgnoreCase(urn)).findFirst();
  }

  /** Whether {@code type} is a plain (non-complex) type. */
  public static boolean isSimple(final Type type) {
    return type != Type.COMPLEX;
  }
}
