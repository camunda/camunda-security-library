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
import java.util.Map;

/**
 * Renders a stored User as the RFC 7643 JSON tree (with {@code schemas}, {@code id}, {@code meta}).
 */
public final class ScimUserRepresentation {

  private ScimUserRepresentation() {}

  /**
   * @param user the stored user
   * @param location absolute {@code meta.location}, or {@code null} to omit it
   */
  public static Map<String, Object> toDocument(final ScimUserResource user, final String location) {
    final Map<String, Object> doc = new LinkedHashMap<>();
    doc.put("schemas", schemasOf(user));
    doc.put("id", user.id());
    doc.putAll(ScimTrees.deepCopy(user.attributes()));
    final Map<String, Object> meta = new LinkedHashMap<>();
    meta.put("resourceType", "User");
    meta.put("created", user.created().toString());
    meta.put("lastModified", user.lastModified().toString());
    if (location != null) {
      meta.put("location", location);
    }
    meta.put("version", "W/\"" + user.version() + "\"");
    doc.put("meta", meta);
    return doc;
  }

  private static List<String> schemasOf(final ScimUserResource user) {
    final List<String> schemas = new ArrayList<>();
    schemas.add(ScimSchemas.USER);
    for (final ScimSchema extension : ScimSchema.USER_EXTENSIONS) {
      if (user.attributes().containsKey(extension.urn())) {
        schemas.add(extension.urn());
      }
    }
    return schemas;
  }
}
