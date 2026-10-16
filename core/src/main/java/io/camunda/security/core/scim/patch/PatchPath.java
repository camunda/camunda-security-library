/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.scim.patch;

import io.camunda.security.core.scim.ScimException;
import io.camunda.security.core.scim.ScimSchema;
import io.camunda.security.core.scim.ScimSchemas;
import io.camunda.security.core.scim.filter.ScimFilter;
import io.camunda.security.core.scim.filter.ScimFilter.AttributePath;
import io.camunda.security.core.scim.filter.ScimFilterParser;

/**
 * A parsed PATCH {@code path} (RFC 7644 §3.5.2): {@code [urn:]attr[.sub]} or {@code
 * [urn:]attr[filter][.sub]}.
 *
 * @param schemaUrn extension schema URN, or {@code null} for the core schema
 * @param attribute attribute name, or {@code null} when the path addresses a whole extension
 * @param filter value filter or {@code null}
 * @param sub sub-attribute name or {@code null}
 */
record PatchPath(String schemaUrn, String attribute, ScimFilter filter, String sub) {

  static PatchPath parse(final String raw) {
    final String path = raw.trim();
    if (path.isEmpty()) {
      throw ScimException.invalidPath("'path' must not be empty");
    }
    final var wholeExtension = ScimSchema.extension(path);
    if (wholeExtension.isPresent()) {
      return new PatchPath(wholeExtension.get().urn(), null, null, null);
    }
    try {
      final int open = path.indexOf('[');
      return open < 0 ? simple(path) : filtered(path, open);
    } catch (final ScimException e) {
      if ("invalidPath".equals(e.scimType())) {
        throw e;
      }
      throw ScimException.invalidPath("Invalid path '" + path + "': " + e.getMessage());
    }
  }

  private static PatchPath simple(final String path) {
    final AttributePath ap = ScimFilterParser.parseAttributePath(path);
    return new PatchPath(resolveUrn(ap.schemaUrn()), ap.attribute(), null, ap.sub());
  }

  private static PatchPath filtered(final String path, final int open) {
    final AttributePath head = ScimFilterParser.parseAttributePath(path.substring(0, open));
    if (head.sub() != null) {
      throw ScimException.invalidPath("Invalid path '" + path + "'");
    }
    final int close = closingBracket(path, open);
    final ScimFilter filter = ScimFilterParser.parse(path.substring(open + 1, close));
    final String rest = path.substring(close + 1);
    String sub = null;
    if (!rest.isEmpty()) {
      if (rest.length() < 2 || rest.charAt(0) != '.') {
        throw ScimException.invalidPath("Invalid path '" + path + "'");
      }
      sub = rest.substring(1);
    }
    return new PatchPath(resolveUrn(head.schemaUrn()), head.attribute(), filter, sub);
  }

  private static int closingBracket(final String path, final int open) {
    boolean inString = false;
    for (int i = open + 1; i < path.length(); i++) {
      final char c = path.charAt(i);
      if (c == '\\' && inString) {
        i++;
      } else if (c == '"') {
        inString = !inString;
      } else if (c == ']' && !inString) {
        return i;
      }
    }
    throw ScimException.invalidPath("Missing ']' in path '" + path + "'");
  }

  private static String resolveUrn(final String urn) {
    if (urn == null || urn.equalsIgnoreCase(ScimSchemas.USER)) {
      return null;
    }
    return ScimSchema.extension(urn)
        .orElseThrow(() -> ScimException.invalidPath("Unknown schema '" + urn + "'"))
        .urn();
  }
}
