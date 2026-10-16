/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.scim;

import java.time.Instant;
import java.util.Map;

/**
 * A stored SCIM User. The attribute tree is the neutral SCIM representation (strings, booleans,
 * numbers, maps, lists) with canonical attribute names; extension attributes live in a nested map
 * keyed by the extension schema URN. {@code id}, {@code schemas} and {@code meta} are not part of
 * {@code attributes}.
 *
 * @param id server-assigned identifier
 * @param attributes the validated attribute tree
 * @param created creation time
 * @param lastModified last modification time
 * @param version monotonically increasing revision, starting at 1
 */
public record ScimUserResource(
    String id,
    Map<String, Object> attributes,
    Instant created,
    Instant lastModified,
    long version) {

  public ScimUserResource {
    attributes = ScimTrees.deepCopy(attributes);
  }

  public String userName() {
    return (String) attributes.get("userName");
  }

  public ScimUserResource withAttributes(
      final Map<String, Object> newAttributes, final Instant now) {
    return new ScimUserResource(id, newAttributes, created, now, version + 1);
  }
}
