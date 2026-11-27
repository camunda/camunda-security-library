/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.authz;

import io.camunda.security.api.model.authz.ResourceAttribute;
import java.util.List;
import java.util.Set;

/**
 * Builds a host's query from a {@link ResourceAccessFilter}; see {@link
 * ResourceAccessFilter#translate(ResourceAccessFilterTranslator)}. The host decides how the
 * resource ID and each {@link ResourceAttribute} map to its storage, for example to columns or
 * search fields.
 *
 * <p>A host that cannot express an attribute must throw from {@link #attributeEquals}, or return
 * {@link #matchNone()}. It must never return {@link #matchAll()}, because that would grant access
 * to resources that the single check denies (ADR-0041 D4).
 *
 * @param <R> the host's query model, for example a JPA specification
 */
public interface ResourceAccessFilterTranslator<R> {

  /** Returns a query that matches every resource. */
  R matchAll();

  /** Returns a query that matches no resource. */
  R matchNone();

  /** Returns a query that matches the resources that match at least one of {@code queries}. */
  R anyOf(List<R> queries);

  /**
   * Returns a query that matches the resources that match all of {@code queries}. A filter term
   * always has at least one part, so {@code queries} is not empty.
   */
  R allOf(List<R> queries);

  /** Returns a query that matches the resources whose ID is in {@code resourceIds}. */
  R resourceIds(Set<String> resourceIds);

  /**
   * Returns a query that matches the resources that have {@code value} among the values of {@code
   * attribute}.
   */
  R attributeEquals(ResourceAttribute attribute, String value);
}
