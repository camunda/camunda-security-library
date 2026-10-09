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
 * Builds a host's query model from a {@link ResourceAccessFilter}, see {@link
 * ResourceAccessFilter#translate(ResourceAccessFilterTranslator)}. The host decides how an
 * attribute and the resource ID map to its storage, e.g. to columns, paths or search clauses.
 *
 * @param <R> the host's query model, e.g. a JPA specification
 */
public interface ResourceAccessFilterTranslator<R> {

  /** A query that matches every resource. */
  R matchAll();

  /** A query that matches no resource. */
  R matchNone();

  /** A query that matches the resources that match at least one of {@code alternatives}. */
  R anyOf(List<R> alternatives);

  /** A query that matches the resources that match all of {@code parts}. */
  R allOf(List<R> parts);

  /** A query that matches the resources whose ID is one of {@code resourceIds}. */
  R resourceIds(Set<String> resourceIds);

  /** A query that matches the resources whose {@code attribute} has a value in {@code values}. */
  R condition(ResourceAttribute attribute, Set<String> values);
}
