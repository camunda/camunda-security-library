/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.out;

import io.camunda.security.core.scim.ScimUserResource;
import java.util.List;
import java.util.Optional;

/** Outbound port through which the host persists SCIM Users. */
public interface ScimUserRepositoryPort {

  /** Inserts or overwrites the User with the same {@code id}. */
  ScimUserResource save(ScimUserResource user);

  Optional<ScimUserResource> findById(String id);

  /** Finds a User by {@code userName}, compared case-insensitively. */
  Optional<ScimUserResource> findByUserName(String userName);

  List<ScimUserResource> findAll();

  /** Removes the User; returns whether it existed. */
  boolean deleteById(String id);
}
