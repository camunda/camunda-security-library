/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.port.in;

import io.camunda.security.core.scim.ScimException;
import io.camunda.security.core.scim.ScimUserPage;
import io.camunda.security.core.scim.ScimUserResource;
import java.util.Map;

/**
 * Inbound port for SCIM 2.0 User provisioning (RFC 7644 §3). Request bodies are the neutral JSON
 * tree (maps, lists, strings, booleans, numbers); failures are reported as {@link ScimException}.
 */
public interface ScimUserPort {

  /** Creates a User ({@code POST /Users}). */
  ScimUserResource create(Map<String, Object> body);

  /** Fetches a User ({@code GET /Users/{id}}). */
  ScimUserResource get(String id);

  /** Replaces a User ({@code PUT /Users/{id}}). */
  ScimUserResource replace(String id, Map<String, Object> body);

  /** Applies a PatchOp message ({@code PATCH /Users/{id}}). */
  ScimUserResource patch(String id, Map<String, Object> patchRequest);

  /** Deletes a User ({@code DELETE /Users/{id}}). */
  void delete(String id);

  /**
   * Searches Users ({@code GET /Users}).
   *
   * @param filter RFC 7644 filter expression or {@code null}
   * @param startIndex 1-based start index; values below 1 are treated as 1
   * @param count maximum page size; negative values are treated as 0
   */
  ScimUserPage search(String filter, int startIndex, int count);
}
