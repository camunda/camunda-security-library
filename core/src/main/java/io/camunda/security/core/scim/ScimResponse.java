/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.scim;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Transport-neutral SCIM HTTP response.
 *
 * @param status HTTP status code
 * @param headers response headers to set (for example {@code Location})
 * @param body JSON tree to serialize, or {@code null} for no content
 */
public record ScimResponse(int status, Map<String, String> headers, Map<String, Object> body) {

  public ScimResponse {
    headers = Map.copyOf(headers);
  }

  public static ScimResponse of(final int status, final Map<String, Object> body) {
    return new ScimResponse(status, Map.of(), body);
  }

  /** RFC 7644 §3.12 error response. */
  public static ScimResponse error(final ScimException e) {
    return error(e.status(), e.scimType(), e.getMessage());
  }

  public static ScimResponse error(final int status, final String scimType, final String detail) {
    final Map<String, Object> body = new LinkedHashMap<>();
    body.put("schemas", List.of(ScimSchemas.ERROR));
    body.put("status", String.valueOf(status));
    if (scimType != null) {
      body.put("scimType", scimType);
    }
    body.put("detail", detail);
    return of(status, body);
  }
}
