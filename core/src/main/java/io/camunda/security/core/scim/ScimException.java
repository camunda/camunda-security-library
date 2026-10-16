/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.scim;

/**
 * Domain exception carrying the HTTP status and RFC 7644 §3.12 {@code scimType} of a failed SCIM
 * operation. Callers translate it to the transport's error representation.
 */
public final class ScimException extends RuntimeException {

  private static final long serialVersionUID = 1L;

  private final int status;
  private final String scimType;

  private ScimException(final int status, final String scimType, final String detail) {
    super(detail);
    this.status = status;
    this.scimType = scimType;
  }

  public int status() {
    return status;
  }

  /** The RFC 7644 {@code scimType} keyword, or {@code null} when none applies. */
  public String scimType() {
    return scimType;
  }

  public static ScimException invalidSyntax(final String detail) {
    return new ScimException(400, "invalidSyntax", detail);
  }

  public static ScimException invalidValue(final String detail) {
    return new ScimException(400, "invalidValue", detail);
  }

  public static ScimException invalidFilter(final String detail) {
    return new ScimException(400, "invalidFilter", detail);
  }

  public static ScimException invalidPath(final String detail) {
    return new ScimException(400, "invalidPath", detail);
  }

  public static ScimException noTarget(final String detail) {
    return new ScimException(400, "noTarget", detail);
  }

  public static ScimException mutability(final String detail) {
    return new ScimException(400, "mutability", detail);
  }

  public static ScimException uniqueness(final String detail) {
    return new ScimException(409, "uniqueness", detail);
  }

  public static ScimException notFound(final String detail) {
    return new ScimException(404, null, detail);
  }

  public static ScimException notImplemented(final String detail) {
    return new ScimException(501, null, detail);
  }

  public static ScimException methodNotAllowed(final String detail) {
    return new ScimException(405, null, detail);
  }

  public static ScimException unauthorized(final String detail) {
    return new ScimException(401, null, detail);
  }

  public static ScimException internal(final String detail) {
    return new ScimException(500, null, detail);
  }
}
