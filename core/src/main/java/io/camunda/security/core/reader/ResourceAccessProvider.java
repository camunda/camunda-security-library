/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.reader;

import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.core.auth.RequiredAuthorization;

/**
 * Resolves whether a principal represented by a {@link CamundaAuthentication} has access to a
 * resource governed by a {@link RequiredAuthorization}.
 *
 * <p>Implementations query the authorization store and return a {@link ResourceAccess} verdict that
 * records whether access is allowed, whether it was granted via a wildcard, and which requirement
 * was evaluated.
 *
 * <p>Three entry points cover the common evaluation patterns: pre-query scope resolution, per-
 * document evaluation during result streaming, and direct lookup by resource ID.
 */
public interface ResourceAccessProvider {

  /**
   * Resolves the broadest access the principal holds for the given {@code requiredAuthorization}
   * without reference to a specific document. Used to populate {@link ResourceAccessChecks} before
   * a query is executed so the search backend can add ID-based filters.
   *
   * @param authentication the resolved authentication context of the caller
   * @param requiredAuthorization the authorization requirement to evaluate
   */
  <T> ResourceAccess resolveResourceAccess(
      CamundaAuthentication authentication, RequiredAuthorization<T> requiredAuthorization);

  /**
   * Evaluates whether the principal has access to the given {@code resource} document. Called
   * per-document during result streaming when a pre-query filter is not sufficient.
   *
   * @param authentication the resolved authentication context of the caller
   * @param requiredAuthorization the authorization requirement to evaluate
   * @param resource the specific document to check access for
   */
  <T> ResourceAccess hasResourceAccess(
      CamundaAuthentication authentication,
      RequiredAuthorization<T> requiredAuthorization,
      T resource);

  /**
   * Evaluates whether the principal has access to the resource identified by {@code resourceId}.
   *
   * @param authentication the resolved authentication context of the caller
   * @param requiredAuthorization the authorization requirement to evaluate
   * @param resourceId the ID of the resource to check
   */
  <T> ResourceAccess hasResourceAccessByResourceId(
      CamundaAuthentication authentication,
      RequiredAuthorization<T> requiredAuthorization,
      String resourceId);
}
