/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.converter;

import io.camunda.security.api.context.CamundaAuthenticationConverter;
import io.camunda.security.api.model.CamundaAuthentication;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Converter implementation that handles authentication when API protection is disabled.
 *
 * <p>This converter supports scenarios where:
 *
 * <ul>
 *   <li>API protection is disabled and the consolidated-auth profile is used, resulting in {@code
 *       null} authentication
 *   <li>API protection is disabled and no auth profile is used, resulting in an {@link
 *       AnonymousAuthenticationToken}
 * </ul>
 *
 * <p>In both cases, the converter converts the Spring Security authentication to a Camunda
 * anonymous authentication, allowing operations to proceed without specific user context.
 */
public class UnprotectedCamundaAuthenticationConverter
    implements CamundaAuthenticationConverter<Authentication> {

  /**
   * Determines whether this converter can handle the given authentication.
   *
   * <p>Supports both {@code null} authentication and {@link AnonymousAuthenticationToken}
   * instances, which occur when API protection is disabled.
   *
   * @param authentication the Spring Security authentication object, which may be {@code null}
   * @return {@code true} if the authentication is {@code null} or an {@link
   *     AnonymousAuthenticationToken}; {@code false} otherwise
   */
  @Override
  public boolean supports(final Authentication authentication) {
    // 1) apiProtection == false and consolidated-auth profile used => authentication == null
    // 2) apiProtection == false and no auth profile used => authentication ==
    // AnonymousAuthenticationToken
    return authentication == null || authentication instanceof AnonymousAuthenticationToken;
  }

  /**
   * Converts the given authentication to a Camunda anonymous authentication.
   *
   * <p>Since this converter handles unprotected scenarios, it always returns an anonymous
   * authentication, allowing the application to function without requiring user identification.
   *
   * @param authentication the Spring Security authentication object (may be {@code null})
   * @return a {@link CamundaAuthentication} representing an anonymous user
   */
  @Override
  public CamundaAuthentication convert(final Authentication authentication) {
    return CamundaAuthentication.anonymous();
  }
}
