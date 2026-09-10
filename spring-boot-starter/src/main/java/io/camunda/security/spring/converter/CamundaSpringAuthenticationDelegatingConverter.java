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
import io.camunda.security.api.model.exception.CamundaAuthenticationException;
import java.util.List;
import org.springframework.security.core.Authentication;

/**
 * A delegating {@link CamundaAuthenticationConverter} that converts Spring Security {@link
 * Authentication} objects to {@link CamundaAuthentication} by delegating to the first matching
 * converter in a prioritized list.
 *
 * <p>This converter always reports {@link #supports(Authentication) supports} as {@code true},
 * acting as a catch-all entry point. The actual conversion is delegated to the first converter in
 * the configured list whose {@code supports} method returns {@code true} for the given
 * authentication.
 *
 * <p>If no matching converter is found for a non-{@code null} authentication, a {@link
 * CamundaAuthenticationException} is thrown. If the input is {@code null} and no converter declares
 * support for {@code null} (e.g. an {@code UnprotectedCamundaAuthenticationConverter} is not
 * active), {@code null} is returned instead — this is not a configuration error: it is the normal
 * shape of an unauthenticated request on a permit-all path, and {@link
 * io.camunda.security.spring.context.DefaultCamundaAuthenticationProvider} already treats a {@code
 * null} converter result as "no authentication".
 */
public class CamundaSpringAuthenticationDelegatingConverter
    implements CamundaAuthenticationConverter<Authentication> {

  private final List<CamundaAuthenticationConverter<Authentication>> converters;

  public CamundaSpringAuthenticationDelegatingConverter(
      final List<CamundaAuthenticationConverter<Authentication>> converters) {
    this.converters = converters;
  }

  /**
   * Always returns {@code true}, as this converter acts as a catch-all that delegates to a specific
   * converter at conversion time.
   *
   * @param authentication the Spring Security authentication object
   * @return {@code true} always
   */
  @Override
  public boolean supports(final Authentication authentication) {
    return true;
  }

  /**
   * Converts the given Spring Security {@link Authentication} to a {@link CamundaAuthentication} by
   * delegating to the first matching converter.
   *
   * @param authentication the Spring Security authentication object to convert, may be {@code null}
   * @return the resulting {@link CamundaAuthentication}, or {@code null} if {@code authentication}
   *     is {@code null} and no converter declares support for {@code null}
   * @throws CamundaAuthenticationException if {@code authentication} is non-{@code null} and no
   *     converter supports its type
   */
  @Override
  public CamundaAuthentication convert(final Authentication authentication) {
    final var converter = getConverter(authentication);
    return converter == null ? null : converter.convert(authentication);
  }

  /**
   * Finds the first converter in the delegate list that supports the given authentication.
   *
   * @param authentication the Spring Security authentication object, may be {@code null}
   * @return the first matching {@link CamundaAuthenticationConverter}, or {@code null} if {@code
   *     authentication} is {@code null} and no converter in the list supports {@code null}
   * @throws CamundaAuthenticationException if {@code authentication} is non-{@code null} and no
   *     converter in the list supports its type
   */
  protected CamundaAuthenticationConverter<Authentication> getConverter(
      final Authentication authentication) {
    final var match =
        converters.stream().filter(c -> c != this && c.supports(authentication)).findFirst();
    if (match.isPresent()) {
      return match.get();
    }
    if (authentication == null) {
      return null;
    }
    final var message =
        "Did not find a matching converter to convert a Spring Authentication '%s' to a Camunda Authentication"
            .formatted(authentication.getClass().getName());
    throw new CamundaAuthenticationException(message);
  }
}
