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
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
 * <p>If no matching converter is found, a {@link CamundaAuthenticationException} is thrown and the
 * failure is logged at error level.
 */
public class CamundaSpringAuthenticationDelegatingConverter
    implements CamundaAuthenticationConverter<Authentication> {

  private static final Logger LOG =
      LoggerFactory.getLogger(CamundaSpringAuthenticationDelegatingConverter.class);

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
   * @param authentication the Spring Security authentication object to convert
   * @return the resulting {@link CamundaAuthentication}
   * @throws CamundaAuthenticationException if no converter supports the given authentication type
   */
  @Override
  public CamundaAuthentication convert(final Authentication authentication) {
    return getConverter(authentication).convert(authentication);
  }

  /**
   * Finds the first converter in the delegate list that supports the given authentication.
   *
   * @param authentication the Spring Security authentication object
   * @return the first matching {@link CamundaAuthenticationConverter}
   * @throws CamundaAuthenticationException if no converter in the list supports the given
   *     authentication type
   */
  protected CamundaAuthenticationConverter<Authentication> getConverter(
      final Authentication authentication) {
    return converters.stream()
        .filter(c -> c != this && c.supports(authentication))
        .findFirst()
        .orElseThrow(
            () -> {
              final var message =
                  "Did not find a matching converter to convert a Spring Authentication '%s' to a Camunda Authentication"
                      .formatted(
                          Optional.ofNullable(authentication)
                              .map(Authentication::getClass)
                              .map(Class::getName)
                              .orElse("null"));
              LOG.error(message);
              return new CamundaAuthenticationException(message);
            });
  }
}
