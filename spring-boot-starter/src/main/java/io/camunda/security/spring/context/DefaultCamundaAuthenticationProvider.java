/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.context;

import io.camunda.security.api.context.CamundaAuthenticationConverter;
import io.camunda.security.api.context.CamundaAuthenticationHolder;
import io.camunda.security.api.context.CamundaAuthenticationProvider;
import io.camunda.security.api.model.CamundaAuthentication;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Default implementation of {@link CamundaAuthenticationProvider} that resolves the current {@link
 * CamundaAuthentication} from the Spring {@link
 * org.springframework.security.core.context.SecurityContext}, optionally caching the result in a
 * {@link CamundaAuthenticationHolder} for the duration of the current request.
 *
 * <p>Resolution follows this priority order:
 *
 * <ol>
 *   <li><b>Holder cache hit:</b> If a Spring {@link Authentication} is present in the {@code
 *       SecurityContext} <em>and</em> a {@link CamundaAuthentication} is already stored in the
 *       {@link CamundaAuthenticationHolder}, the cached value is returned immediately without
 *       invoking the converter again.
 *   <li><b>Converter fallback:</b> Otherwise the {@link CamundaAuthenticationConverter} is called
 *       with the current Spring {@link Authentication} (which may be {@code null}). This path also
 *       covers unauthenticated requests where an {@code UnprotectedCamundaAuthenticationConverter}
 *       is active and produces an anonymous {@link CamundaAuthentication}.
 *   <li><b>No authentication:</b> If the converter returns {@code null}, the holder is cleared and
 *       {@code null} is returned to the caller.
 * </ol>
 *
 * <p>After a successful converter call the result is stored in the holder so that subsequent calls
 * within the same request skip the converter entirely.
 */
public class DefaultCamundaAuthenticationProvider implements CamundaAuthenticationProvider {

  private static final Logger LOG =
      LoggerFactory.getLogger(DefaultCamundaAuthenticationProvider.class);

  private final CamundaAuthenticationHolder holder;
  private final CamundaAuthenticationConverter<Authentication> converter;

  public DefaultCamundaAuthenticationProvider(
      final CamundaAuthenticationHolder holder,
      final CamundaAuthenticationConverter<Authentication> converter) {
    this.holder = holder;
    this.converter = converter;
  }

  /**
   * Resolves the {@link CamundaAuthentication} for the current request.
   *
   * <p>Behavior:
   *
   * <ul>
   *   <li>If the Spring {@code SecurityContext} contains an {@link Authentication} <em>and</em> the
   *       holder already holds a {@link CamundaAuthentication}, the holder value is returned
   *       directly (cache hit — converter is <em>not</em> invoked).
   *   <li>If either condition is not met, the {@link CamundaAuthenticationConverter} is invoked
   *       with the current Spring {@link Authentication} (possibly {@code null} for fully anonymous
   *       access). A non-{@code null} result is stored in the holder for subsequent calls, and a
   *       {@code null} result clears the holder.
   * </ul>
   *
   * @return the resolved {@link CamundaAuthentication}, or {@code null} if neither the holder nor
   *     the converter can produce one
   */
  @Override
  public CamundaAuthentication getCamundaAuthentication() {
    final var springBasedAuthentication = SecurityContextHolder.getContext().getAuthentication();

    final var fromHolder = holder.get();

    // If we have a spring authentication, and it is in holder, return it from there.
    if (springBasedAuthentication != null && fromHolder != null) {
      LOG.trace("Found camunda authentication in holder: {}", fromHolder);
      return fromHolder;
    }

    // If not, we need nevertheless call the converter, because for unprotected API the
    // UnprotectedCamundaAuthenticationConverter is active which created an anonymous
    // authentication.
    final var result = converter.convert(springBasedAuthentication);
    if (result != null) {
      LOG.trace("Created camunda authentication: {}", result);
      holder.set(result);
    } else {
      LOG.trace("No camunda authentication found!");
      holder.clear();
    }

    return result;
  }
}
