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
import io.camunda.security.api.context.MembershipResolutionContextPropagator;
import io.camunda.security.core.authz.LazyTokenClaimsConverter;
import io.camunda.security.core.context.holder.CamundaAuthenticationDelegatingHolder;
import io.camunda.security.core.port.out.MembershipPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.annotation.ConditionalOnUnprotectedApi;
import io.camunda.security.spring.context.holder.HttpSessionBasedAuthenticationHolder;
import io.camunda.security.spring.context.holder.RequestContextBasedAuthenticationHolder;
import io.camunda.security.spring.converter.CamundaSpringAuthenticationDelegatingConverter;
import io.camunda.security.spring.converter.UnprotectedCamundaAuthenticationConverter;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;

/**
 * Default authentication bean wiring for CSL hosts. Provides the core authentication holder and
 * provider beans that hosts need to resolve the current {@link
 * io.camunda.security.api.model.CamundaAuthentication}.
 *
 * <p>Every bean carries {@link ConditionalOnMissingBean} so a host application (e.g., OC) that
 * registers its own version of a bean suppresses the CSL default. OC overrides these with its own
 * {@code CamundaAuthenticationConfiguration}, which adds OC-specific conditionals.
 */
@Configuration(proxyBeanMethods = false)
public class CamundaAuthenticationBeansConfiguration {

  @Bean
  @ConditionalOnUnprotectedApi
  @ConditionalOnMissingBean(name = "unprotectedAuthenticationConverter")
  public CamundaAuthenticationConverter<Authentication> unprotectedAuthenticationConverter() {
    return new UnprotectedCamundaAuthenticationConverter();
  }

  @Bean
  @ConditionalOnMissingBean(name = "requestContextBasedAuthenticationHolder")
  public CamundaAuthenticationHolder requestContextBasedAuthenticationHolder(
      final HttpServletRequest request) {
    return new RequestContextBasedAuthenticationHolder(request);
  }

  @Bean
  @ConditionalOnMissingBean(name = "httpSessionBasedAuthenticationHolder")
  public CamundaAuthenticationHolder httpSessionBasedAuthenticationHolder(
      final HttpServletRequest request, final CamundaSecurityLibraryProperties properties) {
    return new HttpSessionBasedAuthenticationHolder(request, properties.getAuthentication());
  }

  /**
   * Default {@link MembershipResolutionContextPropagator} for the lazy membership-resolution path
   * (used by {@code LazyTokenClaimsConverter}). The library default performs no decoration ({@link
   * MembershipResolutionContextPropagator#identity()}), preserving the plain lazy behaviour. A host
   * whose {@code MembershipPort} depends on request-scoped state (e.g. a multi-tenant routing key)
   * registers its own {@link MembershipResolutionContextPropagator} bean to capture and rebind that
   * state around the deferred lookups; {@link ConditionalOnMissingBean} backs this default off when
   * the host does so.
   */
  @Bean
  @ConditionalOnMissingBean
  public MembershipResolutionContextPropagator membershipResolutionContextPropagator() {
    return MembershipResolutionContextPropagator.identity();
  }

  /**
   * Default {@link LazyTokenClaimsConverter} wired from OIDC configuration and the host-supplied
   * {@link MembershipPort}. Hosts that need custom claim names or a different conversion strategy
   * register their own {@link LazyTokenClaimsConverter} bean; {@link ConditionalOnMissingBean}
   * backs this default off when they do.
   */
  @Bean
  @ConditionalOnBean(MembershipPort.class)
  @ConditionalOnMissingBean
  public LazyTokenClaimsConverter lazyTokenClaimsConverter(
      final CamundaSecurityLibraryProperties properties,
      final MembershipPort membershipPort,
      final MembershipResolutionContextPropagator contextPropagator) {
    final var oidc = properties.getAuthentication().getOidc();
    return new LazyTokenClaimsConverter(
        oidc.getUsernameClaim(),
        oidc.getClientIdClaim(),
        oidc.isPreferUsernameClaim(),
        membershipPort,
        contextPropagator);
  }

  @Bean
  @ConditionalOnMissingBean
  public CamundaAuthenticationProvider camundaAuthenticationProvider(
      final List<CamundaAuthenticationHolder> holders,
      final List<CamundaAuthenticationConverter<Authentication>> converters) {
    return new DefaultCamundaAuthenticationProvider(
        new CamundaAuthenticationDelegatingHolder(holders),
        new CamundaSpringAuthenticationDelegatingConverter(converters));
  }
}
