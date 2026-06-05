/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.user;

import io.camunda.security.api.context.CamundaAuthenticationProvider;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.core.port.in.CamundaUserPort;
import io.camunda.security.core.port.out.AuthorizedComponentsPort;
import io.camunda.security.core.port.out.UserDetailsPort;
import io.camunda.security.spring.annotation.ConditionalOnAuthenticationMethod;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

/**
 * Wires user-service defaults supplied by CSL. Provides {@link OidcCamundaUserService} as the
 * CSL-default {@link CamundaUserPort} for OIDC deployments and an empty-list fallback for {@link
 * AuthorizedComponentsPort} so the default service is runnable in isolation. Hosts register a
 * richer {@link CamundaUserPort} and/or a real {@link AuthorizedComponentsPort} adapter; both
 * defaults back off via {@code @ConditionalOnMissingBean}.
 *
 * <p>For HTTP Basic deployments it also provides the {@link UserDetailsService} that backs the
 * basic-auth chains (delegating to the host-supplied {@link UserDetailsPort}) and a default
 * delegating {@link PasswordEncoder}. Both are guarded so a host can override them; the {@code
 * UserDetailsService} only activates when a {@link UserDetailsPort} bean is present. Spring Boot's
 * {@code InitializeUserDetailsBeanManagerConfigurer} assembles the global {@code
 * AuthenticationManager} from these two beans, so the basic-auth filter chains need no change.
 */
@Configuration
public class UserConfiguration {

  @Bean
  @ConditionalOnMissingBean(AuthorizedComponentsPort.class)
  public AuthorizedComponentsPort emptyAuthorizedComponentsPort() {
    return authentication -> List.of();
  }

  @Bean
  @ConditionalOnMissingBean(CamundaUserPort.class)
  @ConditionalOnAuthenticationMethod(AuthenticationMethod.OIDC)
  public CamundaUserPort oidcCamundaUserService(
      final CamundaAuthenticationProvider authenticationProvider,
      final AuthorizedComponentsPort authorizedComponentsPort,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final HttpServletRequest request) {
    return new OidcCamundaUserService(
        authenticationProvider, authorizedComponentsPort, authorizedClientRepository, request);
  }

  @Bean
  @ConditionalOnMissingBean(UserDetailsService.class)
  @ConditionalOnBean(UserDetailsPort.class)
  @ConditionalOnAuthenticationMethod(AuthenticationMethod.BASIC)
  public UserDetailsService camundaUserDetailsService(final UserDetailsPort userDetailsPort) {
    return new CamundaUserDetailsService(userDetailsPort);
  }

  @Bean
  @ConditionalOnMissingBean(PasswordEncoder.class)
  @ConditionalOnAuthenticationMethod(AuthenticationMethod.BASIC)
  public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }
}
