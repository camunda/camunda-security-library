/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring;

import io.camunda.security.spring.authz.AuthorizationCheckerConfiguration;
import io.camunda.security.spring.context.CamundaAuthenticationBeansConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcBeansConfiguration;
import io.camunda.security.spring.security.AdminUserCheckFilterConfiguration;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.BasicAuthApiSecurityConfiguration;
import io.camunda.security.spring.security.BasicAuthWebappSecurityConfiguration;
import io.camunda.security.spring.security.OidcApiSecurityConfiguration;
import io.camunda.security.spring.security.OidcWebappSecurityConfiguration;
import io.camunda.security.spring.security.UnprotectedApiSecurityConfiguration;
import io.camunda.security.spring.security.WebAppAuthorizationFilterConfiguration;
import io.camunda.security.spring.user.UserConfiguration;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Import;

/**
 * Optional umbrella entry point that imports every CSL configuration class. Hosts that want the
 * full CSL stack active in their security context activate this class explicitly via either:
 *
 * <ul>
 *   <li>{@code @ImportAutoConfiguration(CamundaSecurityAutoConfiguration.class)} on one of their
 *       own configuration classes, or
 *   <li>listing it in their own {@code
 *       META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports} file.
 * </ul>
 *
 * <p>Per ADR-0008, this class is NOT registered in CSL's own {@code AutoConfiguration.imports} —
 * nothing in CSL activates from adding the Maven dependency alone. The host's explicit opt-in is
 * what enables it. Hosts that prefer fine-grained control over which CSL configurations are active
 * can still {@code @Import} individual classes directly instead of going through the umbrella; in
 * that path the host is responsible for working around the conditional-bean evaluation timing
 * described in ADR-0008.
 *
 * <p>Loading CSL configurations through this {@code @AutoConfiguration} causes Spring to evaluate
 * their {@code @ConditionalOnBean} / {@code @ConditionalOnMissingBean} gates in the deferred
 * auto-configuration phase — after every host {@code @Configuration} class has been parsed — so
 * host-supplied SPIs and overrides are visible when the CSL conditions fire.
 */
@AutoConfiguration
@Import({
  AuthorizationCheckerConfiguration.class,
  CamundaSecurityConfiguration.class,
  CamundaAuthenticationBeansConfiguration.class,
  BaseSecurityConfiguration.class,
  BasicAuthApiSecurityConfiguration.class,
  BasicAuthWebappSecurityConfiguration.class,
  OidcApiSecurityConfiguration.class,
  OidcWebappSecurityConfiguration.class,
  UnprotectedApiSecurityConfiguration.class,
  AuthFailureHandlerConfiguration.class,
  OidcBeansConfiguration.class,
  WebAppAuthorizationFilterConfiguration.class,
  AdminUserCheckFilterConfiguration.class,
  UserConfiguration.class,
})
public class CamundaSecurityAutoConfiguration {}
