/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

/**
 * Default {@link LogoutSuccessHandler} for the OIDC webapp chain. Preserves OC's RP-initiated
 * logout behaviour: a same-origin {@code Referer} header is stored as the post-logout redirect URI
 * on the session under {@link CamundaOidcLogoutSuccessHandler#POST_LOGOUT_REDIRECT_ATTRIBUTE}, and
 * the OIDC {@code login_hint} claim is forwarded as {@code logout_hint} to the IdP's end-session
 * endpoint.
 *
 * <p>The bean is registered behind {@link ConditionalOnMissingBean} so a host application that
 * registers its own {@link LogoutSuccessHandler} retains full control. {@link
 * OidcWebappSecurityConfiguration} picks the resulting bean up automatically via its existing
 * {@code ObjectProvider<LogoutSuccessHandler>} plumbing.
 */
@Configuration
@ConditionalOnProperty(name = "camunda.security.authentication.method", havingValue = "oidc")
public class OidcWebappLogoutConfiguration {

  @Bean
  @ConditionalOnMissingBean(LogoutSuccessHandler.class)
  public LogoutSuccessHandler camundaOidcLogoutSuccessHandler(
      final ClientRegistrationRepository clientRegistrationRepository) {
    return new CamundaOidcLogoutSuccessHandler(clientRegistrationRepository);
  }
}
