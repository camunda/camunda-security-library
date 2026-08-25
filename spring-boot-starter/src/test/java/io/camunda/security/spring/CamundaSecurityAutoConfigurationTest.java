/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.spring.authz.AuthorizationCheckerConfiguration;
import io.camunda.security.spring.authz.AuthorizationConfiguration;
import io.camunda.security.spring.context.CamundaAuthenticationBeansConfiguration;
import io.camunda.security.spring.cors.CorsBeansConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.oidc.OidcBeansConfiguration;
import io.camunda.security.spring.oidc.OidcClaimsProviderConfiguration;
import io.camunda.security.spring.oidc.OidcWebappClientBeansConfiguration;
import io.camunda.security.spring.oidc.ScopedOidcInfrastructureConfiguration;
import io.camunda.security.spring.scope.ScopedApiSecurityChainBuilderConfiguration;
import io.camunda.security.spring.scope.ScopedSecurityChainConfiguration;
import io.camunda.security.spring.security.AdminUserCheckFilterConfiguration;
import io.camunda.security.spring.security.BaseSecurityConfiguration;
import io.camunda.security.spring.security.BasicAuthApiSecurityConfiguration;
import io.camunda.security.spring.security.BasicAuthWebappSecurityConfiguration;
import io.camunda.security.spring.security.DefaultWebSessionFilterConfiguration;
import io.camunda.security.spring.security.OidcApiSecurityConfiguration;
import io.camunda.security.spring.security.OidcWebappSecurityConfiguration;
import io.camunda.security.spring.security.ScopedWebappSecurityChainBuilderConfiguration;
import io.camunda.security.spring.security.UnprotectedApiSecurityConfiguration;
import io.camunda.security.spring.security.WebAppAuthorizationFilterConfiguration;
import io.camunda.security.spring.user.UserConfiguration;
import java.io.IOException;
import java.net.URL;
import java.util.Collections;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.UrlResource;
import org.springframework.core.io.support.PropertiesLoaderUtils;

class CamundaSecurityAutoConfigurationTest {

  @Test
  void notRegisteredInAutoConfigurationImports() throws IOException {
    // Per ADR-0006, nothing in CSL activates from adding the Maven dependency alone. The umbrella
    // @AutoConfiguration must NOT be listed in CSL's own AutoConfiguration.imports file — hosts
    // opt in explicitly.
    final var loader = getClass().getClassLoader();
    final var importsResources =
        Collections.list(
            loader.getResources(
                "META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports"));
    for (final URL url : importsResources) {
      final var properties = PropertiesLoaderUtils.loadProperties(new UrlResource(url));
      assertThat(properties.stringPropertyNames())
          .as("CSL must not auto-register %s (ADR-0006)", url)
          .doesNotContain(CamundaSecurityAutoConfiguration.class.getName());
    }
  }

  @Test
  void isAnnotatedAsAutoConfiguration() {
    assertThat(CamundaSecurityAutoConfiguration.class.isAnnotationPresent(AutoConfiguration.class))
        .as(
            "%s must be an @AutoConfiguration so host opt-in via @ImportAutoConfiguration (or"
                + " AutoConfiguration.imports) triggers Spring's deferred condition evaluation",
            CamundaSecurityAutoConfiguration.class.getSimpleName())
        .isTrue();
  }

  @Test
  void importsEveryCslConfigurationClass() {
    // Static check on the @Import annotation. Verifying via a live application context would
    // require stubbing every host SPI; this slice instead pins the membership of the umbrella so
    // future configurations are not forgotten when they're added.
    final var importAnnotation = CamundaSecurityAutoConfiguration.class.getAnnotation(Import.class);
    assertThat(importAnnotation).isNotNull();
    assertThat(importAnnotation.value())
        .containsExactlyInAnyOrder(
            AuthorizationCheckerConfiguration.class,
            AuthorizationConfiguration.class,
            CamundaSecurityConfiguration.class,
            CamundaAuthenticationBeansConfiguration.class,
            BaseSecurityConfiguration.class,
            BasicAuthApiSecurityConfiguration.class,
            BasicAuthWebappSecurityConfiguration.class,
            DefaultWebSessionFilterConfiguration.class,
            OidcApiSecurityConfiguration.class,
            OidcWebappSecurityConfiguration.class,
            ScopedApiSecurityChainBuilderConfiguration.class,
            ScopedSecurityChainConfiguration.class,
            ScopedWebappSecurityChainBuilderConfiguration.class,
            UnprotectedApiSecurityConfiguration.class,
            AuthFailureHandlerConfiguration.class,
            CorsBeansConfiguration.class,
            OidcBeansConfiguration.class,
            OidcWebappClientBeansConfiguration.class,
            OidcClaimsProviderConfiguration.class,
            ScopedOidcInfrastructureConfiguration.class,
            WebAppAuthorizationFilterConfiguration.class,
            AdminUserCheckFilterConfiguration.class,
            UserConfiguration.class);
  }
}
