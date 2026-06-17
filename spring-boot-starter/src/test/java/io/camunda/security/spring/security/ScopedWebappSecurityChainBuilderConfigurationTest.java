/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.handler.AuthFailureHandlerConfiguration;
import io.camunda.security.spring.scope.OAuth2AuthorizedClientManagerFactory;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@ExtendWith(MockitoExtension.class)
class ScopedWebappSecurityChainBuilderConfigurationTest {

  @Mock private ScopedWebappSecurityChainBuilder hostBean;

  @Test
  void shouldCreateBeanWhenCollaboratorsArePresent() {
    new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class))
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBean(ScopedWebappSecurityChainBuilder.class)).isNotNull();
              assertThat(ctx.getBean(OAuth2AuthorizedClientManagerFactory.class)).isNotNull();
            });
  }

  @Test
  void shouldBackOffWhenHostProvidesOwnBean() {
    new WebApplicationContextRunner()
        .withUserConfiguration(ObjectMapperConfig.class, StubPaths.class)
        .withBean(ScopedWebappSecurityChainBuilder.class, () -> hostBean)
        .withConfiguration(
            AutoConfigurations.of(
                CamundaSecurityConfiguration.class,
                AuthFailureHandlerConfiguration.class,
                ScopedWebappSecurityChainBuilderConfiguration.class))
        .run(
            ctx -> {
              assertThat(ctx).hasNotFailed();
              assertThat(ctx.getBean(ScopedWebappSecurityChainBuilder.class)).isSameAs(hostBean);
            });
  }

  @Configuration
  static class ObjectMapperConfig {

    @Bean
    ObjectMapper objectMapper() {
      return new ObjectMapper();
    }
  }

  @Configuration
  static class StubPaths {

    @Bean
    SecurityPathPort securityPathPort() {
      return new SecurityPathPort() {
        @Override
        public Set<String> apiPaths() {
          return Set.of("/api/**");
        }

        @Override
        public Set<String> unprotectedApiPaths() {
          return Set.of();
        }

        @Override
        public Set<String> unprotectedPaths() {
          return Set.of("/error");
        }

        @Override
        public Set<String> webappPaths() {
          return Set.of();
        }

        @Override
        public Set<String> webComponentNames() {
          return Set.of();
        }
      };
    }
  }
}
