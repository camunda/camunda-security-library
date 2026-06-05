/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.user;

import static org.assertj.core.api.Assertions.assertThat;

import io.camunda.security.api.context.CamundaAuthenticationProvider;
import io.camunda.security.api.model.user.CamundaUserDTO;
import io.camunda.security.core.port.in.CamundaUserPort;
import io.camunda.security.core.port.out.UserDetailsPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

class UserConfigurationTest {

  private final WebApplicationContextRunner runner =
      new WebApplicationContextRunner()
          .withBean(CamundaSecurityLibraryProperties.class)
          .withBean(
              CamundaAuthenticationProvider.class,
              () -> Mockito.mock(CamundaAuthenticationProvider.class))
          .withBean(
              OAuth2AuthorizedClientRepository.class,
              () -> Mockito.mock(OAuth2AuthorizedClientRepository.class))
          .withConfiguration(AutoConfigurations.of(UserConfiguration.class));

  @Test
  void registersOidcCamundaUserPortWhenAuthenticationMethodIsOidc() {
    runner
        .withPropertyValues("camunda.security.authentication.method=oidc")
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(CamundaUserPort.class)
                    .getBean(CamundaUserPort.class)
                    .isInstanceOf(OidcCamundaUserService.class));
  }

  @Test
  void doesNotRegisterCamundaUserPortWhenAuthenticationMethodIsNotOidc() {
    runner
        .withPropertyValues("camunda.security.authentication.method=basic")
        .run(ctx -> assertThat(ctx).doesNotHaveBean(CamundaUserPort.class));
  }

  @Test
  void hostCamundaUserPortBeanWins() {
    runner
        .withPropertyValues("camunda.security.authentication.method=oidc")
        .withUserConfiguration(HostCamundaUserPortConfiguration.class)
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(CamundaUserPort.class)
                    .getBean(CamundaUserPort.class)
                    .isInstanceOf(HostCamundaUserPortConfiguration.HostCamundaUserPort.class));
  }

  @Test
  void registersCamundaUserDetailsServiceWhenBasicAndPortPresent() {
    runner
        .withPropertyValues("camunda.security.authentication.method=basic")
        .withUserConfiguration(HostUserDetailsPortConfiguration.class)
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(UserDetailsService.class)
                    .getBean(UserDetailsService.class)
                    .isInstanceOf(CamundaUserDetailsService.class));
  }

  @Test
  void doesNotRegisterUserDetailsServiceWhenNoUserDetailsPort() {
    runner
        .withPropertyValues("camunda.security.authentication.method=basic")
        .run(ctx -> assertThat(ctx).doesNotHaveBean(UserDetailsService.class));
  }

  @Test
  void hostUserDetailsServiceWins() {
    runner
        .withPropertyValues("camunda.security.authentication.method=basic")
        .withUserConfiguration(
            HostUserDetailsPortConfiguration.class, HostUserDetailsServiceConfiguration.class)
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(UserDetailsService.class)
                    .getBean(UserDetailsService.class)
                    .isInstanceOf(
                        HostUserDetailsServiceConfiguration.HostUserDetailsService.class));
  }

  @Test
  void doesNotRegisterCamundaUserDetailsServiceWhenOidc() {
    runner
        .withPropertyValues("camunda.security.authentication.method=oidc")
        .withUserConfiguration(HostUserDetailsPortConfiguration.class)
        .run(ctx -> assertThat(ctx).doesNotHaveBean(CamundaUserDetailsService.class));
  }

  @Test
  void registersDefaultPasswordEncoderUnderBasic() {
    runner
        .withPropertyValues("camunda.security.authentication.method=basic")
        .run(ctx -> assertThat(ctx).hasSingleBean(PasswordEncoder.class));
  }

  @Test
  void hostPasswordEncoderWins() {
    runner
        .withPropertyValues("camunda.security.authentication.method=basic")
        .withUserConfiguration(HostPasswordEncoderConfiguration.class)
        .run(
            ctx ->
                assertThat(ctx)
                    .hasSingleBean(PasswordEncoder.class)
                    .getBean(PasswordEncoder.class)
                    .isSameAs(HostPasswordEncoderConfiguration.NOOP));
  }

  // End-to-end credential verification through the real basic-auth chain (proving Spring Boot
  // assembles the AuthenticationManager from the CSL UserDetailsService + PasswordEncoder beans)
  // lives in BasicAuthApiChainAuthenticationTest. This class covers conditional bean
  // wiring/back-off.

  @Configuration
  static class HostCamundaUserPortConfiguration {

    @Bean
    CamundaUserPort hostCamundaUserPort() {
      return new HostCamundaUserPort();
    }

    static final class HostCamundaUserPort implements CamundaUserPort {

      @Override
      public CamundaUserDTO getCurrentUser() {
        return null;
      }

      @Override
      public String getUserToken() {
        return null;
      }
    }
  }

  @Configuration
  static class HostUserDetailsPortConfiguration {

    @Bean
    UserDetailsPort hostUserDetailsPort() {
      // A mock so individual tests can stub specific usernames as needed.
      return Mockito.mock(UserDetailsPort.class);
    }
  }

  @Configuration
  static class HostUserDetailsServiceConfiguration {

    @Bean
    UserDetailsService hostUserDetailsService() {
      return new HostUserDetailsService();
    }

    static final class HostUserDetailsService implements UserDetailsService {

      @Override
      public org.springframework.security.core.userdetails.UserDetails loadUserByUsername(
          final String username) {
        throw new UsernameNotFoundException(username);
      }
    }
  }

  @Configuration
  static class HostPasswordEncoderConfiguration {

    static final PasswordEncoder NOOP =
        new PasswordEncoder() {
          @Override
          public String encode(final CharSequence rawPassword) {
            return rawPassword.toString();
          }

          @Override
          public boolean matches(final CharSequence rawPassword, final String encodedPassword) {
            return rawPassword.toString().equals(encodedPassword);
          }
        };

    @Bean
    PasswordEncoder hostPasswordEncoder() {
      return NOOP;
    }
  }
}
