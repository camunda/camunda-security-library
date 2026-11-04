/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.api.model.config.client.OutboundClientConfiguration;
import io.camunda.security.client.OidcClientCredentialsProvider;
import io.camunda.security.client.OutboundCredentialsProviders;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

class OutboundCredentialsConfigurationTest {

  private static final String SECRET = "s3cr3t-value";
  private static final String P = "camunda.security.client.";

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class, OutboundCredentialsConfiguration.class));

  private static String[] oidc(final String name) {
    return new String[] {
      P + name + ".oidc.token-uri=https://idp.example.com/token",
      P + name + ".oidc.client-id=my-client",
      P + name + ".oidc.client-secret=" + SECRET
    };
  }

  private static String[] concat(final String[] base, final String... more) {
    final List<String> all = new ArrayList<>(List.of(base));
    all.addAll(List.of(more));
    return all.toArray(new String[0]);
  }

  private static List<String> messages(final Throwable failure) {
    final List<String> result = new ArrayList<>();
    for (Throwable t = failure; t != null; t = t.getCause()) {
      result.add(String.valueOf(t.getMessage()));
    }
    return result;
  }

  private static void assertFailsWith(
      final AssertableApplicationContext ctx, final String expected, final String... secrets) {
    assertThat(ctx).hasFailed();
    final List<String> messages = messages(ctx.getStartupFailure());
    assertThat(messages).anyMatch(m -> m.contains(expected));
    for (final String secret : secrets) {
      assertThat(messages).noneMatch(m -> m.contains(secret));
    }
  }

  @Test
  void createsEmptyRegistryWithoutClients() {
    runner.run(
        ctx -> {
          assertThat(ctx).hasSingleBean(OutboundCredentialsProviders.class);
          final var providers = ctx.getBean(OutboundCredentialsProviders.class);
          assertThatThrownBy(() -> providers.get("x")).isInstanceOf(IllegalArgumentException.class);
        });
  }

  @Test
  void createsOidcProvider() {
    runner
        .withPropertyValues(
            concat(oidc("hub"), P + "hub.oidc.scopes[0]=read", P + "hub.oidc.read-timeout=5s"))
        .run(
            ctx ->
                assertThat(ctx.getBean(OutboundCredentialsProviders.class).get("hub"))
                    .isInstanceOf(OidcClientCredentialsProvider.class));
  }

  @Test
  void createsBasicProvider() {
    runner
        .withPropertyValues(P + "ops.basic.username=ops", P + "ops.basic.password=pw")
        .run(
            ctx -> {
              final Map<String, String> headers = new HashMap<>();
              ctx.getBean(OutboundCredentialsProviders.class)
                  .get("ops")
                  .applyCredentials(headers::put);
              final String token =
                  Base64.getEncoder().encodeToString("ops:pw".getBytes(StandardCharsets.UTF_8));
              assertThat(headers).containsEntry("Authorization", "Basic " + token);
            });
  }

  @Test
  void bindsTwoClientsSideBySide() {
    runner
        .withPropertyValues(
            concat(oidc("hub"), P + "ops.basic.username=ops", P + "ops.basic.password=pw"))
        .run(
            ctx -> {
              final var providers = ctx.getBean(OutboundCredentialsProviders.class);
              assertThat(providers.get("hub")).isInstanceOf(OidcClientCredentialsProvider.class);
              assertThat(providers.get("ops")).isNotNull();
            });
  }

  @Test
  void failsWhenBothOidcAndBasicAreSet() {
    runner
        .withPropertyValues(
            concat(oidc("hub"), P + "hub.basic.username=u", P + "hub.basic.password=p"))
        .run(ctx -> assertFailsWith(ctx, P + "hub must set exactly one of oidc or basic"));
  }

  @Test
  void failsWhenNeitherOidcNorBasicIsSet() {
    // The binder ignores unknown keys, so an entry with neither block needs a hand-built bean.
    new ApplicationContextRunner()
        .withUserConfiguration(EmptyClientProperties.class, OutboundCredentialsConfiguration.class)
        .run(ctx -> assertFailsWith(ctx, P + "hub must set exactly one of oidc or basic"));
  }

  @Test
  void failsWhenTokenUriIsMissing() {
    runner
        .withPropertyValues(P + "hub.oidc.client-id=c", P + "hub.oidc.client-secret=" + SECRET)
        .run(ctx -> assertFailsWith(ctx, P + "hub.oidc.token-uri must be set", SECRET));
  }

  @Test
  void failsWhenTokenUriKeyIsMisspelled() {
    runner
        .withPropertyValues(
            P + "hub.oidc.tokn-uri=https://idp.example.com/token",
            P + "hub.oidc.client-id=c",
            P + "hub.oidc.client-secret=" + SECRET)
        .run(ctx -> assertFailsWith(ctx, P + "hub.oidc.token-uri must be set", SECRET));
  }

  @Test
  void doesNotLeakMalformedTokenUriWithUserInfo() {
    runner
        .withPropertyValues(
            P + "hub.oidc.token-uri=http://u:pw@ho st/token",
            P + "hub.oidc.client-id=c",
            P + "hub.oidc.client-secret=" + SECRET)
        .run(
            ctx ->
                assertFailsWith(
                    ctx, P + "hub.oidc.token-uri is not a valid URI", "pw", SECRET, "u:pw"));
  }

  @Test
  void rejectsTokenUriWithUserInfoWithoutLeakingIt() {
    runner
        .withPropertyValues(
            P + "hub.oidc.token-uri=https://user:pw@idp.example.com/token",
            P + "hub.oidc.client-id=c",
            P + "hub.oidc.client-secret=" + SECRET)
        .run(ctx -> assertFailsWith(ctx, "Invalid " + P + "hub.oidc:", "pw", SECRET));
  }

  @Test
  void rejectsBlankClientIdWithoutLeakingSecret() {
    runner
        .withPropertyValues(
            P + "hub.oidc.token-uri=https://idp.example.com/token",
            P + "hub.oidc.client-id=",
            P + "hub.oidc.client-secret=" + SECRET)
        .run(ctx -> assertFailsWith(ctx, "Invalid " + P + "hub.oidc:", SECRET));
  }

  @Test
  void rejectsBlankBasicUsername() {
    runner
        .withPropertyValues(P + "ops.basic.username=", P + "ops.basic.password=pw")
        .run(ctx -> assertFailsWith(ctx, "Invalid " + P + "ops.basic:", "pw"));
  }

  @Test
  void rejectsBasicUsernameWithColon() {
    runner
        .withPropertyValues(P + "ops.basic.username=a:b", P + "ops.basic.password=pw")
        .run(ctx -> assertFailsWith(ctx, "Invalid " + P + "ops.basic:", "pw"));
  }

  @Test
  void rejectsMissingBasicPassword() {
    runner
        .withPropertyValues(P + "ops.basic.username=ops")
        .run(ctx -> assertFailsWith(ctx, P + "ops.basic.password must be set"));
  }

  @Test
  void backsOffWhenHostProvidesOwnBean() {
    runner
        .withUserConfiguration(HostConfiguration.class)
        .withPropertyValues(oidc("hub"))
        .run(
            ctx -> {
              assertThat(ctx).hasSingleBean(OutboundCredentialsProviders.class);
              assertThat(ctx.getBean(OutboundCredentialsProviders.class))
                  .isSameAs(HostConfiguration.HOST_BEAN);
            });
  }

  @Test
  void usesInferredDestroyMethodSoSpringClosesTheRegistry() {
    runner.run(
        ctx -> {
          final var definition =
              ctx.getSourceApplicationContext()
                  .getBeanFactory()
                  .getBeanDefinition("outboundCredentialsProviders");
          assertThat(((AbstractBeanDefinition) definition).getDestroyMethodName())
              .isEqualTo(AbstractBeanDefinition.INFER_METHOD);
        });
  }

  @Configuration
  static class EmptyClientProperties {
    @Bean
    CamundaSecurityLibraryProperties properties() {
      final var properties = new CamundaSecurityLibraryProperties();
      properties.setClient(Map.of("hub", new OutboundClientConfiguration()));
      return properties;
    }
  }

  @Configuration
  static class HostConfiguration {
    static final OutboundCredentialsProviders HOST_BEAN =
        new OutboundCredentialsProviders(Map.of());

    @Bean
    OutboundCredentialsProviders hostProviders() {
      return HOST_BEAN;
    }
  }
}
