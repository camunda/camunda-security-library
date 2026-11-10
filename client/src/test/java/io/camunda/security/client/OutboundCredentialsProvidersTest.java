/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.camunda.security.client.OutboundCredentialsProvider.StatusCode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class OutboundCredentialsProvidersTest {

  @Test
  void twoNamedClientsSendDifferentCredentials() throws IOException {
    try (final TokenEndpoint endpoint = new TokenEndpoint()) {
      final var providers =
          new OutboundCredentialsProviders(
              Map.of(
                  "hub",
                  OutboundCredentialsProviders.oidc(
                      new OidcClientCredentialsConfiguration(
                          endpoint.uri(), "hub-client", "secret", null, null, null, null, null)),
                  "legacy",
                  OutboundCredentialsProviders.basic(new BasicAuthConfiguration("demo", "demo"))));

      assertThat(header(providers.get("hub"))).isEqualTo("Bearer token-1");
      assertThat(header(providers.get("legacy"))).isEqualTo("Basic ZGVtbzpkZW1v");
      assertThat(providers.get("legacy").shouldRetryRequest(StatusCode.ofHttp(401))).isFalse();
    }
  }

  @Test
  void unknownNameNamesTheClientAndTheConfiguredOnes() {
    final var providers =
        new OutboundCredentialsProviders(
            Map.of(
                "hub", OutboundCredentialsProviders.basic(new BasicAuthConfiguration("u", "p"))));

    assertThatThrownBy(() -> providers.get("nope"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("'nope'")
        .hasMessageContaining("hub");
  }

  @Test
  void aNullProviderIsRejected() {
    final Map<String, OutboundCredentialsProvider> map = new HashMap<>();
    map.put("hub", null);

    assertThatThrownBy(() -> new OutboundCredentialsProviders(map))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void theRegistryDoesNotSeeLaterChangesToTheGivenMap() {
    final Map<String, OutboundCredentialsProvider> map = new HashMap<>();
    map.put("hub", OutboundCredentialsProviders.basic(new BasicAuthConfiguration("u", "p")));
    final var providers = new OutboundCredentialsProviders(map);

    map.put("late", OutboundCredentialsProviders.basic(new BasicAuthConfiguration("u", "p")));

    assertThatThrownBy(() -> providers.get("late")).isInstanceOf(IllegalArgumentException.class);
  }

  private static String header(final OutboundCredentialsProvider provider) throws IOException {
    final List<String> values = new ArrayList<>();
    provider.applyCredentials((name, value) -> values.add(value));
    return values.getFirst();
  }

  @Test
  void closeClosesEveryProviderEvenWhenOneFails() {
    final var failing = new ClosableProvider(true);
    final var healthy = new ClosableProvider(false);
    final var providers =
        new OutboundCredentialsProviders(
            Map.of(
                "failing", failing,
                "healthy", healthy,
                "basic", OutboundCredentialsProviders.basic(new BasicAuthConfiguration("u", "p"))));

    providers.close();

    assertThat(failing.closed).isTrue();
    assertThat(healthy.closed).isTrue();
  }

  private static final class ClosableProvider implements OutboundCredentialsProvider {
    private final boolean failOnClose;
    private boolean closed;

    ClosableProvider(final boolean failOnClose) {
      this.failOnClose = failOnClose;
    }

    @Override
    public void applyCredentials(final CredentialsApplier applier) {}

    @Override
    public boolean shouldRetryRequest(final StatusCode statusCode) {
      return false;
    }

    @Override
    public void close() {
      closed = true;
      if (failOnClose) {
        throw new IllegalStateException("boom");
      }
    }
  }
}
