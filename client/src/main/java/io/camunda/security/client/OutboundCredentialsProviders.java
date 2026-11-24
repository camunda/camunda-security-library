/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Immutable registry of {@link OutboundCredentialsProvider}s by client name. Closing it closes
 * every provider.
 */
public final class OutboundCredentialsProviders implements AutoCloseable {

  private static final Logger LOG = LoggerFactory.getLogger(OutboundCredentialsProviders.class);

  private final Map<String, OutboundCredentialsProvider> providers;

  public OutboundCredentialsProviders(final Map<String, OutboundCredentialsProvider> providers) {
    Objects.requireNonNull(providers, "providers must not be null");
    providers.forEach(
        (name, provider) -> {
          Objects.requireNonNull(name, "client name must not be null");
          Objects.requireNonNull(provider, "provider must not be null");
        });
    this.providers = Collections.unmodifiableMap(new LinkedHashMap<>(providers));
  }

  /**
   * @throws IllegalArgumentException if no client of that name is configured
   */
  public OutboundCredentialsProvider get(final String name) {
    final OutboundCredentialsProvider provider = providers.get(name);
    if (provider == null) {
      throw new IllegalArgumentException(
          "No outbound client named '" + name + "'; configured clients: " + providers.keySet());
    }
    return provider;
  }

  /** Closes all providers; a failing one is logged and does not stop the rest. */
  @Override
  public void close() {
    providers.forEach(OutboundCredentialsProviders::close);
  }

  private static void close(final String name, final OutboundCredentialsProvider provider) {
    try {
      provider.close();
    } catch (final Exception e) {
      LOG.warn("Closing the outbound client '{}' failed", name, e);
    }
  }

  public static OutboundCredentialsProvider oidc(final OidcClientCredentialsConfiguration config) {
    return new OidcClientCredentialsProvider(config);
  }

  public static OutboundCredentialsProvider basic(final BasicAuthConfiguration config) {
    return new BasicAuthCredentialsProvider(config);
  }
}
