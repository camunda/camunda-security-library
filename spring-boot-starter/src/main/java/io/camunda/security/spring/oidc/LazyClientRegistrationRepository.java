/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.util.StringUtils;

/**
 * A {@link ClientRegistrationRepository} that runs OIDC discovery on first use of a registration
 * instead of when the repository is built.
 *
 * <p>{@link
 * org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository}
 * takes finished {@link ClientRegistration}s, so building one at startup means fetching every
 * issuer's discovery document while the application context comes up — an unreachable identity
 * provider then aborts the context and the deployment restart-loops until the provider is back.
 * Resolving per registration on first lookup keeps the startup path free of network calls: the
 * requests that need an unreachable provider fail, everything else keeps working, and the
 * deployment recovers without a restart.
 *
 * <p>Only successful resolutions are cached, so a failure is retried on the next lookup. The
 * configuration is validated without network access when the repository is constructed, so a
 * malformed provider block still fails the startup it is a bug in.
 *
 * <p>Iteration resolves every configured registration and therefore performs discovery. Callers on
 * the startup path must use {@link #registrationIds()} or {@link #clientNamesByRegistrationId()},
 * which answer from configuration alone; {@link Iterable} is implemented for hosts that enumerate
 * the repository per request.
 */
public final class LazyClientRegistrationRepository
    implements ClientRegistrationRepository, Iterable<ClientRegistration> {

  private final ScopedClientRegistrationFactory factory;
  private final Map<String, OidcConfiguration> providers;
  private final String scopedRedirectUriPath;
  private final String scopeDescription;
  private final Map<String, ClientRegistration> resolved = new ConcurrentHashMap<>();

  public LazyClientRegistrationRepository(
      final ScopedClientRegistrationFactory factory,
      final Map<String, OidcConfiguration> providers) {
    this(factory, providers, null, null);
  }

  /**
   * @param scopedRedirectUriPath per-scope redirect-uri path, see {@link
   *     ScopedClientRegistrationFactory#createFromProviderMap(Map, String)}
   * @param scopeDescription how to refer to the scope this repository serves in a failure log (e.g.
   *     {@code basePath=/physical-tenants/t1}), or {@code null} for the unscoped wording
   * @throws IllegalStateException if a provider block cannot produce a registration for reasons
   *     that need no network access (blank registrationId, no issuer-uri and incomplete endpoints)
   * @throws IllegalArgumentException if a configured redirect-uri is not absolute
   */
  public LazyClientRegistrationRepository(
      final ScopedClientRegistrationFactory factory,
      final Map<String, OidcConfiguration> providers,
      final String scopedRedirectUriPath,
      final String scopeDescription) {
    this.factory = Objects.requireNonNull(factory, "factory must not be null");
    this.providers =
        Collections.unmodifiableMap(
            new LinkedHashMap<>(Objects.requireNonNull(providers, "providers must not be null")));
    this.scopedRedirectUriPath = scopedRedirectUriPath;
    this.scopeDescription = scopeDescription;
    factory.validateWithoutNetwork(this.providers, scopedRedirectUriPath);
  }

  /** The configured registrationIds, in configuration order. Resolves nothing. */
  public Set<String> registrationIds() {
    return providers.keySet();
  }

  /**
   * The display name per registrationId that a resolved {@link ClientRegistration} would carry,
   * derived from configuration alone: the configured {@code client-name}, else the issuer-uri,
   * which is what {@link ClientRegistrations#fromIssuerLocation} puts on a discovered registration,
   * else the registrationId, which is the builder's own fallback for an explicit-endpoint
   * registration. Resolves nothing.
   */
  public Map<String, String> clientNamesByRegistrationId() {
    final var names = new LinkedHashMap<String, String>();
    providers.forEach((id, config) -> names.put(id, clientName(id, config)));
    return names;
  }

  private static String clientName(final String registrationId, final OidcConfiguration config) {
    if (StringUtils.hasText(config.getClientName())) {
      return config.getClientName();
    }
    return StringUtils.hasText(config.getIssuerUri()) ? config.getIssuerUri() : registrationId;
  }

  @Override
  public ClientRegistration findByRegistrationId(final String registrationId) {
    final var config = providers.get(registrationId);
    if (config == null) {
      return null;
    }
    final var cached = resolved.get(registrationId);
    if (cached != null) {
      return cached;
    }
    final var registration =
        DeferredOidcResolution.resolve(
            describe(registrationId, config),
            () ->
                factory
                    .createFromProviderMap(Map.of(registrationId, config), scopedRedirectUriPath)
                    .getFirst());
    resolved.putIfAbsent(registrationId, registration);
    return registration;
  }

  @Override
  public Iterator<ClientRegistration> iterator() {
    return providers.keySet().stream().map(this::findByRegistrationId).iterator();
  }

  private String describe(final String registrationId, final OidcConfiguration config) {
    return "OIDC client registration "
        + DeferredOidcResolution.describeProvider(registrationId, config)
        + (StringUtils.hasText(scopeDescription) ? " for " + scopeDescription : "");
  }
}
