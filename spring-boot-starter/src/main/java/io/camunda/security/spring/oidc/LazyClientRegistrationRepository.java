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
 * A {@link ClientRegistrationRepository} that makes OIDC discovery at the first use of a
 * registration, and not while the application builds the repository. An unreachable identity
 * provider therefore fails the requests that need it, and not the start. The repository keeps a
 * resolved registration after a successful lookup only, so the next lookup makes a new attempt
 * after a failed one. The constructor validates the configuration without network access, so an
 * incorrect provider block still stops the start.
 *
 * <p>Iteration resolves each registration, and therefore makes discovery. A caller that runs while
 * the application starts must use {@link #registrationIds()} or {@link
 * #clientNamesByRegistrationId()}, which answer from the configuration alone.
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
   * @param scopedRedirectUriPath the redirect-uri path of the scope, see {@link
   *     ScopedClientRegistrationFactory#createFromProviderMap(Map, String)}
   * @param scopeDescription the name a failure log gives to the scope this repository serves (for
   *     example {@code basePath=/physical-tenants/t1}), or {@code null} for the unscoped text
   * @throws IllegalStateException if a provider block gives no registration for a reason that needs
   *     no network access, such as a blank registrationId, or no issuer-uri together with
   *     incomplete endpoints
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

  /** The configured registrationIds, in the order of the configuration. Resolves nothing. */
  public Set<String> registrationIds() {
    return providers.keySet();
  }

  /**
   * The display name that a resolved {@link ClientRegistration} carries, for each registrationId,
   * from the configuration alone. The method takes the configured {@code client-name}. If the
   * configuration sets none, it takes the issuer-uri, which is the name {@link
   * ClientRegistrations#fromIssuerLocation} gives a discovered registration. If the configuration
   * sets no issuer-uri either, it takes the registrationId, which is the name the builder gives a
   * registration with explicit endpoints. Resolves nothing.
   */
  public Map<String, String> clientNamesByRegistrationId() {
    final var names = new LinkedHashMap<String, String>();
    providers.forEach((id, config) -> names.put(id, clientName(id, config)));
    return names;
  }

  /** Names each configured provider, as a failure log of this repository names it. */
  public String providerDescriptions() {
    return DeferredOidcResolution.describeProviders(providers);
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
    // Two lookups of the same registration each make their own attempt. A single-flight lock
    // would hold one caller for the complete discovery timeout of the other attempt, which is 30
    // seconds for an unreachable provider. The first result wins.
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
    final var winner = resolved.putIfAbsent(registrationId, registration);
    return winner != null ? winner : registration;
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
