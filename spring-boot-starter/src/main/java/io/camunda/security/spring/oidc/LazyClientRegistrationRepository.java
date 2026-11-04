/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
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
 * after a failed one. The constructor validates the configuration without network access; a
 * provider block that fails such a check logs a {@code WARN} naming the provider and the problem,
 * rather than stopping the start (see {@link ScopedClientRegistrationFactory}'s class Javadoc).
 *
 * <p>Iteration resolves each registration, and therefore makes discovery. A caller that runs while
 * the application starts must use {@link #registrationIds()} or {@link
 * #clientNamesByRegistrationId()}, which answer from the configuration alone.
 */
public final class LazyClientRegistrationRepository
    implements ClientRegistrationRepository, Iterable<ClientRegistration> {

  private final ScopedClientRegistrationFactory factory;
  private final String scopedRedirectUriPath;
  private final String scopeDescription;
  private final ScopedClientRegistrationFactory.LoginRouteChecks loginRouteChecks;

  /**
   * The providers and the registrations resolved from them, replaced as a whole when credentials
   * rotate, so a lookup never pairs a registration with providers it was not built from.
   */
  private volatile State state;

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
   * @throws IllegalArgumentException if scopedRedirectUriPath is non-blank and does not start with
   *     '/'
   */
  public LazyClientRegistrationRepository(
      final ScopedClientRegistrationFactory factory,
      final Map<String, OidcConfiguration> providers,
      final String scopedRedirectUriPath,
      final String scopeDescription) {
    this(
        factory,
        providers,
        scopedRedirectUriPath,
        scopeDescription,
        ScopedClientRegistrationFactory.LoginRouteChecks.ENFORCED);
  }

  private LazyClientRegistrationRepository(
      final ScopedClientRegistrationFactory factory,
      final Map<String, OidcConfiguration> providers,
      final String scopedRedirectUriPath,
      final String scopeDescription,
      final ScopedClientRegistrationFactory.LoginRouteChecks loginRouteChecks) {
    this.factory = Objects.requireNonNull(factory, "factory must not be null");
    final var normalized =
        Collections.unmodifiableMap(
            new LinkedHashMap<>(Objects.requireNonNull(providers, "providers must not be null")));
    this.scopedRedirectUriPath = scopedRedirectUriPath;
    this.scopeDescription = scopeDescription;
    this.loginRouteChecks = loginRouteChecks;
    // Validated before filtering: a blank registrationId is warn-only, not rejected, and that
    // warning must still fire for it. ScopedClientRegistrationFactory#withoutBlankRegistrationIds
    // then keeps the entry out of every reader below (iterator(), findByRegistrationId(),
    // registrationIds(), providers()) in this one place, rather than each one filtering it again.
    if (loginRouteChecks == ScopedClientRegistrationFactory.LoginRouteChecks.SKIPPED) {
      factory.validateWithoutLoginRoutes(normalized);
    } else {
      factory.validateWithoutNetwork(normalized, scopedRedirectUriPath);
    }
    state =
        new State(
            Collections.unmodifiableMap(
                ScopedClientRegistrationFactory.withoutBlankRegistrationIds(normalized)),
            new ConcurrentHashMap<>());
  }

  /**
   * A repository for a caller that derives no browser login route from the configuration — a
   * bearer-only API chain, or the access-token refresh of an API chain
   * (camunda-security-library#662). It validates and resolves with {@link
   * ScopedClientRegistrationFactory.LoginRouteChecks#SKIPPED}, the same mode {@link
   * ScopedJwtDecoderFactory} and {@link ScopedOidcClaimsProviderFactory} use, so login-only checks
   * do not reject a configuration that no login route ever reads. In particular {@code
   * user-info-required=true} together with {@code user-info-enabled=false} is inert for such a
   * caller and must not fail its startup.
   *
   * @param scopeDescription the name a failure log gives to the scope this repository serves (for
   *     example {@code basePath=/physical-tenants/t1}), or {@code null} for the unscoped text
   */
  public static LazyClientRegistrationRepository withoutLoginRoutes(
      final ScopedClientRegistrationFactory factory,
      final Map<String, OidcConfiguration> providers,
      final String scopeDescription) {
    return new LazyClientRegistrationRepository(
        factory,
        providers,
        null,
        scopeDescription,
        ScopedClientRegistrationFactory.LoginRouteChecks.SKIPPED);
  }

  /** The configured registrationIds, in the order of the configuration. Resolves nothing. */
  public Set<String> registrationIds() {
    return state.providers().keySet();
  }

  /**
   * The provider configuration this repository resolves, keyed by registrationId. A caller that
   * routes a token by issuer takes the issuers from here, so the route and the registration it
   * reaches describe one provider. Resolves nothing.
   */
  public Map<String, OidcConfiguration> providers() {
    return state.providers();
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
    state.providers().forEach((id, config) -> names.put(id, clientName(id, config)));
    return names;
  }

  /** Names each configured provider, as a failure log of this repository names it. */
  public String providerDescriptions() {
    return DeferredOidcResolution.describeProviders(state.providers());
  }

  private static String clientName(final String registrationId, final OidcConfiguration config) {
    if (StringUtils.hasText(config.getClientName())) {
      return config.getClientName();
    }
    return StringUtils.hasText(config.getIssuerUri()) ? config.getIssuerUri() : registrationId;
  }

  /** The registrations resolved so far. Resolves nothing. */
  public Collection<ClientRegistration> resolvedRegistrations() {
    return List.copyOf(state.resolved().values());
  }

  @Override
  public ClientRegistration findByRegistrationId(final String registrationId) {
    final var current = state;
    final var config = current.providers().get(registrationId);
    if (config == null) {
      return null;
    }
    // Two lookups of the same registration each make their own attempt. A single-flight lock
    // would hold one caller for the complete discovery timeout of the other attempt, which is 30
    // seconds for an unreachable provider. The first result wins.
    final var cached = current.resolved().get(registrationId);
    if (cached != null) {
      return cached;
    }
    // buildAll, not createFromProviderMap: the constructor already ran the no-network validation
    // once, over the whole map. Re-running it here on every retry of a registration that keeps
    // failing to build would re-log the same WARN on every request.
    final var registration = build(registrationId, config);
    final var winner = current.resolved().putIfAbsent(registrationId, registration);
    return winner != null ? winner : registration;
  }

  @Override
  public Iterator<ClientRegistration> iterator() {
    // providers is already filtered by the constructor, so no key here can reach
    // findByRegistrationId's resolved cache (a ConcurrentHashMap, which throws
    // NullPointerException on get(null)).
    return state.providers().keySet().stream().map(this::findByRegistrationId).iterator();
  }

  /**
   * Builds the registrations of {@code providers} next to the ones in use, without publishing them:
   * every registration, so that the identity provider can be asked whether it accepts the new
   * credentials before they are used. Discovery documents come from the factory's cache.
   *
   * @param providers the same registrationIds and settings as now, with other credentials; the
   *     caller checks that only credentials differ
   * @throws IllegalArgumentException if the registrationIds differ from the ones served
   * @throws RuntimeException if a registration cannot be built, for example because its provider
   *     cannot be reached; nothing changed then
   */
  public Prepared prepareCredentials(final Map<String, OidcConfiguration> providers) {
    final var normalized = new LinkedHashMap<>(providers);
    if (loginRouteChecks == ScopedClientRegistrationFactory.LoginRouteChecks.SKIPPED) {
      factory.validateWithoutLoginRoutes(normalized);
    } else {
      factory.validateWithoutNetwork(normalized, scopedRedirectUriPath);
    }
    final var next =
        Collections.unmodifiableMap(
            ScopedClientRegistrationFactory.withoutBlankRegistrationIds(normalized));
    if (!next.keySet().equals(state.providers().keySet())) {
      throw new IllegalArgumentException(
          "A credential rotation must keep the registrationIds %s, got %s"
              .formatted(state.providers().keySet(), next.keySet()));
    }
    final Map<String, ClientRegistration> registrations = new LinkedHashMap<>();
    next.forEach((id, config) -> registrations.put(id, build(id, config)));
    return new Prepared(this, next, Collections.unmodifiableMap(registrations));
  }

  /**
   * Serves the prepared registrations from now on, in one step. A lookup that started before it may
   * still return a previous registration.
   */
  public void publishCredentials(final Prepared prepared) {
    if (prepared.repository() != this) {
      throw new IllegalArgumentException("Prepared for another repository");
    }
    state = new State(prepared.providers(), new ConcurrentHashMap<>(prepared.registrations()));
  }

  private ClientRegistration build(final String registrationId, final OidcConfiguration config) {
    return DeferredOidcResolution.resolve(
        describe(registrationId, config),
        () ->
            factory
                .buildAll(Map.of(registrationId, config), scopedRedirectUriPath, loginRouteChecks)
                .getFirst());
  }

  private String describe(final String registrationId, final OidcConfiguration config) {
    return "OIDC client registration "
        + DeferredOidcResolution.describeProvider(registrationId, config)
        + (StringUtils.hasText(scopeDescription) ? " for " + scopeDescription : "");
  }

  /**
   * Registrations built by {@link #prepareCredentials} and not yet served.
   *
   * @param registrations by registrationId, each built from {@code providers}
   */
  public record Prepared(
      LazyClientRegistrationRepository repository,
      Map<String, OidcConfiguration> providers,
      Map<String, ClientRegistration> registrations) {}

  private record State(
      Map<String, OidcConfiguration> providers, Map<String, ClientRegistration> resolved) {}
}
