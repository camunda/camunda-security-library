/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.REDIRECT_URI;

import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.core.port.out.SecurityPathPort;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import io.camunda.security.spring.oidc.ScopedJwtDecoderFactory;
import io.camunda.security.spring.oidc.ScopedOidcClients;
import io.camunda.security.spring.security.ScopedWebappSecurityChainBuilder;
import io.camunda.security.spring.session.ScopeAuthenticationBoundSessionRepository;
import io.camunda.security.spring.session.ScopedWebSessionRepositoryFactory;
import io.camunda.security.spring.session.WebSessionRepositories;
import io.camunda.security.spring.session.WebSessionRepository;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Builds one {@link ScopeGeneration} of a scope: its API and webapp chains, its OIDC client stacks,
 * and the objects Spring Security post-processed for them — all owned by the generation.
 *
 * <p>Nothing here publishes anything. A build that fails disposes what it created and leaves the
 * scope's live generation, and every other scope, untouched.
 */
final class ScopeGenerationBuilder {

  private static final Logger LOG = LoggerFactory.getLogger(ScopeGenerationBuilder.class);

  private final ConfigurableListableBeanFactory beanFactory;
  private volatile boolean warnedAboutSharedObjects;

  ScopeGenerationBuilder(final ConfigurableListableBeanFactory beanFactory) {
    this.beanFactory = beanFactory;
  }

  /** Builds generation {@code number} of the slot's scope. Call with the slot's lock held. */
  ScopeGeneration build(
      final ScopeSlot slot,
      final ScopedSecurityDescriptor descriptor,
      final long number,
      final ScopeFingerprints fingerprints) {
    final var basePath = slot.basePath();
    final var objects = new ScopeObjects(basePath);
    final List<ScopedOidcClients> oidcClients = new ArrayList<>();
    try {
      final var chains =
          ScopeCapturingObjectPostProcessor.capturing(
              objects,
              () -> {
                final var sessionFilter = slot.sessionFilter(() -> buildSessionFilter(basePath));
                final var marker =
                    new ScopeGenerationMarkerFilter(
                        basePath, number, fingerprints.authentication());
                final var api =
                    buildApiChain(descriptor, basePath, sessionFilter, marker, oidcClients);
                final var webapp =
                    buildWebappChain(descriptor, basePath, sessionFilter, marker, oidcClients);
                return new SecurityFilterChain[] {api, webapp};
              });
      initializeSingletons(objects);
      return new ScopeGeneration(
          number, descriptor, fingerprints, chains[0], chains[1], objects, oidcClients);
    } catch (final RuntimeException failure) {
      objects.dispose();
      throw failure;
    }
  }

  private SecurityFilterChain buildApiChain(
      final ScopedSecurityDescriptor descriptor,
      final String basePath,
      final SessionRepositoryFilter<?> sessionFilter,
      final ScopeGenerationMarkerFilter marker,
      final List<ScopedOidcClients> oidcClients) {
    try {
      final var http = httpSecurity(marker);
      final var builder = beanFactory.getBean(ScopedApiSecurityChainBuilder.class);
      final var properties = beanFactory.getBean(CamundaSecurityLibraryProperties.class);
      if (properties.getAuthentication().isUnprotectedApi()) {
        return builder.buildUnprotectedScopedApiChain(http, basePath, sessionFilter);
      }
      final var refreshSupport = refreshSupport(descriptor, basePath, oidcClients);
      return builder.buildScopedApiChain(
          http,
          descriptor.basePath(),
          descriptor.authentication(),
          () -> decoder(descriptor),
          () -> null,
          sessionFilter,
          refreshSupport);
    } catch (final IllegalStateException ex) {
      throw ex;
    } catch (final Exception ex) {
      throw new IllegalStateException(
          "Failed to build scoped API security chain for basePath=" + basePath, ex);
    }
  }

  private SecurityFilterChain buildWebappChain(
      final ScopedSecurityDescriptor descriptor,
      final String basePath,
      final SessionRepositoryFilter<?> sessionFilter,
      final ScopeGenerationMarkerFilter marker,
      final List<ScopedOidcClients> oidcClients) {
    try {
      final var http = httpSecurity(marker);
      final var builder = beanFactory.getBean(ScopedWebappSecurityChainBuilder.class);
      // Webapp chain sorts after the scoped API chain (ORDER_API < ORDER_WEBAPP) so a scoped
      // catch-all webapp matcher cannot claim API requests ahead of the scoped API chain.
      return builder.buildScopedWebappChain(
          http,
          descriptor.basePath(),
          descriptor.authentication(),
          sessionFilter,
          ScopedSecurityChainRegistrar.sessionCookieName(basePath),
          ScopedSecurityChainRegistrar.csrfCookieName(basePath),
          loginClients(descriptor, basePath, oidcClients));
    } catch (final IllegalStateException ex) {
      throw ex;
    } catch (final Exception ex) {
      throw new IllegalStateException(
          "Failed to build scoped webapp security chain for basePath=" + basePath, ex);
    }
  }

  /**
   * A fresh {@link HttpSecurity} — a prototype bean — whose first filter marks the generation.
   * Added ahead of the session filter the chain builders add next to the same anchor, so the
   * session repository already knows the serving generation when it reads the session.
   */
  private HttpSecurity httpSecurity(final ScopeGenerationMarkerFilter marker) {
    final var http = beanFactory.getBean(HttpSecurity.class);
    http.addFilterBefore(marker, SecurityContextHolderFilter.class);
    return http;
  }

  /**
   * The login chain's OIDC client stack, or {@code null} when the chain logs no one in through
   * OIDC: a BASIC scope, or a host without webapp paths.
   */
  private ScopedOidcClients loginClients(
      final ScopedSecurityDescriptor descriptor,
      final String basePath,
      final List<ScopedOidcClients> oidcClients) {
    final var pathPort = beanFactory.getBean(SecurityPathPort.class);
    if (!isOidc(descriptor) || pathPort.webappPaths() == null || pathPort.webappPaths().isEmpty()) {
      return null;
    }
    final var registrationFactory = beanFactory.getBean(ScopedClientRegistrationFactory.class);
    final var providers = registrationFactory.flatten(descriptor.authentication());
    if (providers.isEmpty()) {
      // The webapp chain builder rejects this configuration with the scope named.
      return null;
    }
    final var clients =
        ScopedOidcClients.forLogin(
            registrationFactory,
            providers,
            basePath + REDIRECT_URI,
            "basePath=" + basePath,
            beanFactory.getBean(OAuth2AuthorizedClientManagerFactory.class));
    oidcClients.add(clients);
    return clients;
  }

  /**
   * The API chain's token refresh (ADR-0039), or {@code null} to install none: a BASIC scope holds
   * no OAuth2 token, and an OIDC scope with no provider is reported by the decoder with a better
   * message.
   */
  private ApiTokenRefreshSupport refreshSupport(
      final ScopedSecurityDescriptor descriptor,
      final String basePath,
      final List<ScopedOidcClients> oidcClients) {
    if (!isOidc(descriptor)) {
      return null;
    }
    final var registrationFactory = beanFactory.getBean(ScopedClientRegistrationFactory.class);
    final var providers = registrationFactory.flatten(descriptor.authentication());
    if (providers.isEmpty()) {
      LOG.debug(
          "Scope basePath={} configures no OIDC provider; its API chain gets no refresh filter",
          basePath);
      return null;
    }
    final var clients =
        ScopedOidcClients.withoutLoginRoutes(
            registrationFactory,
            providers,
            "basePath=" + basePath,
            beanFactory.getBean(OAuth2AuthorizedClientManagerFactory.class));
    oidcClients.add(clients);
    return ApiTokenRefreshSupport.forScope(
        clients.authorizedClients(),
        clients.authorizedClientManager(),
        basePath,
        ScopedSecurityChainRegistrar.sessionCookieName(basePath),
        ScopedSecurityChainRegistrar.csrfCookieName(basePath));
  }

  private JwtDecoder decoder(final ScopedSecurityDescriptor descriptor) {
    try {
      return beanFactory
          .getBean(ScopedJwtDecoderFactory.class)
          .buildIssuerAwareDecoder(
              descriptor.authentication(), "basePath=" + descriptor.basePath());
    } catch (final NoSuchBeanDefinitionException missing) {
      throw new IllegalStateException(
          "Cannot build the OIDC scoped API chain for basePath="
              + descriptor.basePath()
              + ": required bean "
              + ScopedJwtDecoderFactory.class.getName()
              + " is not present. It is normally provided unconditionally by"
              + " ScopedOidcInfrastructureConfiguration (activated via the"
              + " CamundaSecurityAutoConfiguration umbrella), independently of"
              + " camunda.security.authentication.method. Ensure that configuration"
              + " is imported, or register an equivalent ScopedJwtDecoderFactory"
              + " bean.",
          missing);
    }
  }

  private static boolean isOidc(final ScopedSecurityDescriptor descriptor) {
    return descriptor.authentication() != null
        && descriptor.authentication().getMethod() == AuthenticationMethod.OIDC;
  }

  /**
   * The scope's session filter, built once per scope and shared by its chains and generations. Its
   * repository binds each session to the authentication configuration it was created under.
   */
  private SessionRepositoryFilter<?> buildSessionFilter(final String basePath) {
    return ScopedWebSessionComponentsFactory.sessionRepositoryFilter(
        basePath, boundToAuthentication(resolveSessionRepository(basePath), basePath));
  }

  private static <S extends Session> SessionRepository<S> boundToAuthentication(
      final SessionRepository<S> repository, final String basePath) {
    return new ScopeAuthenticationBoundSessionRepository<>(
        repository,
        "basePath=" + basePath,
        () -> ScopeGenerationMarkerFilter.servingFingerprint(basePath));
  }

  /**
   * Resolves the {@link SessionRepository} that backs a scope's session filter, in order of
   * preference:
   *
   * <ol>
   *   <li>a <b>per-scope</b> durable {@link WebSessionRepository} bound to the scope's own store,
   *       via {@link ScopedWebSessionRepositoryFactory} (ADR-0009);
   *   <li>the shared durable {@link WebSessionRepository} bean when no per-scope provider is
   *       contributed;
   *   <li>a per-scope in-memory repository (dev/test).
   * </ol>
   */
  private SessionRepository<?> resolveSessionRepository(final String basePath) {
    final var perScopeFactory =
        beanFactory.getBeanProvider(ScopedWebSessionRepositoryFactory.class).getIfAvailable();
    if (perScopeFactory != null && perScopeFactory.isAvailable()) {
      return perScopeFactory.forBasePath(basePath);
    }
    final var sharedDurableRepo =
        beanFactory.getBeanProvider(WebSessionRepository.class).getIfAvailable();
    final var properties = beanFactory.getBean(CamundaSecurityLibraryProperties.class);
    return WebSessionRepositories.durableOrInMemory(
        sharedDurableRepo, properties.getSession(), basePath);
  }

  /**
   * Hands the generation's post-processed singletons their callback. Warns once when nothing was
   * post-processed for the scope, which means Spring Security's shared post-processor still owns
   * the scope's objects and keeps them until the context closes.
   */
  private void initializeSingletons(final ScopeObjects objects) {
    final var name = ScopeObjectPostProcessorInstaller.SHARED_PROCESSOR_BEAN_NAME;
    final Object processor = beanFactory.containsBean(name) ? beanFactory.getBean(name) : null;
    if (processor instanceof final ScopeCapturingObjectPostProcessor capturing) {
      capturing.initialize(objects);
    } else if (!warnedAboutSharedObjects) {
      warnedAboutSharedObjects = true;
      LOG.warn(
          "Spring Security's shared object post-processor ({}) is not wrapped by CSL, so the"
              + " filters of replaced or removed scopes stay referenced until the application"
              + " context closes. Import ScopedSecurityChainConfiguration to wrap it.",
          processor != null ? processor.getClass().getName() : "absent");
    }
  }
}
