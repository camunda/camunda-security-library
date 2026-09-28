/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.ORDER_API;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.ORDER_WEBAPP;
import static io.camunda.security.spring.security.CamundaSecurityFilterChainConstants.X_CSRF_TOKEN;

import io.camunda.security.api.context.CamundaSecurityScopeProvider;
import io.camunda.security.api.model.config.AuthenticationMethod;
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import io.camunda.security.spring.CamundaSecurityLibraryProperties;
import io.camunda.security.spring.oidc.LazyClientRegistrationRepository;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import io.camunda.security.spring.oidc.ScopedJwtDecoderFactory;
import io.camunda.security.spring.security.ScopedWebappSecurityChainBuilder;
import io.camunda.security.spring.session.ScopedWebSessionRepositoryFactory;
import io.camunda.security.spring.session.WebSessionRepositories;
import io.camunda.security.spring.session.WebSessionRepository;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.MapSessionRepository;
import org.springframework.session.SessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * {@link BeanDefinitionRegistryPostProcessor} that discovers all {@link
 * CamundaSecurityScopeProvider} beans and registers both an API {@link SecurityFilterChain} and a
 * webapp {@link SecurityFilterChain} per {@link ScopedSecurityDescriptor}.
 *
 * <p>Declared {@code static} (via the enclosing {@link ScopedSecurityChainConfiguration}'s {@code
 * static @Bean} method) so Spring does not need to instantiate the enclosing {@code @Configuration}
 * class before the post-processor runs.
 */
final class ScopedSecurityChainRegistrar implements BeanDefinitionRegistryPostProcessor {

  static final String SESSION_COOKIE_PREFIX = "camunda-session-";
  static final String CSRF_COOKIE_PREFIX = X_CSRF_TOKEN + "-";

  static final int MAX_COOKIE_NAME_LENGTH =
      200; // well under the RFC 6265 4096-byte name=value budget

  private static final Logger LOG = LoggerFactory.getLogger(ScopedSecurityChainRegistrar.class);

  /**
   * Shared per-scope {@link SessionRepositoryFilter} instances, keyed by basePath. Built once per
   * descriptor so the same per-scope filter instance can be shared across the scope's chains (e.g.
   * a future session-authenticated API chain) without creating a second session store.
   *
   * <p>Populated lazily by {@link #getOrBuildSessionFilter}, which runs from the scoped chain
   * beans' instance suppliers when Spring instantiates them — not during {@link
   * #postProcessBeanDefinitionRegistry}. A {@link ConcurrentHashMap} with {@code computeIfAbsent}
   * keeps the build-once-per-basePath invariant intact even if those beans are ever instantiated
   * concurrently.
   */
  private final Map<String, SessionRepositoryFilter<?>> sessionFiltersByBasePath =
      new ConcurrentHashMap<>();

  /**
   * Shared per-scope {@link ApiTokenRefreshSupport} instances, keyed by basePath, built once per
   * OIDC descriptor by {@link #getOrBuildRefreshSupport} for the same build-once reason as {@link
   * #sessionFiltersByBasePath} above.
   */
  private final Map<String, ApiTokenRefreshSupport> refreshSupportByBasePath =
      new ConcurrentHashMap<>();

  @Override
  public void postProcessBeanDefinitionRegistry(final BeanDefinitionRegistry registry)
      throws BeansException {
    // The registry is a DefaultListableBeanFactory at runtime which also implements
    // ConfigurableListableBeanFactory — we need that interface to call getBean().
    if (!(registry instanceof ConfigurableListableBeanFactory beanFactory)) {
      LOG.warn(
          "ScopedSecurityChainRegistrar: registry is not a ConfigurableListableBeanFactory ({}); "
              + "skipping scoped chain registration",
          registry.getClass().getName());
      return;
    }

    final var providerNames = beanFactory.getBeanNamesForType(CamundaSecurityScopeProvider.class);
    if (providerNames.length == 0) {
      LOG.debug("No CamundaSecurityScopeProvider beans found — no scoped chains registered");
      return;
    }

    final var descriptors = collectDescriptors(beanFactory, providerNames);

    if (descriptors.isEmpty()) {
      LOG.debug("CamundaSecurityScopeProvider(s) returned no descriptors — nothing to register");
      return;
    }

    rejectDuplicateBasePaths(descriptors);
    rejectCookieNameCollisions(descriptors);

    LOG.info(
        "Registering scoped API + webapp security chains for {} descriptor(s) from"
            + " CamundaSecurityScopeProvider(s)",
        descriptors.size());

    registerChains(registry, beanFactory, descriptors);
  }

  @Override
  public void postProcessBeanFactory(final ConfigurableListableBeanFactory beanFactory)
      throws BeansException {
    // Nothing needed here — all work is done in postProcessBeanDefinitionRegistry.
  }

  private static List<ScopedSecurityDescriptor> collectDescriptors(
      final ConfigurableListableBeanFactory beanFactory, final String[] providerNames) {
    final List<ScopedSecurityDescriptor> descriptors = new ArrayList<>();
    for (final var providerBeanName : providerNames) {
      final var provider =
          beanFactory.getBean(providerBeanName, CamundaSecurityScopeProvider.class);
      final var returned = provider.get();
      if (returned == null) {
        throw new IllegalStateException(
            "CamundaSecurityScopeProvider bean '"
                + providerBeanName
                + "' returned null; it must return a (possibly empty) list of descriptors");
      }
      for (final var descriptor : returned) {
        if (descriptor == null) {
          throw new IllegalStateException(
              "CamundaSecurityScopeProvider bean '"
                  + providerBeanName
                  + "' returned a list containing a null element");
        }
        descriptors.add(descriptor);
      }
    }
    return descriptors;
  }

  private static void rejectDuplicateBasePaths(final List<ScopedSecurityDescriptor> descriptors) {
    final var seen = new HashSet<String>();
    final var duplicates = new LinkedHashSet<String>();
    for (final var d : descriptors) {
      final var normalized = BasePaths.normalize(d.basePath(), "basePath");
      if (!seen.add(normalized)) {
        duplicates.add(normalized);
      }
    }
    if (!duplicates.isEmpty()) {
      throw new IllegalStateException(
          "Duplicate scope basePath(s) contributed by CamundaSecurityScopeProvider beans: "
              + duplicates
              + ". Each contributed scope must have a unique basePath.");
    }
  }

  private void registerChains(
      final BeanDefinitionRegistry registry,
      final ConfigurableListableBeanFactory beanFactory,
      final List<ScopedSecurityDescriptor> descriptors) {
    for (int i = 0; i < descriptors.size(); i++) {
      final var descriptor = descriptors.get(i);
      final var sanitized = sanitizeBasePath(descriptor.basePath());

      // API chain
      final var apiChainName = "scopedApiSecurityFilterChain-" + i + "-" + sanitized;
      final var apiChainBd =
          new RootBeanDefinition(
              OrderedSecurityFilterChainWrapper.class, () -> buildChain(beanFactory, descriptor));
      registry.registerBeanDefinition(apiChainName, apiChainBd);
      LOG.debug(
          "Registered scoped API chain bean '{}' for basePath={}",
          apiChainName,
          descriptor.basePath());

      // Webapp chain — always registered. When the host provides no webapp paths, buildWebappChain
      // returns a no-op chain that matches nothing so it is effectively inert.
      final var webappChainName = "scopedWebappSecurityFilterChain-" + i + "-" + sanitized;
      final var webappChainBd =
          new RootBeanDefinition(
              OrderedSecurityFilterChainWrapper.class,
              () -> buildWebappChain(beanFactory, descriptor));
      registry.registerBeanDefinition(webappChainName, webappChainBd);
      LOG.debug(
          "Registered scoped webapp chain bean '{}' for basePath={}",
          webappChainName,
          descriptor.basePath());
    }
  }

  private OrderedSecurityFilterChainWrapper buildChain(
      final ConfigurableListableBeanFactory beanFactory,
      final ScopedSecurityDescriptor descriptor) {
    try {
      // HttpSecurity is a prototype bean — each call produces a fresh, independent instance.
      final var http = beanFactory.getBean(HttpSecurity.class);
      final var builder = beanFactory.getBean(ScopedApiSecurityChainBuilder.class);
      final var properties = beanFactory.getBean(CamundaSecurityLibraryProperties.class);
      final SecurityFilterChain chain;
      if (properties.getAuthentication().isUnprotectedApi()) {
        final var sessionFilter = getOrBuildSessionFilter(beanFactory, descriptor.basePath());
        chain = builder.buildUnprotectedScopedApiChain(http, descriptor.basePath(), sessionFilter);
      } else {
        final var sessionFilter = getOrBuildSessionFilter(beanFactory, descriptor.basePath());
        chain =
            builder.buildScopedApiChain(
                http,
                descriptor.basePath(),
                descriptor.authentication(),
                () -> {
                  try {
                    final var decoderFactory = beanFactory.getBean(ScopedJwtDecoderFactory.class);
                    return decoderFactory.buildIssuerAwareDecoder(
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
                },
                () -> null,
                sessionFilter,
                getOrBuildRefreshSupport(beanFactory, descriptor));
      }
      return new OrderedSecurityFilterChainWrapper(chain, ORDER_API);
    } catch (final IllegalStateException ex) {
      throw ex;
    } catch (final Exception ex) {
      throw new IllegalStateException(
          "Failed to build scoped API security chain for basePath=" + descriptor.basePath(), ex);
    }
  }

  /**
   * Resolves or creates the scope's {@link ApiTokenRefreshSupport}, so the scoped API chain
   * refreshes a session-authenticated caller's access token the way the scoped webapp chain does
   * (camunda-security-library#662). Returns {@code null} — meaning "install no refresh filter" —
   * for a BASIC scope, which holds no OAuth2 token, and for an OIDC scope that configures no
   * provider, whose decoder supplier reports the misconfiguration with a better message.
   *
   * <p>The authorized-client repository is a fresh {@link
   * HttpSessionOAuth2AuthorizedClientRepository} rather than the instance the scope's webapp chain
   * holds: it keeps no per-instance state and resolves the authorized clients from a session
   * attribute named by a class-level constant, so it reads exactly what the login flow stored. The
   * client-registration repository is likewise built here rather than shared, because the refresh
   * path resolves no registration from it — {@code DefaultOAuth2AuthorizedClientManager} takes the
   * registration off the stored authorized client whenever the authorize request carries one, as
   * the refresh filter's does. See ADR-0031.
   *
   * <p>It is built {@linkplain LazyClientRegistrationRepository#withoutLoginRoutes without login
   * routes}, like every other non-login consumer of the provider map ({@code
   * ScopedJwtDecoderFactory}, {@code ScopedOidcClaimsProviderFactory}). A scope whose host declares
   * no webapp paths gets an API chain and an inert webapp chain, so login-only validation would
   * otherwise reject a configuration no login route in this application ever reads — {@code
   * user-info-required=true} with {@code user-info-enabled=false} being the one such check that
   * throws rather than warns.
   */
  private ApiTokenRefreshSupport getOrBuildRefreshSupport(
      final ConfigurableListableBeanFactory beanFactory,
      final ScopedSecurityDescriptor descriptor) {
    if (descriptor.authentication() == null
        || descriptor.authentication().getMethod() != AuthenticationMethod.OIDC) {
      return null;
    }
    final var registrationFactory = beanFactory.getBean(ScopedClientRegistrationFactory.class);
    final var providers = registrationFactory.flatten(descriptor.authentication());
    if (providers.isEmpty()) {
      LOG.debug(
          "Scope basePath={} configures no OIDC provider; its API chain gets no refresh filter",
          descriptor.basePath());
      return null;
    }
    return refreshSupportByBasePath.computeIfAbsent(
        descriptor.basePath(),
        basePath -> {
          final var prefix = BasePaths.normalize(basePath, "basePath");
          final var clientRegistrationRepository =
              LazyClientRegistrationRepository.withoutLoginRoutes(
                  registrationFactory, providers, "basePath=" + prefix);
          final var authorizedClientRepository = new HttpSessionOAuth2AuthorizedClientRepository();
          final var authorizedClientManager =
              beanFactory
                  .getBean(OAuth2AuthorizedClientManagerFactory.class)
                  .create(clientRegistrationRepository, authorizedClientRepository);
          return ApiTokenRefreshSupport.forScope(
              authorizedClientRepository,
              authorizedClientManager,
              basePath,
              sessionCookieName(basePath),
              csrfCookieName(basePath));
        });
  }

  /**
   * Resolves or creates the shared {@link SessionRepositoryFilter} for the given basePath. The
   * filter is built once per descriptor and cached so the same instance can be reused across the
   * scope's chains without creating a second, independent session store.
   */
  private SessionRepositoryFilter<?> getOrBuildSessionFilter(
      final ConfigurableListableBeanFactory beanFactory, final String basePath) {
    return sessionFiltersByBasePath.computeIfAbsent(
        basePath,
        bp ->
            ScopedWebSessionComponentsFactory.sessionRepositoryFilter(
                bp, resolveSessionRepository(beanFactory, bp)));
  }

  /**
   * Resolves the {@link SessionRepository} that backs a scope's {@link SessionRepositoryFilter}, in
   * order of preference:
   *
   * <ol>
   *   <li>a <b>per-scope</b> durable {@link WebSessionRepository} bound to the scope's own store,
   *       via {@link ScopedWebSessionRepositoryFactory} (ADR-0009) — so persistent writes route
   *       structurally at Spring Session's commit time, not via request/thread context;
   *   <li>the shared durable {@link WebSessionRepository} bean (the legacy, non-per-scope fallback)
   *       when no per-scope provider is contributed;
   *   <li>a per-scope in-memory {@link MapSessionRepository} backed by a fresh {@link
   *       ConcurrentHashMap} (dev/test) — separate instances give store-level isolation on top of
   *       the cookie {@code Path} isolation.
   * </ol>
   */
  private SessionRepository<?> resolveSessionRepository(
      final ConfigurableListableBeanFactory beanFactory, final String basePath) {
    final var perScopeFactory =
        beanFactory.getBeanProvider(ScopedWebSessionRepositoryFactory.class).getIfAvailable();
    if (perScopeFactory != null && perScopeFactory.isAvailable()) {
      // normalize to match how the rest of the scope subsystem keys base paths
      return perScopeFactory.forBasePath(BasePaths.normalize(basePath, "basePath"));
    }
    final var sharedDurableRepo =
        beanFactory.getBeanProvider(WebSessionRepository.class).getIfAvailable();
    final var properties = beanFactory.getBean(CamundaSecurityLibraryProperties.class);
    return WebSessionRepositories.durableOrInMemory(
        sharedDurableRepo, properties.getSession(), basePath);
  }

  private OrderedSecurityFilterChainWrapper buildWebappChain(
      final ConfigurableListableBeanFactory beanFactory,
      final ScopedSecurityDescriptor descriptor) {
    try {
      // HttpSecurity is a prototype bean — each call produces a fresh, independent instance.
      final var http = beanFactory.getBean(HttpSecurity.class);
      final var builder = beanFactory.getBean(ScopedWebappSecurityChainBuilder.class);
      final var sessionFilter = getOrBuildSessionFilter(beanFactory, descriptor.basePath());
      final SecurityFilterChain chain =
          builder.buildScopedWebappChain(
              http,
              descriptor.basePath(),
              descriptor.authentication(),
              sessionFilter,
              sessionCookieName(descriptor.basePath()),
              csrfCookieName(descriptor.basePath()));
      // Webapp chain sorts after the scoped API chain (ORDER_API < ORDER_WEBAPP) so a scoped
      // catch-all webapp matcher cannot claim API requests ahead of the scoped API chain.
      return new OrderedSecurityFilterChainWrapper(chain, ORDER_WEBAPP);
    } catch (final IllegalStateException ex) {
      throw ex;
    } catch (final Exception ex) {
      throw new IllegalStateException(
          "Failed to build scoped webapp security chain for basePath=" + descriptor.basePath(), ex);
    }
  }

  /** The per-scope session cookie name: {@code camunda-session-<sanitize(basePath)>}. */
  static String sessionCookieName(final String basePath) {
    return SESSION_COOKIE_PREFIX + sanitizeBasePath(basePath);
  }

  /** The per-scope CSRF cookie name: {@code X-CSRF-TOKEN-<sanitize(basePath)>}. */
  static String csrfCookieName(final String basePath) {
    return CSRF_COOKIE_PREFIX + sanitizeBasePath(basePath);
  }

  static void rejectCookieNameCollisions(final List<ScopedSecurityDescriptor> descriptors) {
    final var seen = new HashSet<String>();
    final var collisions = new LinkedHashSet<String>();
    for (final var d : descriptors) {
      final var suffix = sanitizeBasePath(d.basePath());
      if (suffix.isEmpty()) {
        throw new IllegalStateException(
            "basePath="
                + d.basePath()
                + " sanitizes to an empty suffix, which would yield the non-distinct session"
                + " cookie name '"
                + SESSION_COOKIE_PREFIX
                + "'. Use a basePath containing alphanumerics.");
      }
      final var sessionName = SESSION_COOKIE_PREFIX + suffix;
      final var csrfName = CSRF_COOKIE_PREFIX + suffix;
      if (sessionName.length() > MAX_COOKIE_NAME_LENGTH
          || csrfName.length() > MAX_COOKIE_NAME_LENGTH) {
        throw new IllegalStateException(
            "Derived session cookie name for basePath="
                + d.basePath()
                + " exceeds the maximum length of "
                + MAX_COOKIE_NAME_LENGTH
                + " characters ("
                + sessionName.length()
                + "). Use a shorter basePath.");
      }
      if (!seen.add(sessionName)) {
        collisions.add(sessionName);
      }
    }
    if (!collisions.isEmpty()) {
      throw new IllegalStateException(
          "Distinct scope basePath(s) sanitize to the same session cookie name(s): "
              + collisions
              + ". Each scope must yield a unique cookie name.");
    }
  }

  /**
   * Sanitizes a basePath for use as part of a Spring bean name. Strips a leading {@code /},
   * replaces every run of non-alphanumeric characters with a single {@code -}, and trims leading
   * and trailing {@code -}.
   *
   * <p>Example: {@code /some/base-path} → {@code some-base-path}.
   *
   * <p>The leading index in the caller's bean name guarantees uniqueness even if two distinct
   * basePaths sanitize to the same string.
   *
   * @param basePath the raw basePath; may be {@code null} (returned as empty string)
   * @return the sanitized basePath fragment
   */
  // package-private (not private) so ScopedSecurityChainRegistrarTest can exercise it directly.
  static String sanitizeBasePath(final String basePath) {
    if (basePath == null) {
      return "";
    }
    String s = basePath;
    if (s.startsWith("/")) {
      s = s.substring(1);
    }
    s = s.replaceAll("[^A-Za-z0-9]+", "-");
    s = s.replaceAll("^-+|-+$", "");
    return s;
  }
}
