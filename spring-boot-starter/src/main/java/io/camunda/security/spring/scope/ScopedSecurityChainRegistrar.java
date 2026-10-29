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
import io.camunda.security.api.model.config.ScopedSecurityDescriptor;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.security.web.SecurityFilterChain;

/**
 * {@link BeanDefinitionRegistryPostProcessor} that discovers all {@link
 * CamundaSecurityScopeProvider} beans and registers both an API {@link SecurityFilterChain} and a
 * webapp {@link SecurityFilterChain} per {@link ScopedSecurityDescriptor}.
 *
 * <p>Each registered chain is a {@link ScopeChainView} of the scope's {@link ScopeSlot}, so the
 * scope can be replaced or removed at runtime under the same bean. Alongside them it registers the
 * {@link ScopeDispatchingSecurityFilterChain} that serves scopes added later, and the {@link
 * ScopedSecurityReloadService} that changes scopes (ADR-0040).
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

  static final String RELOAD_SERVICE_BEAN_NAME = "scopedSecurityReloadService";
  static final String DISPATCHING_CHAIN_BEAN_NAME = "scopedDispatchingSecurityFilterChain";

  private static final Logger LOG = LoggerFactory.getLogger(ScopedSecurityChainRegistrar.class);

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
    rejectDuplicateBasePaths(descriptors);
    rejectCookieNameCollisions(descriptors);

    final var slots = new ScopeSlots();
    final var service =
        new ScopedSecurityReloadService(
            beanFactory,
            slots,
            new ScopeGenerationBuilder(beanFactory),
            new ScopeRetirement(beanFactory));
    registry.registerBeanDefinition(
        RELOAD_SERVICE_BEAN_NAME,
        new RootBeanDefinition(ScopedSecurityReloadService.class, () -> service));
    final var dispatcher = new ScopeDispatchingSecurityFilterChain(slots, ORDER_API);
    registry.registerBeanDefinition(
        DISPATCHING_CHAIN_BEAN_NAME,
        new RootBeanDefinition(ScopeDispatchingSecurityFilterChain.class, () -> dispatcher));

    if (descriptors.isEmpty()) {
      LOG.debug("CamundaSecurityScopeProvider(s) returned no descriptors — no startup scopes");
      return;
    }
    LOG.info(
        "Registering scoped API + webapp security chains for {} descriptor(s) from"
            + " CamundaSecurityScopeProvider(s)",
        descriptors.size());
    registerChains(registry, service, slots, descriptors);
  }

  @Override
  public void postProcessBeanFactory(final ConfigurableListableBeanFactory beanFactory)
      throws BeansException {
    // Nothing needed here — all work is done in postProcessBeanDefinitionRegistry.
  }

  static List<ScopedSecurityDescriptor> collectDescriptors(
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

  static void rejectDuplicateBasePaths(final List<ScopedSecurityDescriptor> descriptors) {
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

  private static void registerChains(
      final BeanDefinitionRegistry registry,
      final ScopedSecurityReloadService service,
      final ScopeSlots slots,
      final List<ScopedSecurityDescriptor> descriptors) {
    for (int i = 0; i < descriptors.size(); i++) {
      final var descriptor = descriptors.get(i);
      final var sanitized = sanitizeBasePath(descriptor.basePath());
      final var slot =
          slots.registerStartupSlot(BasePaths.normalize(descriptor.basePath(), "basePath"));

      final var apiChainName = "scopedApiSecurityFilterChain-" + i + "-" + sanitized;
      registry.registerBeanDefinition(
          apiChainName,
          new RootBeanDefinition(
              OrderedSecurityFilterChainWrapper.class,
              () -> view(service, slot, descriptor, ScopeChainKind.API, ORDER_API)));
      LOG.debug(
          "Registered scoped API chain bean '{}' for basePath={}",
          apiChainName,
          descriptor.basePath());

      // Webapp chain — always registered. When the host provides no webapp paths, the scope's
      // webapp chain matches nothing so it is effectively inert. It sorts after the scoped API
      // chain
      // (ORDER_API < ORDER_WEBAPP) so a scoped catch-all webapp matcher cannot claim API requests.
      final var webappChainName = "scopedWebappSecurityFilterChain-" + i + "-" + sanitized;
      registry.registerBeanDefinition(
          webappChainName,
          new RootBeanDefinition(
              OrderedSecurityFilterChainWrapper.class,
              () -> view(service, slot, descriptor, ScopeChainKind.WEBAPP, ORDER_WEBAPP)));
      LOG.debug(
          "Registered scoped webapp chain bean '{}' for basePath={}",
          webappChainName,
          descriptor.basePath());
    }
  }

  /** The chain bean of a startup scope; the first of its two beans builds the scope. */
  private static OrderedSecurityFilterChainWrapper view(
      final ScopedSecurityReloadService service,
      final ScopeSlot slot,
      final ScopedSecurityDescriptor descriptor,
      final ScopeChainKind kind,
      final int order) {
    service.initializeStartupScope(slot, descriptor);
    return new OrderedSecurityFilterChainWrapper(new ScopeChainView(slot, kind), order);
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

  private record ScopeChains(
      OrderedSecurityFilterChainWrapper api, OrderedSecurityFilterChainWrapper webapp) {}
}
