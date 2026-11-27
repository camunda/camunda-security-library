/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import io.camunda.security.spring.html.HtmlTemplate;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Year;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Renders a Camunda-branded identity-provider picker for {@code GET} requests to the configured
 * login page URL, replacing Spring Security's {@link
 * org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter} as the
 * library default (ADR-0022).
 *
 * <p>The picker is rendered only when there is an actual choice to make: two or more OIDC client
 * registrations. With exactly one registration there is nothing to pick between, so the filter
 * redirects straight to that provider's authorization endpoint instead — the same destination
 * {@link ScopedWebappSecurityChainBuilder#resolveOauthRedirectTarget} already sends unauthenticated
 * users to when a protected resource triggers the entry point. This keeps a direct {@code GET} to
 * the login URL consistent with that flow rather than presenting a one-link "choice" (GH-269
 * follow-up). The request falls through the filter chain in the two cases where {@link
 * LoginLinksBuilder#buildLoginLinks} yields no links: zero registrations — unreachable in practice,
 * since every OIDC chain requires at least one provider — and a host-supplied {@link
 * ClientRegistrationRepository} that does not implement {@link Iterable}, which {@code
 * buildLoginLinks} cannot enumerate.
 *
 * <p>This class is an intentional extension point: it is not {@code final}, and {@link
 * #renderPickerHtml(Map)} is {@code protected} so a host that wants different branding can subclass
 * it and register its own instance as a bean of this type, reusing the multi-registration gating
 * and redirect behavior.
 */
public class CamundaLoginPickerFilter extends OncePerRequestFilter {

  static final String PAGE_TEMPLATE_RESOURCE = "login-picker-page.html";
  static final String PROVIDER_TEMPLATE_RESOURCE = "login-picker-provider.html";

  private static final Logger LOG = LoggerFactory.getLogger(CamundaLoginPickerFilter.class);

  private final ClientRegistrationRepository clientRegistrationRepository;
  private final String loginPageUrl;
  private final String authorizationBaseUriPrefix;
  private final RequestMatcher loginPageMatcher;
  private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

  public CamundaLoginPickerFilter(
      final ClientRegistrationRepository clientRegistrationRepository, final String loginPageUrl) {
    this(clientRegistrationRepository, loginPageUrl, "");
  }

  /**
   * @param authorizationBaseUriPrefix the scope prefix authorization links are rendered under (e.g.
   *     {@code /physical-tenants/t1}); empty for the primary, non-scoped chain.
   */
  public CamundaLoginPickerFilter(
      final ClientRegistrationRepository clientRegistrationRepository,
      final String loginPageUrl,
      final String authorizationBaseUriPrefix) {
    this.clientRegistrationRepository = clientRegistrationRepository;
    this.loginPageUrl = loginPageUrl;
    this.authorizationBaseUriPrefix = authorizationBaseUriPrefix;
    loginPageMatcher =
        PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, loginPageUrl);
  }

  public String getLoginPageUrl() {
    return loginPageUrl;
  }

  @Override
  protected void doFilterInternal(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final FilterChain filterChain)
      throws ServletException, IOException {
    if (!loginPageMatcher.matches(request)) {
      filterChain.doFilter(request, response);
      return;
    }

    final var links =
        LoginLinksBuilder.buildLoginLinks(clientRegistrationRepository, authorizationBaseUriPrefix);
    if (links.isEmpty()) {
      filterChain.doFilter(request, response);
      return;
    }
    if (links.size() == 1) {
      redirectStrategy.sendRedirect(request, response, links.keySet().iterator().next());
      return;
    }
    final String html;
    try {
      html = renderPickerHtml(withContextPath(links, request.getContextPath()));
    } catch (final MissingTemplatesException e) {
      // Only the default rendering needs the templates: a host's renderPickerHtml override that
      // doesn't call super still renders without them.
      filterChain.doFilter(request, response);
      return;
    }

    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentType(MediaType.TEXT_HTML_VALUE);
    response.setCharacterEncoding("UTF-8");
    response.getWriter().write(html);
  }

  /**
   * Prefixes every link with the request's servlet context path. Unlike the single-provider
   * redirect above and the unauthenticated entry point's redirect ({@link
   * ScopedWebappSecurityChainBuilder#resolveOauthRedirectTarget}), which both go through {@link
   * DefaultRedirectStrategy} and get the context path prepended automatically, this filter writes
   * the links straight into HTML — so it has to apply that same prefix itself, or every rendered
   * link 404s on a context-path'd deployment (every SaaS Orchestration Cluster instance).
   *
   * <p>{@code request.getContextPath()} is never {@code null} per the Servlet contract, and is
   * {@code ""} for a root-deployed app, in which case the links are returned unchanged.
   */
  private static Map<String, String> withContextPath(
      final Map<String, String> links, final String contextPath) {
    if (contextPath.isEmpty()) {
      return links;
    }
    final var prefixed = new LinkedHashMap<String, String>();
    links.forEach((url, name) -> prefixed.put(contextPath + url, name));
    return prefixed;
  }

  /**
   * Renders the full picker HTML for the given {@code authorizationUrl -> displayName} links. Names
   * come from {@link org.springframework.security.oauth2.client.registration.ClientRegistration
   * #getClientName()} — host-configured, untrusted input — so both the name and the URL are
   * HTML-escaped before being written into the page. The URL is already servlet
   * context-path–prefixed (see {@link #withContextPath}); a subclass overriding this method should
   * not prefix it again.
   *
   * <p>If the default templates are missing from the classpath, this default rendering throws an
   * exception the filter turns into a fall-through to the next filter, as it did before the page
   * moved into templates. An override that doesn't call {@code super} doesn't need them.
   */
  protected String renderPickerHtml(final Map<String, String> links) {
    if (!defaultTemplatesAvailable()) {
      throw new MissingTemplatesException();
    }
    final String provider = Templates.PROVIDER.orElseThrow(MissingTemplatesException::new);
    final String providers =
        links.entrySet().stream()
            .map(
                link ->
                    HtmlTemplate.render(
                        provider, Map.of("href", link.getKey(), "name", link.getValue())))
            .collect(Collectors.joining());
    return HtmlTemplate.render(
        Templates.PAGE.orElseThrow(MissingTemplatesException::new),
        Map.of("year", String.valueOf(Year.now().getValue())),
        Map.of("providers", providers));
  }

  /** Whether the default picker templates loaded; package-private so tests can simulate a gap. */
  boolean defaultTemplatesAvailable() {
    return Templates.PAGE.isPresent() && Templates.PROVIDER.isPresent();
  }

  /** The default rendering's templates are missing; the filter falls through to the next one. */
  private static final class MissingTemplatesException extends IllegalStateException {
    private MissingTemplatesException() {
      super("The login picker templates are missing; see the log.");
    }
  }

  /**
   * The page's markup and styling, kept as resources in this class's package so they can be read
   * and edited as HTML (ADR-0050). The style tokens mirror {@code @camunda/design-system}'s {@code
   * .c4-ui} scope (light: zinc-50/900, dark: zinc-950/50; brand accent #c2410c / #fb923c; 0.5rem
   * radius), the design system the webapp is migrating to. The page makes no external font or
   * stylesheet requests: it must render standalone, without depending on a CSP allowlist or
   * third-party network access. Loaded on the first rendered picker rather than with the filter, by
   * the holder idiom.
   */
  private static final class Templates {
    private static final String FALLBACK =
        "the login page falls through to the next filter instead of showing the picker.";
    private static final Optional<String> PAGE =
        HtmlTemplate.load(CamundaLoginPickerFilter.class, PAGE_TEMPLATE_RESOURCE, LOG, FALLBACK);
    private static final Optional<String> PROVIDER =
        HtmlTemplate.load(
            CamundaLoginPickerFilter.class, PROVIDER_TEMPLATE_RESOURCE, LOG, FALLBACK);
  }
}
