/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Year;
import java.util.Map;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.HtmlUtils;

/**
 * Renders a Camunda-branded identity-provider picker for {@code GET} requests to the configured
 * login page URL, replacing Spring Security's {@link
 * org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter} as the
 * library default (ADR-0043).
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

  private static final String CAMUNDA_LOGO_SVG =
      "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"96\" height=\"33\" viewBox=\"0 0 96 33\""
          + " role=\"img\" aria-label=\"Camunda\"><path fill-rule=\"evenodd\" d=\"M96 26.907V33H0v"
          + "-6.093zM43.826.296l3.602.003-.015 17.744c-.002 1.643.718 2.235 1.864 2.236s1.867-.59"
          + " 1.869-2.233L51.16.302l3.405.003-.015 17.514c-.003 3.68-1.838 5.782-5.375 5.779s-5.368"
          + "-2.108-5.365-5.788zM5.385 0c3.537.003 5.368 2.108 5.365 5.788l-.002 2.234-3.405-.003"
          + ".002-2.464c.001-1.643-.718-2.268-1.865-2.269-1.146 0-1.866.623-1.868 2.266l-.01 12.42c"
          + "-.002 1.644.718 2.236 1.864 2.237s1.867-.59 1.869-2.233l.002-3.286 3.406.003-.003 3.056"
          + "c-.003 3.68-1.838 5.782-5.375 5.779S-.003 21.42 0 17.74L.01 5.779C.013 2.099 1.85-.003"
          + " 5.385 0M87.08.332l5.272.005L96 23.342l-3.635-.003-.619-4.174-4.42-.004-.625"
          + " 4.173-3.308-.003zM71.003.32 76.7.324c3.601.003 5.368 2.009 5.365 5.69l-.01 11.632c"
          + "-.003 3.68-1.773 5.683-5.375 5.68l-5.698-.006zM56.989.307l4.519.004 3.688 13.771.011"
          + "-13.768 3.21.003-.02 23.001-3.7-.003-4.472-16.663-.014 16.66-3.242-.003zM26.242.281l5.01"
          + ".004 2.639 16.333L36.36.29l5.01.005-.02 23.001-3.405-.002.013-16.496-2.502"
          + " 16.494-3.406-.003-2.67-16.268-.014 16.265-3.144-.003zM15.666.27l5.272.005 3.648"
          + " 23.005-3.635-.003-.618-4.174-4.42-.003-.627 4.172-3.307-.003zm58.936 3.337-.014 16.43"
          + " 2.03.002c1.146 0 1.834-.59 1.836-2.233l.01-11.961c.001-1.643-.686-2.235-1.832-2.236zm"
          + "14.93.801L87.788 16.04l3.471.003zm-71.414-.06-1.745 11.63 3.471.003z\"/></svg>";

  // Tokens mirror @camunda/design-system's .c4-ui scope (light: zinc-50/900, dark: zinc-950/50;
  // brand accent #c2410c / #fb923c; 0.5rem radius) — the design system the webapp is migrating to.
  // No external font/stylesheet requests: this page must render standalone, without depending on a
  // CSP allowlist or third-party network access.
  private static final String PAGE_TEMPLATE =
      "<!doctype html>\n"
          + "<html lang=\"en\">\n"
          + "<head>\n"
          + "<meta charset=\"UTF-8\">\n"
          + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
          + "<title>Sign in to Camunda</title>\n"
          + "<style>\n"
          + ":root{--background:#fafafa;--foreground:#18181b;--border:rgba(161,161,170,.2);"
          + "--popover:#fff;--popover-foreground:#18181b;--muted-foreground:#71717a;"
          + "--accent-action-default:#c2410c;--ring:#ea580c;--radius-md:.375rem;--radius-lg:.5rem}\n"
          + "@media(prefers-color-scheme:dark){:root{--background:#09090b;--foreground:#fafafa;"
          + "--border:rgba(255,255,255,.16);--popover:#27272a;--popover-foreground:#fafafa;"
          + "--muted-foreground:#a1a1aa;--accent-action-default:#fb923c;--ring:#fb923c}}\n"
          + "*{box-sizing:border-box}\n"
          + "body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;"
          + "background:var(--background);color:var(--foreground);"
          + "font-family:system-ui,-apple-system,\"Segoe UI\",sans-serif;padding:2rem 1rem}\n"
          + ".frame{width:100%;max-width:26rem;display:flex;flex-direction:column;gap:1.25rem}\n"
          + ".card{background:var(--popover);color:var(--popover-foreground);"
          + "border:1px solid var(--border);border-radius:var(--radius-lg);"
          + "box-shadow:0 1px 3px rgba(0,0,0,.08),0 1px 2px rgba(0,0,0,.04);"
          + "padding:1.5rem;display:flex;flex-direction:column;gap:1rem}\n"
          + ".logo{display:flex;justify-content:center;padding-top:.5rem;color:var(--foreground)}\n"
          + ".logo svg{display:block;height:2rem;width:auto;fill:currentColor}\n"
          + "h1{margin:0 0 .5rem;padding-bottom:.5rem;font-size:1.25rem;line-height:1.4;"
          + "font-weight:600;letter-spacing:-.01em;text-align:center}\n"
          + ".subtitle{margin:-.75rem 0 .25rem;text-align:center;font-size:.875rem;"
          + "color:var(--muted-foreground)}\n"
          + ".providers{display:flex;flex-direction:column;gap:.5rem}\n"
          + ".provider{display:flex;align-items:center;gap:.75rem;width:100%;height:2.75rem;"
          + "padding:0 .875rem;background:var(--popover);border:1px solid var(--border);"
          + "border-radius:var(--radius-md);color:var(--popover-foreground);"
          + "font-family:inherit;font-size:.875rem;font-weight:500;text-align:left;"
          + "text-decoration:none;cursor:pointer;"
          + "transition:border-color 120ms ease}\n"
          + ".provider:hover{border-color:var(--accent-action-default)}\n"
          + ".provider:focus-visible{outline:2px solid var(--ring);outline-offset:2px}\n"
          + ".provider-name{flex:1}\n"
          + ".provider-arrow{flex:none;color:var(--muted-foreground)}\n"
          + "footer{text-align:center;font-size:.75rem;color:var(--muted-foreground)}\n"
          + "</style>\n"
          + "</head>\n"
          + "<body>\n"
          + "<div class=\"frame\">\n"
          + "<div class=\"card\">\n"
          + "<div class=\"logo\" aria-hidden=\"true\">"
          + CAMUNDA_LOGO_SVG
          + "</div>\n"
          + "<h1>Sign in to Camunda</h1>\n"
          + "<p class=\"subtitle\">Choose an identity provider to continue.</p>\n"
          + "<div class=\"providers\">\n"
          + "{{providers}}"
          + "</div>\n"
          + "</div>\n"
          + "<footer>&copy; Camunda Services GmbH, {{year}}. All rights reserved.</footer>\n"
          + "</div>\n"
          + "</body>\n"
          + "</html>\n";

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

    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentType(MediaType.TEXT_HTML_VALUE);
    response.setCharacterEncoding("UTF-8");
    response.getWriter().write(renderPickerHtml(links));
  }

  /**
   * Renders the full picker HTML for the given {@code authorizationUrl -> displayName} links. Names
   * come from {@link org.springframework.security.oauth2.client.registration.ClientRegistration
   * #getClientName()} — host-configured, untrusted input — so both the name and the URL are
   * HTML-escaped before being written into the page.
   */
  protected String renderPickerHtml(final Map<String, String> links) {
    final var providers = new StringBuilder();
    links.forEach(
        (url, name) ->
            providers
                .append("<a class=\"provider\" href=\"")
                .append(HtmlUtils.htmlEscape(url))
                .append("\">")
                .append("<span class=\"provider-name\">")
                .append(HtmlUtils.htmlEscape(name))
                .append("</span>")
                .append("<span class=\"provider-arrow\" aria-hidden=\"true\">&rarr;</span>")
                .append("</a>\n"));
    return PAGE_TEMPLATE
        .replace("{{providers}}", providers.toString())
        .replace("{{year}}", String.valueOf(Year.now().getValue()));
  }
}
