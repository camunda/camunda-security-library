/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.headers;

/**
 * Configures Content Security Policy (CSP) to prevent XSS and other content injection attacks.
 *
 * <p>The library ships two built-in default policies — {@link #DEFAULT_SAAS_SECURITY_POLICY} and
 * {@link #DEFAULT_SM_SECURITY_POLICY}. The active default is selected by {@link #getMode()}: hosts
 * deployed in SaaS environments set {@code mode = SAAS}; self-managed deployments use the default
 * {@code SELF_MANAGED}. To supply a custom policy, set {@code mode = CUSTOM} and populate {@link
 * #setPolicyDirectives(String)}.
 *
 * @see <a
 *     href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy">MDN:
 *     Content-Security-Policy</a>
 */
public class ContentSecurityPolicyConfig {

  public static final String DEFAULT_SAAS_SECURITY_POLICY =
      "default-src 'self'; "
          + "base-uri 'self'; "
          + "script-src 'self' https: osano.com *.osano.com *.chargebee.com ajax.cloudflare.com static.cloudflareinsights.com; "
          + "script-src-elem 'self' cdn.jsdelivr.net osano.com *.osano.com cloudflareinsights.com; "
          + "connect-src 'self' https: cdn.jsdelivr.net *.osano.com; "
          + "style-src 'self' 'unsafe-inline' https: cdn.jsdelivr.net *.osano.com *.googleapis.com *.chargebee.com; "
          + "img-src * data: 'self' blob:; "
          + "form-action 'self'; "
          + "frame-ancestors 'self'; "
          + "frame-src 'self' https: *.osano.com *.chargebee.com blob:; "
          + "object-src 'self' blob:; "
          + "font-src 'self' data: fonts.camunda.io cdn.jsdelivr.net fonts.gstatic.com; "
          + "worker-src 'self' *.osano.com blob:; "
          + "child-src; "
          + "script-src-attr 'none'";

  public static final String DEFAULT_SM_SECURITY_POLICY =
      "default-src 'self'; "
          + "base-uri 'self'; "
          + "script-src 'self' https: *.chargebee.com ajax.cloudflare.com static.cloudflareinsights.com; "
          + "script-src-elem 'self' cdn.jsdelivr.net ; "
          + "connect-src 'self' https: cloudflareinsights.com cdn.jsdelivr.net; "
          + "style-src 'self' https: 'unsafe-inline' cdn.jsdelivr.net *.googleapis.com *.chargebee.com; "
          + "img-src data: 'self' blob:; "
          + "form-action 'self'; "
          + "frame-ancestors 'self'; "
          + "frame-src 'self' https: *.chargebee.com blob: ; "
          + "object-src 'self' blob:; "
          + "font-src 'self' data: fonts.camunda.io cdn.jsdelivr.net; "
          + "worker-src 'self' blob:; "
          + "child-src; "
          + "script-src-attr 'none'";

  /** Selects which built-in default policy applies, or whether a custom policy is in effect. */
  public enum Mode {
    /** Use {@link #DEFAULT_SAAS_SECURITY_POLICY}. */
    SAAS,
    /** Use {@link #DEFAULT_SM_SECURITY_POLICY}. */
    SELF_MANAGED,
    /** Use the value of {@link #getPolicyDirectives()} verbatim. */
    CUSTOM
  }

  /** Default: true (enabled). */
  private boolean enabled = true;

  /** Default: SELF_MANAGED. Hosts in SaaS deployments set this to SAAS. */
  private Mode mode = Mode.SELF_MANAGED;

  /** Used when {@link #getMode()} is {@link Mode#CUSTOM}. */
  private String policyDirectives;

  /** Default: false. When true, uses Content-Security-Policy-Report-Only. */
  private boolean reportOnly = false;

  public boolean isEnabled() {
    return enabled;
  }

  public void setEnabled(final boolean enabled) {
    this.enabled = enabled;
  }

  public boolean isDisabled() {
    return !enabled;
  }

  public Mode getMode() {
    return mode;
  }

  public void setMode(final Mode mode) {
    this.mode = mode;
  }

  public String getPolicyDirectives() {
    return policyDirectives;
  }

  public void setPolicyDirectives(final String policyDirectives) {
    this.policyDirectives = policyDirectives;
  }

  public boolean isReportOnly() {
    return reportOnly;
  }

  public void setReportOnly(final boolean reportOnly) {
    this.reportOnly = reportOnly;
  }

  /**
   * Resolves the policy string this config represents. An explicitly-set {@link
   * #getPolicyDirectives()} always wins; otherwise the built-in default for {@link #getMode()} is
   * returned. When {@code mode == CUSTOM} and no directives are set the result is {@code null}.
   */
  public String resolvePolicy() {
    if (policyDirectives != null && !policyDirectives.isBlank()) {
      return policyDirectives;
    }
    return switch (mode) {
      case SAAS -> DEFAULT_SAAS_SECURITY_POLICY;
      case SELF_MANAGED -> DEFAULT_SM_SECURITY_POLICY;
      case CUSTOM -> null;
    };
  }
}
