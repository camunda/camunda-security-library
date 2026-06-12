/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring;

import io.camunda.security.api.model.config.*;
import io.camunda.security.api.model.config.headers.HeaderConfiguration;
import io.camunda.security.api.model.config.initialization.InitializationConfiguration;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import jakarta.annotation.PostConstruct;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

/**
 * Binds {@code camunda.security.*} configuration values for the CSL filter chains.
 *
 * <p>The legacy name in OC was SecurityConfiguration
 */
@ConfigurationProperties(prefix = "camunda.security")
public class CamundaSecurityLibraryProperties {

  /** 1 or more alphanumeric characters, '_', '@', '.', '+', '-' or '~'. */
  public static final String DEFAULT_ID_REGEX = "^[a-zA-Z0-9_~@.+-]+$";

  public static final Pattern DEFAULT_EXTERNAL_ID_PATTERN = Pattern.compile(".*", Pattern.DOTALL);

  @NestedConfigurationProperty
  private AuthenticationConfiguration authentication = new AuthenticationConfiguration();

  @NestedConfigurationProperty
  private AuthorizationsConfiguration authorizations = new AuthorizationsConfiguration();

  @NestedConfigurationProperty
  private InitializationConfiguration initialization = new InitializationConfiguration();

  @NestedConfigurationProperty
  private MultiTenancyConfiguration multiTenancy = new MultiTenancyConfiguration();

  @NestedConfigurationProperty private CsrfConfiguration csrf = new CsrfConfiguration();

  @NestedConfigurationProperty private HeaderConfiguration httpHeaders = new HeaderConfiguration();

  @NestedConfigurationProperty private SaasConfiguration saas = new SaasConfiguration();

  @NestedConfigurationProperty private SessionConfiguration session = new SessionConfiguration();

  /**
   * The ID validation pattern is configurable with the intention to:
   *
   * <ul>
   *   <li>allow customers to use even more strict validation
   *   <li>be able to react quickly if there was any ReDoS vulnerability within the default pattern
   * </ul>
   */
  private String idValidationPattern = DEFAULT_ID_REGEX;

  private Pattern compiledIdValidationPattern;

  public AuthenticationConfiguration getAuthentication() {
    return authentication;
  }

  public void setAuthentication(final AuthenticationConfiguration authentication) {
    this.authentication = authentication;
  }

  public AuthorizationsConfiguration getAuthorizations() {
    return authorizations;
  }

  public void setAuthorizations(final AuthorizationsConfiguration authorizations) {
    this.authorizations = authorizations;
  }

  public InitializationConfiguration getInitialization() {
    return initialization;
  }

  public void setInitialization(final InitializationConfiguration initialization) {
    this.initialization = initialization;
  }

  public MultiTenancyConfiguration getMultiTenancy() {
    return multiTenancy;
  }

  public void setMultiTenancy(final MultiTenancyConfiguration multiTenancy) {
    this.multiTenancy = multiTenancy;
  }

  public boolean isApiProtected() {
    return authentication == null || !authentication.isUnprotectedApi();
  }

  public SaasConfiguration getSaas() {
    return saas;
  }

  public void setSaas(final SaasConfiguration saas) {
    this.saas = saas;
  }

  public HeaderConfiguration getHttpHeaders() {
    return httpHeaders;
  }

  public void setHttpHeaders(final HeaderConfiguration httpHeaders) {
    this.httpHeaders = httpHeaders;
  }

  public CsrfConfiguration getCsrf() {
    return csrf;
  }

  public void setCsrf(final CsrfConfiguration csrf) {
    this.csrf = csrf;
  }

  public SessionConfiguration getSession() {
    return session;
  }

  public void setSession(final SessionConfiguration session) {
    this.session = session;
  }

  public String getIdValidationPattern() {
    return idValidationPattern;
  }

  public void setIdValidationPattern(final String idValidationPattern) {
    if (idValidationPattern == null || idValidationPattern.isBlank()) {
      throw new IllegalArgumentException(
          "camunda.security.id-validation-pattern must not be null or blank");
    }
    this.idValidationPattern = idValidationPattern;
    compiledIdValidationPattern = null;
  }

  public Pattern getCompiledIdValidationPattern() {
    if (compiledIdValidationPattern == null) {
      validateIdValidationPattern();
    }
    return compiledIdValidationPattern;
  }

  public Pattern getCompiledGroupIdValidationPattern() {
    final var oidcConfiguration = getAuthentication().getOidc();
    if (oidcConfiguration != null && oidcConfiguration.isGroupsClaimConfigured()) {
      return DEFAULT_EXTERNAL_ID_PATTERN;
    }
    return getCompiledIdValidationPattern();
  }

  @PostConstruct
  void validate() {
    validateIdValidationPattern();

    if (authentication == null) {
      return;
    }

    validateOidcConfiguration(authentication.getOidc());

    final var providers = authentication.getProviders();
    if (providers != null && providers.getOidc() != null) {
      providers.getOidc().values().forEach(this::validateOidcConfiguration);
    }
  }

  private void validateIdValidationPattern() {
    if (idValidationPattern == null) {
      throw new IllegalStateException("camunda.security.id-validation-pattern must not be null");
    }

    try {
      compiledIdValidationPattern = Pattern.compile(idValidationPattern);
    } catch (final PatternSyntaxException exception) {
      throw new IllegalStateException(
          "Invalid regex for camunda.security.id-validation-pattern: " + idValidationPattern,
          exception);
    }
  }

  private void validateOidcConfiguration(final OidcConfiguration oidcConfiguration) {
    if (oidcConfiguration != null) {
      oidcConfiguration.validate();
    }
  }
}
