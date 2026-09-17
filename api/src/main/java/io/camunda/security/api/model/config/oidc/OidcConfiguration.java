/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config.oidc;

import static io.camunda.security.api.model.config.AssertionConfiguration.KidDigestAlgorithm;
import static io.camunda.security.api.model.config.AssertionConfiguration.KidEncoding;
import static io.camunda.security.api.model.config.AssertionConfiguration.KidSource;

import io.camunda.security.api.model.config.AssertionConfiguration;
import io.camunda.security.api.model.config.oidc.validator.OidcGroupsClaimValidator;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

public class OidcConfiguration {
  public static final String GROUPS_CLAIM_PROPERTY =
      "camunda.security.authentication.oidc.groupsClaim";

  public static final String CLIENT_AUTHENTICATION_METHOD_CLIENT_SECRET_BASIC =
      "client_secret_basic";
  public static final String CLIENT_AUTHENTICATION_METHOD_PRIVATE_KEY_JWT = "private_key_jwt";
  public static final List<String> CLIENT_AUTHENTICATION_METHODS =
      List.of(
          CLIENT_AUTHENTICATION_METHOD_CLIENT_SECRET_BASIC,
          CLIENT_AUTHENTICATION_METHOD_PRIVATE_KEY_JWT);
  public static final Duration DEFAULT_CLOCK_SKEW = Duration.ofSeconds(60);
  public static final String DEFAULT_GRANT_TYPE = "authorization_code";
  public static final String DEFAULT_ID_TOKEN_ALGORITHM = "RS256";
  public static final String DEFAULT_USERNAME_CLAIM = "sub";
  public static final String DEFAULT_REGISTRATION_ID = "oidc";
  public static final List<String> DEFAULT_SCOPE = Arrays.asList("openid", "profile");
  public static final boolean DEFAULT_IDP_LOGOUT_ENABLED = true;
  public static final boolean DEFAULT_POST_LOGOUT_REDIRECT_ENABLED = true;
  public static final boolean DEFAULT_USER_INFO_ENABLED = true;

  private String issuerUri;
  private String clientName;
  private String clientId;
  private String registrationId = DEFAULT_REGISTRATION_ID;
  private String clientSecret;
  private String idTokenAlgorithm = DEFAULT_ID_TOKEN_ALGORITHM;
  private String grantType = DEFAULT_GRANT_TYPE;
  private String redirectUri;
  private List<String> scope = DEFAULT_SCOPE;
  private String jwkSetUri;
  private List<String> additionalJwkSetUris;
  private String authorizationUri;
  private String endSessionEndpointUri;
  private String tokenUri;
  private String userInfoUri;
  private AuthorizeRequestConfiguration authorizeRequestConfiguration =
      new AuthorizeRequestConfiguration();
  private Set<String> audiences;
  private String usernameClaim = DEFAULT_USERNAME_CLAIM;
  private String clientIdClaim;
  private String groupsClaim;
  private boolean preferUsernameClaim;
  private boolean preferIdTokenClaims;
  private String organizationId;
  private List<String> resource;
  private String clientAuthenticationMethod = CLIENT_AUTHENTICATION_METHOD_CLIENT_SECRET_BASIC;
  private AssertionConfiguration assertionConfiguration = new AssertionConfiguration();
  private Duration clockSkew = DEFAULT_CLOCK_SKEW;
  private boolean idpLogoutEnabled = DEFAULT_IDP_LOGOUT_ENABLED;
  private boolean postLogoutRedirectEnabled = DEFAULT_POST_LOGOUT_REDIRECT_ENABLED;
  private String postLogoutRedirectUri;
  private boolean userInfoEnabled = DEFAULT_USER_INFO_ENABLED;
  private OidcUserInfoAugmentationConfiguration userInfoAugmentation =
      new OidcUserInfoAugmentationConfiguration();
  private OidcDiagnosticsConfiguration diagnostics = new OidcDiagnosticsConfiguration();

  public void validate() {
    if (assertionConfiguration != null) {
      assertionConfiguration.validate();
    }
  }

  public List<String> getResource() {
    return resource;
  }

  public void setResource(final List<String> resource) {
    this.resource = resource;
  }

  public String getIssuerUri() {
    return issuerUri;
  }

  public void setIssuerUri(final String issuerUri) {
    this.issuerUri = issuerUri;
  }

  public String getIdTokenAlgorithm() {
    return idTokenAlgorithm;
  }

  public void setIdTokenAlgorithm(final String idTokenAlgorithm) {
    this.idTokenAlgorithm = idTokenAlgorithm;
  }

  public String getClientName() {
    return clientName;
  }

  public void setClientName(final String clientName) {
    this.clientName = clientName;
  }

  public String getClientId() {
    return clientId;
  }

  public void setClientId(final String clientId) {
    this.clientId = clientId;
  }

  public String getRegistrationId() {
    return registrationId;
  }

  public void setRegistrationId(final String registrationId) {
    this.registrationId = registrationId;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public void setClientSecret(final String clientSecret) {
    this.clientSecret = clientSecret;
  }

  public String getGrantType() {
    return grantType;
  }

  public void setGrantType(final String grantType) {
    this.grantType = grantType;
  }

  /**
   * The OAuth2 client {@code redirect_uri} that the application sends to the IdP. The application
   * also derives the redirection endpoint that serves the callback from this value. The two uses
   * must agree. A caller that derives an endpoint from this value therefore rejects it at startup
   * if the IdP would send the browser to a path where no redirection-endpoint filter listens.
   *
   * <p>If you set this property, it must expand to an absolute http(s) URL with a host, a callback
   * path and no fragment. If the URL has a port, the port must be in the range 1 to 65535. A query
   * is permitted. Spring expands only {@code {baseUrl}}, {@code {baseScheme}}, {@code {baseHost}},
   * {@code {basePort}}, {@code {basePath}}, {@code {registrationId}} and {@code {action}}. If you
   * do not set this property, the application uses the {@code {baseUrl}/sso-callback} default.
   *
   * <p>The adopters' security-filter-chains document tells you which chain serves that callback,
   * which callers apply the rule, and which values look correct but are rejected.
   */
  public String getRedirectUri() {
    return redirectUri;
  }

  public void setRedirectUri(final String redirectUri) {
    this.redirectUri = redirectUri;
  }

  public List<String> getScope() {
    return scope;
  }

  public void setScope(final List<String> scope) {
    this.scope = scope;
  }

  public String getJwkSetUri() {
    return jwkSetUri;
  }

  public void setJwkSetUri(final String jwkSetUri) {
    this.jwkSetUri = jwkSetUri;
  }

  public List<String> getAdditionalJwkSetUris() {
    return additionalJwkSetUris;
  }

  public void setAdditionalJwkSetUris(final List<String> additionalJwkSetUris) {
    this.additionalJwkSetUris = additionalJwkSetUris;
  }

  public String getAuthorizationUri() {
    return authorizationUri;
  }

  public void setAuthorizationUri(final String authorizationUri) {
    this.authorizationUri = authorizationUri;
  }

  public String getEndSessionEndpointUri() {
    return endSessionEndpointUri;
  }

  public void setEndSessionEndpointUri(final String endSessionEndpointUri) {
    this.endSessionEndpointUri = endSessionEndpointUri;
  }

  public String getTokenUri() {
    return tokenUri;
  }

  public void setTokenUri(final String tokenUri) {
    this.tokenUri = tokenUri;
  }

  public String getUserInfoUri() {
    return userInfoUri;
  }

  public void setUserInfoUri(final String userInfoUri) {
    this.userInfoUri = userInfoUri;
  }

  public AuthorizeRequestConfiguration getAuthorizeRequest() {
    return authorizeRequestConfiguration;
  }

  public void setAuthorizeRequest(
      final AuthorizeRequestConfiguration authorizeRequestConfiguration) {
    this.authorizeRequestConfiguration = authorizeRequestConfiguration;
  }

  public Set<String> getAudiences() {
    return audiences;
  }

  public void setAudiences(final Set<String> audiences) {
    this.audiences = audiences;
  }

  public String getUsernameClaim() {
    return usernameClaim;
  }

  public void setUsernameClaim(final String usernameClaim) {
    this.usernameClaim = usernameClaim;
  }

  public String getClientIdClaim() {
    return clientIdClaim;
  }

  public void setClientIdClaim(final String clientIdClaim) {
    this.clientIdClaim = clientIdClaim;
  }

  public String getOrganizationId() {
    return organizationId;
  }

  public void setOrganizationId(final String organizationId) {
    this.organizationId = organizationId;
  }

  public String getGroupsClaim() {
    return groupsClaim;
  }

  public void setGroupsClaim(final String groupsClaim) {
    OidcGroupsClaimValidator.validate(groupsClaim);
    this.groupsClaim = groupsClaim;
  }

  public boolean isGroupsClaimConfigured() {
    return groupsClaim != null && !groupsClaim.isBlank();
  }

  public boolean isPreferUsernameClaim() {
    return preferUsernameClaim;
  }

  public void setPreferUsernameClaim(final boolean preferUsernameClaim) {
    this.preferUsernameClaim = preferUsernameClaim;
  }

  public boolean isPreferIdTokenClaims() {
    return preferIdTokenClaims;
  }

  public void setPreferIdTokenClaims(final boolean preferIdTokenClaims) {
    this.preferIdTokenClaims = preferIdTokenClaims;
  }

  public String getClientAuthenticationMethod() {
    return clientAuthenticationMethod;
  }

  public void setClientAuthenticationMethod(final String clientAuthenticationMethod) {
    this.clientAuthenticationMethod = clientAuthenticationMethod;
  }

  public AssertionConfiguration getAssertion() {
    return assertionConfiguration;
  }

  public void setAssertion(final AssertionConfiguration assertionConfiguration) {
    this.assertionConfiguration = assertionConfiguration;
  }

  public Duration getClockSkew() {
    return clockSkew;
  }

  public void setClockSkew(final Duration clockSkew) {
    this.clockSkew = clockSkew;
  }

  public boolean isIdpLogoutEnabled() {
    return idpLogoutEnabled;
  }

  public void setIdpLogoutEnabled(final boolean idpLogoutEnabled) {
    this.idpLogoutEnabled = idpLogoutEnabled;
  }

  /**
   * Whether RP-initiated logout asks the IdP to send the browser back to the host afterwards, by
   * submitting the host's post-logout route (see {@code SecurityPathPort#postLogoutRedirectPath()})
   * as {@code post_logout_redirect_uri}. Enabled by default.
   *
   * <p>Disable it for an IdP that cannot have the resulting URL registered as an allowed
   * post-logout redirect. Auth0 matches {@code post_logout_redirect_uri} against its "Allowed
   * Logout URLs" exactly and accepts wildcards only in the subdomain position, never in the path —
   * so a deployment served under a per-tenant or per-cluster path prefix produces a URL no entry
   * can ever match, and Auth0 rejects the whole end-session request with {@code invalid_request}
   * rather than logging the user out.
   *
   * <p>{@link #isIdpLogoutEnabled()} is a separate, currently-unwired flag (no code path reads it
   * since ADR-0009 removed the host-provided {@code LogoutSuccessHandler} bean seam) — it is not an
   * orthogonal "contact the IdP at all" switch this property complements today. Disabling this
   * property still terminates the IdP session; the IdP renders its own logged-out page instead of
   * returning to the host.
   *
   * <p>See ADR-0023 for why this is configuration rather than a {@code SecurityPathPort} method.
   */
  public boolean isPostLogoutRedirectEnabled() {
    return postLogoutRedirectEnabled;
  }

  public void setPostLogoutRedirectEnabled(final boolean postLogoutRedirectEnabled) {
    this.postLogoutRedirectEnabled = postLogoutRedirectEnabled;
  }

  /**
   * The {@code post_logout_redirect_uri} to submit on this provider's RP-initiated logout request,
   * overriding the value CSL composes from the host's post-logout route. Unset by default, meaning
   * the composed value is used.
   *
   * <p>How the value is read depends on its first character:
   *
   * <ul>
   *   <li>Starting with {@code /} — a path, resolved against the chain it belongs to exactly as the
   *       host's own route is: {@code {baseUrl}} + the chain's base path + this path. Use it to
   *       land somewhere other than the host's post-logout route while keeping per-scope
   *       resolution.
   *   <li>Anything else — a URI template passed to Spring Security untouched, so an absolute {@code
   *       https://…} URL or a template such as {@code {baseUrl}/post-logout} both work. Spring
   *       expands {@code {baseUrl}}, {@code {baseScheme}}, {@code {baseHost}}, {@code {basePort}},
   *       {@code {basePath}} and {@code {registrationId}}. Notably this form does <em>not</em> pick
   *       up the chain's base path, which is the point: it is how a deployment served under a
   *       per-cluster prefix asks for a URL its IdP can actually have registered.
   * </ul>
   *
   * <p>Auth0 is the motivating case. It matches {@code post_logout_redirect_uri} against its
   * "Allowed Logout URLs" exactly, accepting wildcards only in the subdomain position and never in
   * the path, so the per-cluster URL CSL composes by default can never match an entry — and Auth0
   * answers the whole end-session request with {@code invalid_request} rather than logging the user
   * out. Setting a registerable URL here fixes that while keeping the redirect, where {@link
   * #isPostLogoutRedirectEnabled()} can only drop it.
   *
   * <p>Resolved per client registration, so each IdP in a multi-provider deployment can carry its
   * own value (or none). See ADR-0026.
   */
  public String getPostLogoutRedirectUri() {
    return postLogoutRedirectUri;
  }

  public void setPostLogoutRedirectUri(final String postLogoutRedirectUri) {
    this.postLogoutRedirectUri = postLogoutRedirectUri;
  }

  public boolean isUserInfoEnabled() {
    return userInfoEnabled;
  }

  public void setUserInfoEnabled(final boolean userInfoEnabled) {
    this.userInfoEnabled = userInfoEnabled;
  }

  public OidcUserInfoAugmentationConfiguration getUserInfoAugmentation() {
    return userInfoAugmentation;
  }

  public void setUserInfoAugmentation(
      final OidcUserInfoAugmentationConfiguration userInfoAugmentation) {
    this.userInfoAugmentation = userInfoAugmentation;
  }

  public OidcDiagnosticsConfiguration getDiagnostics() {
    return diagnostics;
  }

  public void setDiagnostics(final OidcDiagnosticsConfiguration diagnostics) {
    this.diagnostics = diagnostics != null ? diagnostics : new OidcDiagnosticsConfiguration();
  }

  /**
   * Returns whether any OIDC property deviates from the default configuration.
   *
   * <p>This includes direct OIDC fields as well as nested assertion/keystore settings. The method
   * is used by higher-level configuration validation to detect when OIDC settings are present and
   * should therefore be considered active.
   *
   * @return {@code true} when at least one property is non-default; {@code false} otherwise
   */
  public boolean isAnyPropertySet() {
    final AssertionConfiguration currentAssertionConfiguration = assertionConfiguration;
    final var currentKeystoreConfiguration =
        currentAssertionConfiguration != null ? currentAssertionConfiguration.getKeystore() : null;
    return issuerUri != null
        || clientId != null
        || clientName != null
        || clientSecret != null
        || !DEFAULT_ID_TOKEN_ALGORITHM.equals(idTokenAlgorithm)
        || !DEFAULT_GRANT_TYPE.equals(grantType)
        || redirectUri != null
        || !DEFAULT_SCOPE.equals(scope)
        || jwkSetUri != null
        || additionalJwkSetUris != null
        || authorizationUri != null
        || endSessionEndpointUri != null
        || tokenUri != null
        || userInfoUri != null
        || authorizeRequestConfiguration == null
        || authorizeRequestConfiguration.isSet()
        || !DEFAULT_USERNAME_CLAIM.equals(usernameClaim)
        || audiences != null
        || clientIdClaim != null
        || groupsClaim != null
        || preferUsernameClaim
        || preferIdTokenClaims
        || organizationId != null
        || !CLIENT_AUTHENTICATION_METHOD_CLIENT_SECRET_BASIC.equals(clientAuthenticationMethod)
        || currentAssertionConfiguration == null
        || currentKeystoreConfiguration == null
        || currentKeystoreConfiguration.getPath() != null
        || currentKeystoreConfiguration.getPassword() != null
        || currentKeystoreConfiguration.getKeyAlias() != null
        || currentKeystoreConfiguration.getKeyPassword() != null
        || currentAssertionConfiguration.getKidSource() != KidSource.PUBLIC_KEY
        || currentAssertionConfiguration.getKidDigestAlgorithm() != KidDigestAlgorithm.SHA256
        || currentAssertionConfiguration.getKidEncoding() != KidEncoding.BASE64URL
        || currentAssertionConfiguration.getKidCase() != null
        || !DEFAULT_CLOCK_SKEW.equals(clockSkew)
        || postLogoutRedirectEnabled != DEFAULT_POST_LOGOUT_REDIRECT_ENABLED
        || postLogoutRedirectUri != null
        || diagnostics.isEnabled();
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {
    private String issuerUri;
    private String clientId;
    private String clientName;
    private String registrationId = DEFAULT_REGISTRATION_ID;
    private String clientSecret;
    private String idTokenAlgorithm = DEFAULT_ID_TOKEN_ALGORITHM;
    private String grantType = DEFAULT_GRANT_TYPE;
    private String redirectUri;
    private List<String> scope = DEFAULT_SCOPE;
    private String jwkSetUri;
    private List<String> additionalJwkSetUris;
    private String authorizationUri;
    private String endSessionEndpointUri;
    private String tokenUri;
    private String userInfoUri;
    private AuthorizeRequestConfiguration authorizeRequestConfiguration =
        new AuthorizeRequestConfiguration();
    private Set<String> audiences;
    private String usernameClaim = DEFAULT_USERNAME_CLAIM;
    private String clientIdClaim;
    private String groupsClaim;
    private boolean preferUsernameClaim;
    private boolean preferIdTokenClaims;
    private String organizationId;
    private String clientAuthenticationMethod = CLIENT_AUTHENTICATION_METHOD_CLIENT_SECRET_BASIC;
    private AssertionConfiguration assertionConfiguration = new AssertionConfiguration();
    private Duration clockSkew = DEFAULT_CLOCK_SKEW;
    private boolean idpLogoutEnabled = DEFAULT_IDP_LOGOUT_ENABLED;
    private boolean postLogoutRedirectEnabled = DEFAULT_POST_LOGOUT_REDIRECT_ENABLED;
    private String postLogoutRedirectUri;
    private boolean userInfoEnabled = DEFAULT_USER_INFO_ENABLED;
    private OidcUserInfoAugmentationConfiguration userInfoAugmentation =
        new OidcUserInfoAugmentationConfiguration();
    private OidcDiagnosticsConfiguration diagnostics = new OidcDiagnosticsConfiguration();

    public Builder issuerUri(final String issuerUri) {
      this.issuerUri = issuerUri;
      return this;
    }

    public Builder clientId(final String clientId) {
      this.clientId = clientId;
      return this;
    }

    public Builder clientName(final String clientName) {
      this.clientName = clientName;
      return this;
    }

    public Builder registrationId(final String registrationId) {
      this.registrationId = registrationId;
      return this;
    }

    public Builder clientSecret(final String clientSecret) {
      this.clientSecret = clientSecret;
      return this;
    }

    public Builder idTokenAlgorithm(final String idTokenAlgorithm) {
      this.idTokenAlgorithm = idTokenAlgorithm;
      return this;
    }

    public Builder grantType(final String grantType) {
      this.grantType = grantType;
      return this;
    }

    public Builder redirectUri(final String redirectUri) {
      this.redirectUri = redirectUri;
      return this;
    }

    public Builder scope(final List<String> scope) {
      this.scope = scope;
      return this;
    }

    public Builder jwkSetUri(final String jwkSetUri) {
      this.jwkSetUri = jwkSetUri;
      return this;
    }

    public Builder additionalJwkSetUris(final List<String> additionalJwkSetUris) {
      this.additionalJwkSetUris = additionalJwkSetUris;
      return this;
    }

    public Builder authorizationUri(final String authorizationUri) {
      this.authorizationUri = authorizationUri;
      return this;
    }

    public Builder endSessionEndpointUri(final String endSessionEndpointUri) {
      this.endSessionEndpointUri = endSessionEndpointUri;
      return this;
    }

    public Builder tokenUri(final String tokenUri) {
      this.tokenUri = tokenUri;
      return this;
    }

    public Builder userInfoUri(final String userInfoUri) {
      this.userInfoUri = userInfoUri;
      return this;
    }

    public Builder authorizeRequestConfiguration(
        final AuthorizeRequestConfiguration authorizeRequestConfiguration) {
      this.authorizeRequestConfiguration = authorizeRequestConfiguration;
      return this;
    }

    public Builder audiences(final Set<String> audiences) {
      this.audiences = audiences;
      return this;
    }

    public Builder usernameClaim(final String usernameClaim) {
      this.usernameClaim = usernameClaim;
      return this;
    }

    public Builder clientIdClaim(final String clientIdClaim) {
      this.clientIdClaim = clientIdClaim;
      return this;
    }

    public Builder groupsClaim(final String groupsClaim) {
      OidcGroupsClaimValidator.validate(groupsClaim);
      this.groupsClaim = groupsClaim;
      return this;
    }

    public Builder preferUsernameClaim(final boolean preferUsernameClaim) {
      this.preferUsernameClaim = preferUsernameClaim;
      return this;
    }

    public Builder preferIdTokenClaims(final boolean preferIdTokenClaims) {
      this.preferIdTokenClaims = preferIdTokenClaims;
      return this;
    }

    public Builder organizationId(final String organizationId) {
      this.organizationId = organizationId;
      return this;
    }

    public Builder clientAuthenticationMethod(final String clientAuthenticationMethod) {
      this.clientAuthenticationMethod = clientAuthenticationMethod;
      return this;
    }

    public Builder assertionConfiguration(final AssertionConfiguration assertionConfiguration) {
      this.assertionConfiguration = assertionConfiguration;
      return this;
    }

    public Builder clockSkew(final Duration clockSkew) {
      this.clockSkew = clockSkew;
      return this;
    }

    public Builder idpLogoutEnabled(final boolean idpLogoutEnabled) {
      this.idpLogoutEnabled = idpLogoutEnabled;
      return this;
    }

    public Builder postLogoutRedirectEnabled(final boolean postLogoutRedirectEnabled) {
      this.postLogoutRedirectEnabled = postLogoutRedirectEnabled;
      return this;
    }

    public Builder postLogoutRedirectUri(final String postLogoutRedirectUri) {
      this.postLogoutRedirectUri = postLogoutRedirectUri;
      return this;
    }

    public Builder userInfoEnabled(final boolean userInfoEnabled) {
      this.userInfoEnabled = userInfoEnabled;
      return this;
    }

    public Builder userInfoAugmentation(
        final OidcUserInfoAugmentationConfiguration userInfoAugmentation) {
      this.userInfoAugmentation = userInfoAugmentation;
      return this;
    }

    public OidcConfiguration build() {
      final OidcConfiguration config = new OidcConfiguration();
      config.setIssuerUri(issuerUri);
      config.setClientId(clientId);
      config.setClientName(clientName);
      config.setRegistrationId(registrationId);
      config.setClientSecret(clientSecret);
      config.setIdTokenAlgorithm(idTokenAlgorithm);
      config.setGrantType(grantType);
      config.setRedirectUri(redirectUri);
      config.setEndSessionEndpointUri(endSessionEndpointUri);
      config.setScope(scope);
      config.setJwkSetUri(jwkSetUri);
      config.setAdditionalJwkSetUris(additionalJwkSetUris);
      config.setAuthorizationUri(authorizationUri);
      config.setTokenUri(tokenUri);
      config.setUserInfoUri(userInfoUri);
      config.setAuthorizeRequest(authorizeRequestConfiguration);
      config.setAudiences(audiences);
      config.setUsernameClaim(usernameClaim);
      config.setClientIdClaim(clientIdClaim);
      config.setGroupsClaim(groupsClaim);
      config.setPreferUsernameClaim(preferUsernameClaim);
      config.setPreferIdTokenClaims(preferIdTokenClaims);
      config.setOrganizationId(organizationId);
      config.setClientAuthenticationMethod(clientAuthenticationMethod);
      config.setAssertion(assertionConfiguration);
      config.setClockSkew(clockSkew);
      config.setIdpLogoutEnabled(idpLogoutEnabled);
      config.setPostLogoutRedirectEnabled(postLogoutRedirectEnabled);
      config.setPostLogoutRedirectUri(postLogoutRedirectUri);
      config.setUserInfoEnabled(userInfoEnabled);
      config.setUserInfoAugmentation(userInfoAugmentation);
      config.setDiagnostics(diagnostics);
      return config;
    }
  }
}
