/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.user;

import com.fasterxml.jackson.core.io.JsonStringEncoder;
import io.camunda.security.api.context.CamundaAuthenticationProvider;
import io.camunda.security.api.model.CamundaAuthentication;
import io.camunda.security.api.model.user.CamundaUserDTO;
import io.camunda.security.core.port.in.CamundaUserPort;
import io.camunda.security.core.port.out.AuthorizedComponentsPort;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.Optional;
import org.jspecify.annotations.NullMarked;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.StandardClaimAccessor;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;


/**
 * Default {@link CamundaUserPort} for OIDC deployments. Builds a {@link CamundaUserDTO} from the
 * active {@link CamundaAuthentication} and the OIDC principal carried in the Spring Security
 * context, and returns the access (or id) token via {@link OAuth2AuthorizedClientRepository}.
 *
 * <p>The default <strong>does not</strong> resolve tenant display names, SaaS metadata, or {@code
 * c8Links}; those values are left empty because CSL has no contract for them. Authorized components
 * come from the host-provided {@link AuthorizedComponentsPort} (in OC, the adapter delegates to
 * {@code ResourceAccessProvider}); when no adapter is registered, the configuration falls back to
 * an empty-list bean.
 */
public class OidcCamundaUserService implements CamundaUserPort {

  private static final String SALES_PLAN_TYPE = "";
  private static final JsonStringEncoder JSON_STRING_ENCODER = JsonStringEncoder.getInstance();

  private final CamundaAuthenticationProvider authenticationProvider;
  private final AuthorizedComponentsPort authorizedComponentsPort;
  private final OAuth2AuthorizedClientRepository authorizedClientRepository;
  private final HttpServletRequest request;

  public OidcCamundaUserService(
      final CamundaAuthenticationProvider authenticationProvider,
      final AuthorizedComponentsPort authorizedComponentsPort,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final HttpServletRequest request) {
    this.authenticationProvider = authenticationProvider;
    this.authorizedComponentsPort = authorizedComponentsPort;
    this.authorizedClientRepository = authorizedClientRepository;
    this.request = request;
  }

  @Override
  public CamundaUserDTO getCurrentUser() {
    final var authentication = authenticationProvider.getCamundaAuthentication();
    return Optional.ofNullable(authentication)
        .filter(a -> !a.isAnonymous())
        .map(this::toUserDto)
        .orElse(null);
  }

  @Override
  public String getUserToken() {
    final var authentication = SecurityContextHolder.getContext().getAuthentication();
    final var oidcUser = getOidcUser(authentication);
    if (oidcUser == null) {
      throw new UnsupportedOperationException("User is not authenticated or is not a OIDC user");
    }
    return Optional.ofNullable(getToken(authentication, oidcUser))
        .map(OidcCamundaUserService::toJsonStringLiteral)
        .orElseThrow(() -> new UnsupportedOperationException("User does not have a valid token"));
  }

  /**
   * Wraps the raw token in a JSON string literal (escaped and surrounded by quotes) so the {@code
   * /v2/authentication/me/token} response body stays byte-identical to OC's pre-migration {@code
   * Json.createValue(token).toString()} behaviour. The endpoint declares {@code application/json},
   * so the body must be a valid JSON value, not raw text.
   */
  private static String toJsonStringLiteral(final String value) {
    return "\"" + new String(JSON_STRING_ENCODER.quoteAsString(value)) + "\"";
  }

  protected CamundaUserDTO toUserDto(final CamundaAuthentication authentication) {
    final var claimAccessor = getStandardClaimAccessor();
    final var fullName = claimAccessor != null ? claimAccessor.getFullName() : null;
    final var email = claimAccessor != null ? claimAccessor.getEmail() : null;

    return new CamundaUserDTO(
        fullName,
        authentication.authenticatedUsername(),
        email,
        authorizedComponentsPort.resolve(authentication),
        authentication.authenticatedTenantIds(),
        authentication.authenticatedGroupIds(),
        authentication.authenticatedRoleIds(),
        SALES_PLAN_TYPE,
        true);
  }

  protected StandardClaimAccessor getStandardClaimAccessor() {
    final var authentication = SecurityContextHolder.getContext().getAuthentication();
    final var oidcUser = getOidcUser(authentication);
    if (oidcUser != null) {
      return oidcUser;
    }
    return getOidcTokenBasedUser(authentication);
  }

  protected OidcUser getOidcUser(final Authentication authentication) {
    return Optional.ofNullable(authentication)
        .map(Authentication::getPrincipal)
        .filter(OidcUser.class::isInstance)
        .map(OidcUser.class::cast)
        .orElse(null);
  }

  protected StandardClaimAccessor getOidcTokenBasedUser(final Authentication authentication) {
    return Optional.ofNullable(authentication)
        .filter(AbstractOAuth2TokenAuthenticationToken.class::isInstance)
        .map(AbstractOAuth2TokenAuthenticationToken.class::cast)
        .map(AbstractOAuth2TokenAuthenticationToken::getTokenAttributes)
        .map(OidcTokenUser::new)
        .orElse(null);
  }

  protected String getToken(final Authentication authentication, final OidcUser oidcUser) {
    return Optional.ofNullable(getAccessToken(authentication))
        .orElseGet(() -> getIdToken(oidcUser));
  }

  protected String getAccessToken(final Authentication authentication) {
    return Optional.of(authentication)
        .filter(OAuth2AuthenticationToken.class::isInstance)
        .map(OAuth2AuthenticationToken.class::cast)
        .map(this::getAuthorizedClient)
        .map(OAuth2AuthorizedClient::getAccessToken)
        .map(OAuth2AccessToken::getTokenValue)
        .orElse(null);
  }

  protected String getIdToken(final OidcUser oidcUser) {
    return Optional.of(oidcUser)
        .map(OidcUser::getIdToken)
        .map(OidcIdToken::getTokenValue)
        .orElse(null);
  }

  protected OAuth2AuthorizedClient getAuthorizedClient(final OAuth2AuthenticationToken token) {
    return authorizedClientRepository.loadAuthorizedClient(
        token.getAuthorizedClientRegistrationId(), token, request);
  }

  record OidcTokenUser(Map<String, Object> claims) implements StandardClaimAccessor {

    @Override
    @NullMarked
    public Map<String, Object> getClaims() {
      return claims;
    }
  }
}
