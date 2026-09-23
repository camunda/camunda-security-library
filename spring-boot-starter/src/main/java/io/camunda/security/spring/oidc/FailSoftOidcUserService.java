/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

/**
 * Default {@link OidcUserService} that degrades to ID-token-only claims when the {@code /userinfo}
 * call fails, instead of failing login. See ADR-0028.
 *
 * <p>Several IdPs reject the access token at {@code /userinfo} even though it's valid for local JWT
 * validation — Microsoft Entra with the documented {@code <client-id>/.default} scope always,
 * Auth0/Okta/PingFederate in common audience-bound setups. A transport error or malformed response
 * fails the same way. {@code DefaultOAuth2UserService} maps all of these to the same {@code
 * invalid_user_info_response} error code that {@link OidcUserService#loadUser} also uses for its
 * OIDC S:5.3.2 sub-mismatch check, so the two cases can't be told apart by error code. Only the
 * delegate fetch call is wrapped, in a private marker exception, making them structurally
 * distinguishable instead: the sub-mismatch check runs after the delegate returns, so it can never
 * be caught here.
 *
 * <p>A provider that cannot tolerate missing UserInfo claims (e.g. groups sourced only from
 * UserInfo) sets {@code user-info-required=true}; this class then re-throws instead of degrading.
 * This applies on token refresh too: Spring wires this bean into {@code
 * OidcAuthorizedClientRefreshedEventListener}, so without the flag a UserInfo failure there would
 * silently narrow a live session's claims instead of failing the refresh.
 *
 * <p>WARN logs omit the throwable (registration id + error code only) since this can fire on every
 * refresh for a structurally broken IdP; the cause is at DEBUG.
 */
public final class FailSoftOidcUserService extends OidcUserService {

  /**
   * {@link ClientRegistration} provider-metadata key for the per-provider {@code
   * user-info-required} flag, set by {@link ScopedClientRegistrationFactory#mergeProviderMetadata}.
   * Absent (e.g. a registration built outside CSL) is treated as {@code false}.
   */
  public static final String USER_INFO_REQUIRED_METADATA_KEY =
      "camunda.security.oidc.userInfoRequired";

  private static final Logger LOG = LoggerFactory.getLogger(FailSoftOidcUserService.class);

  /**
   * Reproduces exactly what {@code user-info-enabled=false} produces (ADR-0007). A separate
   * instance from {@code this} on purpose: flipping {@code retrieveUserInfo} on {@code this}
   * instead would double the UserInfo call or disable it on the happy path.
   */
  private final OidcUserService idTokenOnlyFallback = newIdTokenOnlyService();

  public FailSoftOidcUserService(final OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate) {
    setOauth2UserService(
        request -> {
          try {
            return delegate.loadUser(request);
          } catch (final OAuth2AuthenticationException fetchFailure) {
            throw new UserInfoFetchFailedException(fetchFailure);
          }
        });
  }

  @Override
  public OidcUser loadUser(final OidcUserRequest userRequest) throws OAuth2AuthenticationException {
    try {
      return super.loadUser(userRequest);
    } catch (final UserInfoFetchFailedException wrapped) {
      final var originalFailure = wrapped.original;
      final var registrationId = userRequest.getClientRegistration().getRegistrationId();
      final var errorCode = originalFailure.getError().getErrorCode();
      if (isUserInfoRequired(userRequest)) {
        LOG.warn(
            "OIDC /userinfo call failed for registration '{}' ({}); failing login because"
                + " user-info-required=true for this provider",
            registrationId,
            errorCode);
        throw originalFailure;
      }
      LOG.warn(
          "OIDC /userinfo call failed for registration '{}' ({}); continuing login with"
              + " ID-token-only claims. Set user-info-required=true for this provider to fail"
              + " login instead, or adjust the requested scope so the access token is accepted"
              + " at this IdP's userinfo endpoint.",
          registrationId,
          errorCode);
      LOG.debug("OIDC /userinfo call failure detail", originalFailure);
      return idTokenOnlyFallback.loadUser(userRequest);
    }
  }

  private static boolean isUserInfoRequired(final OidcUserRequest userRequest) {
    final Map<String, Object> metadata =
        userRequest.getClientRegistration().getProviderDetails().getConfigurationMetadata();
    return Boolean.TRUE.equals(metadata.get(USER_INFO_REQUIRED_METADATA_KEY));
  }

  private static OidcUserService newIdTokenOnlyService() {
    final var service = new OidcUserService();
    service.setRetrieveUserInfo(request -> false);
    return service;
  }

  /**
   * Marks a failed UserInfo fetch, distinct from the sub-validation {@link
   * OAuth2AuthenticationException} that {@link OidcUserService#loadUser} throws afterward on a
   * successful fetch. Never escapes {@link #loadUser}: the {@code user-info-required=true} branch
   * rethrows {@link #original}, never {@code this}. Extends {@code RuntimeException}, not {@link
   * OAuth2AuthenticationException}, so it can't be mistaken for the type whose ambiguity motivated
   * wrapping the delegate in the first place.
   */
  private static final class UserInfoFetchFailedException extends RuntimeException {
    private final OAuth2AuthenticationException original;

    UserInfoFetchFailedException(final OAuth2AuthenticationException original) {
      super(original.getMessage(), original);
      this.original = original;
    }
  }
}
