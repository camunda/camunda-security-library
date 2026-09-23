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
 * Default {@link OidcUserService} that degrades to ID-token-only claims when the IdP's {@code
 * /userinfo} endpoint rejects the app's access token, instead of failing login. See ADR-0028.
 *
 * <p>Several IdPs issue an access token whose audience {@code /userinfo} does not accept, even
 * though the same token is exactly what Camunda needs for local JWT validation — Microsoft Entra
 * with the documented {@code <client-id>/.default} scope always, Auth0/Okta/PingFederate in common
 * audience-bound configurations. The delegate can also fail for a plain transport error, or a
 * malformed/non-JSON response body (e.g. an HTML error page from a misconfigured gateway in front
 * of the IdP) — {@code DefaultOAuth2UserService} maps all three to the same error code (see below),
 * and none of them yields any claims to validate, so none of them can be the OIDC S:5.3.2 violation
 * handled separately below. Spring Security's stock {@link OidcUserService} treats all of these as
 * fatal. This subclass mirrors the fail-open policy {@link CachingOidcClaimsProvider} already
 * applies on the resource-server augmentation path (ADR-0007): attempt the call, use it when it
 * succeeds, log a WARN and continue with ID-token-only claims when it fails.
 *
 * <p>The distinction between "the fetch itself failed" (fail-soft) and "the fetch succeeded but the
 * response fails OIDC S:5.3.2 sub validation" (still fatal — a token-substitution defense) cannot
 * be made by inspecting the caught {@link OAuth2AuthenticationException}: Spring Security gives
 * both the identical {@code invalid_user_info_response} error code. So only the delegate fetch call
 * is wrapped; a failure there is translated into a private marker exception, making it structurally
 * — not heuristically — distinguishable from the unwrapped sub-validation failure that {@link
 * OidcUserService#loadUser} throws afterward on a successful fetch.
 *
 * <p>A provider that cannot tolerate missing UserInfo claims (for example, groups sourced only from
 * UserInfo) sets the per-provider {@code user-info-required} property; this class then re-throws
 * instead of degrading.
 *
 * <p>Logged at WARN without the original throwable: Spring Security's {@code OAuth2LoginConfigurer}
 * wires this same bean into {@code OidcAuthorizedClientRefreshedEventListener}, so for a
 * structurally-mismatched IdP this fires not just at login but on every access-token refresh — a
 * full stack trace there is log noise. The cause is still available at DEBUG. The same refresh-path
 * invocation is also why a provider whose authorization-relevant claims are available only via
 * UserInfo should set {@code user-info-required=true}: otherwise a transient fetch failure during a
 * live session's token refresh, not just at login, silently narrows that session to ID-token-only
 * claims instead of failing the refresh.
 */
public final class FailSoftOidcUserService extends OidcUserService {

  /**
   * {@link ClientRegistration} provider-metadata key carrying the per-provider {@code
   * user-info-required} flag, set by {@link ScopedClientRegistrationFactory#mergeProviderMetadata}.
   * Absent — as for a registration built outside CSL, e.g. a host-supplied {@code
   * ClientRegistrationRepository} — is treated as {@code false}: fail-soft is the default posture.
   */
  public static final String USER_INFO_REQUIRED_METADATA_KEY =
      "camunda.security.oidc.userInfoRequired";

  private static final Logger LOG = LoggerFactory.getLogger(FailSoftOidcUserService.class);

  /**
   * Reproduces exactly what {@code user-info-enabled=false} already produces (ADR-0007).
   * Deliberately a separate instance from {@code this}: it must always skip the UserInfo call,
   * while {@code this} must attempt it on every request. Reusing {@code this} for the fallback (by
   * flipping {@code retrieveUserInfo} on it directly) would either double the UserInfo call or
   * silently disable it on the happy path.
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
   * Marks a failure of the wrapped UserInfo fetch, distinct from the unwrapped sub-validation
   * {@link OAuth2AuthenticationException} that {@link OidcUserService#loadUser} throws afterward on
   * a successful fetch. Private on purpose: nothing outside this class constructs or catches it,
   * and no instance of it may ever leave {@link #loadUser}: the {@code user-info-required=true}
   * branch above rethrows {@link #original}, never {@code this}. A plain {@code RuntimeException} —
   * not an {@link OAuth2AuthenticationException} subclass — on purpose: that keeps this marker
   * impossible to mistake for, or accidentally catch as, the exception type whose ambiguity
   * motivated wrapping the delegate in the first place.
   */
  private static final class UserInfoFetchFailedException extends RuntimeException {
    private final OAuth2AuthenticationException original;

    UserInfoFetchFailedException(final OAuth2AuthenticationException original) {
      super(original.getMessage(), original);
      this.original = original;
    }
  }
}
