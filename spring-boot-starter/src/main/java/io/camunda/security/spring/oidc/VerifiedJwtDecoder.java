/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import io.camunda.security.api.model.config.oidc.OidcPrincipalClaims;
import java.util.Map;
import java.util.function.Function;
import org.jspecify.annotations.Nullable;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * Decodes as its delegate, and returns each token as a {@link VerifiedJwt} with the principal
 * claims of the provider whose registration verified it. The owner follows the routing of the
 * decoder, and the claims come from the providers of the decoder's own scope, so the claim settings
 * of a token never come from a provider that did not verify it.
 *
 * <p>The delegate is the decoder the public {@code OidcAccessTokenDecoderFactory} selection gives,
 * so a host that overrides that selection keeps its decoder; the owner is computed from the same
 * configuration by {@link OidcAccessTokenDecoderFactory#registrationIdByIssuer}.
 */
final class VerifiedJwtDecoder implements JwtDecoder {

  private final JwtDecoder delegate;
  private final Function<String, String> registrationIdByIssuer;
  private final Function<String, VerifiedJwtTag> tagByRegistrationId;

  private VerifiedJwtDecoder(
      final JwtDecoder delegate,
      final Function<String, String> registrationIdByIssuer,
      final Function<String, VerifiedJwtTag> tagByRegistrationId) {
    this.delegate = delegate;
    this.registrationIdByIssuer = registrationIdByIssuer;
    this.tagByRegistrationId = tagByRegistrationId;
  }

  /**
   * For the library's default decoder: the claims only. Its UserInfo use is decided by the global
   * claims provider, which routes as this decoder does.
   *
   * @param delegate the selected decoder
   * @param registrationIdByIssuer the registrationId the decoder routes the tokens of an issuer to
   * @param providers the providers of the decoder, keyed by registrationId
   * @param defaultSlot the default slot ({@code oidc.*}), whose claims a named provider inherits,
   *     and whose own tokens use the default claim converter
   */
  static JwtDecoder withClaims(
      final JwtDecoder delegate,
      final Function<String, String> registrationIdByIssuer,
      final Map<String, OidcConfiguration> providers,
      final @Nullable OidcConfiguration defaultSlot) {
    final var inherited = defaultSlot != null ? defaultSlot : new OidcConfiguration();
    return new VerifiedJwtDecoder(
        delegate,
        registrationIdByIssuer,
        registrationId -> {
          final var provider = providers.get(registrationId);
          // A registration that no provider describes, such as one a host repository adds, and
          // the default slot itself use the default converter.
          return new VerifiedJwtTag(
              provider == null || provider == defaultSlot
                  ? null
                  : OidcPrincipalClaims.resolve(provider, inherited),
              null);
        });
  }

  /**
   * For the decoder of one scope: the claims, and the UserInfo use, of the scope's own provider.
   * The claims converter and the claims provider are shared by all scopes, and would otherwise pick
   * a provider of another scope by issuer.
   *
   * <p>A token uses UserInfo only if its scope enables augmentation ({@code
   * oidc.user-info-augmentation.enabled} of the default slot, off by default) and its provider
   * enables UserInfo ({@code user-info-enabled}, on by default), as {@link
   * ScopedOidcClaimsProviderFactory} decides for the scope's own claims provider. Otherwise a
   * shared claims provider with augmentation enabled would augment the tokens of a scope that
   * disabled it.
   *
   * @param delegate the selected decoder
   * @param registrationIdByIssuer the registrationId the decoder routes the tokens of an issuer to
   * @param providers the providers of the scope, keyed by registrationId
   * @param defaultSlot the default slot ({@code oidc.*}) of the scope, whose claims a named
   *     provider inherits, and whose {@code user-info-augmentation} decides for the whole scope
   * @param registrationById the registration of a registrationId, as the decoder resolved it
   */
  static JwtDecoder withClaimsAndUserInfo(
      final JwtDecoder delegate,
      final Function<String, String> registrationIdByIssuer,
      final Map<String, OidcConfiguration> providers,
      final @Nullable OidcConfiguration defaultSlot,
      final Function<String, ClientRegistration> registrationById) {
    final var inherited = defaultSlot != null ? defaultSlot : new OidcConfiguration();
    final var augmentation = inherited.getUserInfoAugmentation();
    final var scopeAugments = augmentation != null && augmentation.isEnabled();
    return new VerifiedJwtDecoder(
        delegate,
        registrationIdByIssuer,
        registrationId -> {
          final var provider = providers.get(registrationId);
          if (provider == null) {
            return new VerifiedJwtTag(null, new UserInfoUse(false, null));
          }
          final var claims = OidcPrincipalClaims.resolve(provider, inherited);
          if (!scopeAugments || !provider.isUserInfoEnabled()) {
            return new VerifiedJwtTag(claims, new UserInfoUse(false, null));
          }
          final var registration = registrationById.apply(registrationId);
          return new VerifiedJwtTag(
              claims,
              new UserInfoUse(
                  true,
                  registration != null
                      ? registration.getProviderDetails().getUserInfoEndpoint().getUri()
                      : null));
        });
  }

  @Override
  public Jwt decode(final String token) throws JwtException {
    final var jwt = delegate.decode(token);
    final var issuer = jwt.getClaims().get(JwtClaimNames.ISS);
    final var registrationId =
        registrationIdByIssuer.apply(issuer == null ? null : issuer.toString());
    if (registrationId == null) {
      return new VerifiedJwt(jwt, null);
    }
    final var tag = tagByRegistrationId.apply(registrationId);
    final var userInfo = tag.userInfo();
    return userInfo == null
        ? new VerifiedJwt(jwt, tag.claims())
        : new VerifiedJwt(jwt, tag.claims(), userInfo.enabled(), userInfo.uri());
  }

  /** What a token carries: its claims, and its UserInfo use if the decoder decides it. */
  private record VerifiedJwtTag(
      @Nullable OidcPrincipalClaims claims, @Nullable UserInfoUse userInfo) {}

  /** Whether the verifying provider uses UserInfo, and the endpoint of its registration. */
  private record UserInfoUse(boolean enabled, @Nullable String uri) {}
}
