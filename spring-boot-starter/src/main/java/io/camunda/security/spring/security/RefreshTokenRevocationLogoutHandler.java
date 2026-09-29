/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.security;

import com.nimbusds.jose.jwk.JWK;
import io.camunda.security.spring.oidc.ScopedClientRegistrationFactory;
import io.camunda.security.spring.oidc.UrlRedaction;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.StreamingHttpOutputMessage;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.DefaultOAuth2TokenRequestHeadersConverter;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2RefreshTokenGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;

/**
 * Revokes the session's OAuth2 refresh token at the provider's RFC 7009 revocation endpoint when a
 * user logs out (ADR-0032).
 *
 * <p>Logout already invalidates the web session, which discards the {@link OAuth2AuthorizedClient}
 * holding the tokens, but that is local: without this handler the refresh token stays usable at the
 * authorization server until its own expiry. Revoking it closes that window, and per RFC 7009 §2.1
 * a provider SHOULD invalidate the access tokens issued from it as well, so one call covers both.
 *
 * <p>Must be registered with {@code
 * org.springframework.security.config.annotation.web.configurers.LogoutConfigurer#addLogoutHandler}
 * rather than as a {@code LogoutSuccessHandler}. {@code LogoutConfigurer} appends its own {@code
 * SecurityContextLogoutHandler} after every handler added that way, so this one still runs while
 * the session — and therefore the authorized client the refresh token lives in — is readable. A
 * success handler runs after that invalidation, when the token is already gone.
 *
 * <p>Every failure is fail-soft: a provider that publishes no revocation endpoint, a session with
 * no refresh token, a rejected request, and an unreachable IdP all leave logout itself unaffected.
 * Losing a local session the user asked to end must never depend on the IdP being reachable.
 * Failures that the operator can act on are logged at {@code WARN}; the token value never is, which
 * is why the form body is written through the streaming overload and exceptions are logged by type
 * — see {@link #revokeRefreshToken} and {@link #logout}.
 */
public final class RefreshTokenRevocationLogoutHandler implements LogoutHandler {

  private static final Logger LOG =
      LoggerFactory.getLogger(RefreshTokenRevocationLogoutHandler.class);

  /** Discovery metadata key holding the revocation endpoint, per RFC 8414 §2. */
  private static final String REVOCATION_ENDPOINT_METADATA_KEY = "revocation_endpoint";

  private static final String REFRESH_TOKEN_TYPE_HINT = "refresh_token";

  /**
   * The user waits on this request, so both timeouts are deliberately tighter than the defaults.
   * Fixed rather than configurable: a revocation that cannot complete in a few seconds is better
   * abandoned with a {@code WARN} than allowed to hold up the logout it accompanies.
   */
  private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(2);

  /**
   * A deadline for the whole exchange, not a per-read one. {@code SimpleClientHttpRequestFactory}'s
   * read timeout is {@code URLConnection}'s socket inactivity timeout, so an IdP trickling a byte
   * every couple of seconds could hold this request — and the servlet thread serving the logout —
   * open indefinitely. {@link JdkClientHttpRequestFactory} applies this through {@code
   * HttpRequest.Builder#timeout} and wraps the response stream, so it bounds header and body alike.
   */
  private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(3);

  /**
   * One client for every chain. A JDK {@code HttpClient} owns a selector-manager thread and a
   * connection pool, and the chain builder constructs one handler per OIDC chain, so building a
   * client per handler would cost a permanent thread per scope in a multi-tenant deployment before
   * anyone logs out. {@link RestClient} is immutable and thread-safe, so one instance serves all of
   * them.
   */
  private static final RestClient SHARED_REST_CLIENT = defaultRestClient();

  /**
   * Reused from Spring rather than reimplemented: it sets {@code Accept} and {@code Content-Type},
   * and — for a {@code client_secret_basic} client — the {@code Authorization} header with the
   * form-encoding that RFC 6749 §2.3.1 requires of client credentials. Getting that encoding subtly
   * wrong is the kind of bug that only shows up for the one customer whose client secret contains a
   * reserved character.
   */
  private static final Converter<OAuth2RefreshTokenGrantRequest, HttpHeaders> HEADERS_CONVERTER =
      new DefaultOAuth2TokenRequestHeadersConverter<>();

  private final ClientRegistrationRepository clientRegistrationRepository;
  private final OAuth2AuthorizedClientRepository authorizedClientRepository;
  private final RestClient restClient;

  /**
   * Produces {@code client_assertion} parameters for a {@code private_key_jwt} or {@code
   * client_secret_jwt} client, and {@code null} for any other client-authentication method.
   *
   * <p>That {@code null} is what selects secret-based authentication in {@link
   * #clientAuthenticationParameters}. Branching on the configured method instead would duplicate,
   * in a second place, a decision this converter already owns — and would diverge the moment Spring
   * supports another assertion-based method.
   *
   * <p>{@code null} when no JWK resolver was supplied, which leaves an assertion-authenticated
   * client unable to revoke; {@link #clientAuthenticationParameters} logs that case.
   */
  private final Converter<OAuth2RefreshTokenGrantRequest, MultiValueMap<String, String>>
      clientAssertionConverter;

  /**
   * @param jwkResolver supplies the signing key for an assertion-authenticated client, or {@code
   *     null} when the deployment has no assertion configuration to resolve one from
   */
  public RefreshTokenRevocationLogoutHandler(
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final Function<ClientRegistration, JWK> jwkResolver) {
    this(clientRegistrationRepository, authorizedClientRepository, jwkResolver, SHARED_REST_CLIENT);
  }

  // Visible for testing: lets a test drive the handler against a MockRestServiceServer-backed
  // client without reaching the network.
  RefreshTokenRevocationLogoutHandler(
      final ClientRegistrationRepository clientRegistrationRepository,
      final OAuth2AuthorizedClientRepository authorizedClientRepository,
      final Function<ClientRegistration, JWK> jwkResolver,
      final RestClient restClient) {
    this.clientRegistrationRepository =
        Objects.requireNonNull(
            clientRegistrationRepository, "clientRegistrationRepository must not be null");
    this.authorizedClientRepository =
        Objects.requireNonNull(
            authorizedClientRepository, "authorizedClientRepository must not be null");
    this.restClient = Objects.requireNonNull(restClient, "restClient must not be null");
    clientAssertionConverter = jwkResolver != null ? assertionConverter(jwkResolver) : null;
  }

  @Override
  public void logout(
      final HttpServletRequest request,
      final HttpServletResponse response,
      final Authentication authentication) {
    try {
      revokeRefreshToken(request, authentication);
    } catch (final RuntimeException e) {
      // Deliberately swallowed: see the class Javadoc on why logout must not depend on the IdP.
      // The type, not the throwable: a ResourceAccessException message carries the request URI,
      // and Spring strips its query string but not its user-info, so an endpoint configured as
      // https://user:secret@idp/... would write the secret here.
      LOG.warn(
          "Failed to revoke the refresh token on OIDC logout ({}). The local session is still"
              + " terminated, but the refresh token may remain valid at the identity provider"
              + " until it expires.",
          e.getClass().getName());
    }
  }

  private void revokeRefreshToken(
      final HttpServletRequest request, final Authentication authentication) {
    if (!(authentication instanceof final OAuth2AuthenticationToken oauth)) {
      // The type, never the object: Authentication#toString renders the principal and the
      // authorities, and CSL must not log PII at any level.
      LOG.trace(
          "Authentication is not an OAuth2AuthenticationToken but '{}'. Nothing to revoke.",
          authentication == null ? "null" : authentication.getClass().getName());
      return;
    }

    final String registrationId = oauth.getAuthorizedClientRegistrationId();
    final String safeId = ScopedClientRegistrationFactory.sanitizeForLog(registrationId);
    final ClientRegistration clientRegistration =
        clientRegistrationRepository.findByRegistrationId(registrationId);
    if (clientRegistration == null) {
      LOG.trace("No client registration found for id '{}'. Nothing to revoke.", safeId);
      return;
    }

    final String revocationEndpoint = revocationEndpoint(clientRegistration);
    if (revocationEndpoint == null) {
      // The common case for a provider that publishes none, MS Entra among them. Not a warning:
      // there is nothing the operator can do about it and it happens on every single logout.
      LOG.debug(
          "OIDC registration '{}' resolved no revocation endpoint, so the refresh token cannot be"
              + " revoked. Configure 'revocation-endpoint-uri' if the provider has one that issuer"
              + " discovery does not publish.",
          safeId);
      return;
    }

    final OAuth2AuthorizedClient authorizedClient =
        authorizedClientRepository.loadAuthorizedClient(registrationId, oauth, request);
    if (authorizedClient == null || authorizedClient.getRefreshToken() == null) {
      LOG.debug("No refresh token stored for OIDC registration '{}'. Nothing to revoke.", safeId);
      return;
    }

    // CSL's CLIENT_AUTHENTICATION_METHODS permits only client_secret_basic and private_key_jwt,
    // so it has no client-secret-derived octet key to MAC an assertion with. A registration on
    // client_secret_jwt could only arrive from a host-supplied ClientRegistrationRepository, and
    // signing its assertion with the RSA key from AssertionJwkProvider would produce one the
    // provider rejects. Saying so beats sending it.
    if (ClientAuthenticationMethod.CLIENT_SECRET_JWT.equals(
        clientRegistration.getClientAuthenticationMethod())) {
      LOG.warn(
          "OIDC registration '{}' authenticates with 'client_secret_jwt', which is not supported"
              + " for refresh-token revocation. The local session is still terminated, but the"
              + " refresh token remains valid until it expires.",
          safeId);
      return;
    }

    final var grantRequest =
        new OAuth2RefreshTokenGrantRequest(
            clientRegistration,
            authorizedClient.getAccessToken(),
            authorizedClient.getRefreshToken());

    final MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
    form.set(OAuth2ParameterNames.TOKEN, authorizedClient.getRefreshToken().getTokenValue());
    form.set(OAuth2ParameterNames.TOKEN_TYPE_HINT, REFRESH_TOKEN_TYPE_HINT);
    // Inside the try: signing a client assertion can fail on a missing or unreadable keystore,
    // and that failure has to keep the registration id rather than falling through to the net in
    // logout(), which has none.
    final HttpStatusCode status;
    try {
      form.addAll(clientAuthenticationParameters(grantRequest, safeId));
      // Encoded here and written through the streaming overload rather than handed to
      // body(Object): DefaultRestClient#logBody appends the body object to a DEBUG line before
      // invoking a message converter, and a MultiValueMap renders every entry — the refresh token,
      // the client secret, the client assertion — into the log. The streaming path never reaches
      // that call.
      final var encodedForm = formUrlEncode(form);
      status =
          restClient
              .post()
              .uri(revocationEndpoint)
              .headers(headers -> headers.addAll(HEADERS_CONVERTER.convert(grantRequest)))
              .body((StreamingHttpOutputMessage.Body) out -> out.write(encodedForm))
              .retrieve()
              // Inspect the status rather than letting RestClient raise on 4xx/5xx: the default
              // handler would put the response body — which can echo request parameters — into an
              // exception message, and the refresh token is one of those parameters.
              .onStatus(anyStatus -> true, (req, res) -> {})
              .toBodilessEntity()
              .getStatusCode();
    } catch (final RuntimeException e) {
      // Type only, same reasoning as the net in logout(), but with the identifiers that make the
      // line actionable in a multi-provider deployment.
      LOG.warn(
          "Failed to revoke the refresh token for OIDC registration '{}' at {} ({}). The local"
              + " session is still terminated, but the refresh token may remain valid until it"
              + " expires.",
          safeId,
          UrlRedaction.redact(revocationEndpoint),
          e.getClass().getName());
      return;
    }

    // RFC 7009 §2.2 answers a successful revocation with 200, so anything outside 2xx failed.
    // Testing isError() instead would treat a 3xx as success: this client does not follow a
    // redirect on POST, so nothing would have been revoked.
    if (!status.is2xxSuccessful()) {
      LOG.warn(
          "The identity provider did not confirm the refresh-token revocation for OIDC"
              + " registration '{}' (status {}). The local session is still terminated, but the"
              + " refresh token may remain valid until it expires.",
          safeId,
          status.value());
      return;
    }
    LOG.debug("Revoked the refresh token for OIDC registration '{}'.", safeId);
  }

  /**
   * The provider's revocation endpoint, or {@code null} when it resolved none. Read from the
   * provider metadata, which issuer discovery populates and {@code ScopedClientRegistrationFactory}
   * also fills from an explicitly configured {@code revocation-endpoint-uri}.
   */
  private static String revocationEndpoint(final ClientRegistration clientRegistration) {
    final Object endpoint =
        clientRegistration
            .getProviderDetails()
            .getConfigurationMetadata()
            .get(REVOCATION_ENDPOINT_METADATA_KEY);
    return endpoint instanceof final String uri && StringUtils.hasText(uri) ? uri : null;
  }

  /**
   * The client-authentication parameters for the request body, mirroring what Spring's {@code
   * DefaultOAuth2TokenRequestParametersConverter} sends to the token endpoint: no {@code client_id}
   * for {@code client_secret_basic} (it travels in the {@code Authorization} header instead), a
   * {@code client_secret} for {@code client_secret_post}, and a {@code client_assertion} pair for
   * the assertion-based methods. That converter itself is not reused because it would also add the
   * {@code grant_type} and {@code refresh_token} of a token request, which have no place in a
   * revocation request.
   */
  private MultiValueMap<String, String> clientAuthenticationParameters(
      final OAuth2RefreshTokenGrantRequest grantRequest, final String safeId) {
    final ClientRegistration clientRegistration = grantRequest.getClientRegistration();
    final ClientAuthenticationMethod method = clientRegistration.getClientAuthenticationMethod();
    final MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();

    if (clientAssertionConverter != null) {
      final var assertion = clientAssertionConverter.convert(grantRequest);
      if (assertion != null) {
        parameters.set(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
        parameters.addAll(assertion);
        return parameters;
      }
    } else if (ClientAuthenticationMethod.PRIVATE_KEY_JWT.equals(method)) {
      LOG.warn(
          "OIDC registration '{}' authenticates with '{}' but no assertion signing key is"
              + " available, so the revocation request will be sent unauthenticated and is"
              + " expected to be rejected.",
          safeId,
          method.getValue());
    }

    if (!ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(method)) {
      parameters.set(OAuth2ParameterNames.CLIENT_ID, clientRegistration.getClientId());
    }
    if (ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(method)) {
      parameters.set(OAuth2ParameterNames.CLIENT_SECRET, clientRegistration.getClientSecret());
    }
    return parameters;
  }

  /**
   * Forces RS256 to match how the token endpoint's assertion is signed in the Orchestration
   * Cluster, so a provider that pins the algorithm on its client accepts both requests or neither.
   */
  private static Converter<OAuth2RefreshTokenGrantRequest, MultiValueMap<String, String>>
      assertionConverter(final Function<ClientRegistration, JWK> jwkResolver) {
    final var converter =
        new NimbusJwtClientAuthenticationParametersConverter<OAuth2RefreshTokenGrantRequest>(
            jwkResolver);
    converter.setJwtClientAssertionCustomizer(
        context -> context.getHeaders().algorithm(SignatureAlgorithm.RS256));
    return converter;
  }

  /**
   * The {@code application/x-www-form-urlencoded} rendering of the request body.
   *
   * <p>Hand-encoded rather than delegated to {@code FormHttpMessageConverter} because reaching that
   * converter means going through {@code body(Object)}, which logs the unencoded map. {@link
   * URLEncoder} is the right encoder for this media type: it renders a space as {@code +}, as the
   * form encoding requires.
   */
  private static byte[] formUrlEncode(final MultiValueMap<String, String> form) {
    final var encoded = new StringBuilder();
    form.forEach(
        (name, values) ->
            values.forEach(
                value -> {
                  if (!encoded.isEmpty()) {
                    encoded.append('&');
                  }
                  encoded
                      .append(URLEncoder.encode(name, StandardCharsets.UTF_8))
                      .append('=')
                      .append(
                          URLEncoder.encode(value == null ? "" : value, StandardCharsets.UTF_8));
                }));
    return encoded.toString().getBytes(StandardCharsets.UTF_8);
  }

  /**
   * The JDK client is chosen over {@code SimpleClientHttpRequestFactory} for two reasons: it can
   * enforce a whole-exchange deadline (see {@link #REQUEST_TIMEOUT}), and its default redirect
   * policy is {@code NEVER}, so a 3xx from the revocation endpoint arrives as a 3xx instead of
   * being quietly followed — which is what makes the non-2xx check in {@link #revokeRefreshToken}
   * meaningful rather than theoretical.
   */
  private static RestClient defaultRestClient() {
    final var httpClient = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build();
    final var requestFactory = new JdkClientHttpRequestFactory(httpClient);
    requestFactory.setReadTimeout(REQUEST_TIMEOUT);
    return RestClient.builder().requestFactory(requestFactory).build();
  }
}
