/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import io.camunda.security.spring.CamundaSecurityConfiguration;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.ContextConsumer;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * End-to-end decode test for the issuer-aware {@code JwtDecoder} path in {@link
 * OidcBeansConfiguration}. Two local HTTP servers simulate Keycloak and Azure AD. Tests verify
 * correct routing by issuer, rejection of unknown issuers, cross-issuer token blocking, and
 * per-issuer audience enforcement.
 */
final class OidcBeansConfigurationMultiIssuerDecodeTest {

  private static final String KEYCLOAK_ISSUER = "https://keycloak.example.com/realms/camunda";
  private static final String AZURE_ISSUER = "https://login.microsoftonline.com/tenant/v2.0";

  private JwksTestServer keycloak;
  private JwksTestServer azure;

  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withPropertyValues("camunda.security.authentication.method=oidc")
          .withUserConfiguration(StubOidcInfrastructure.class)
          .withConfiguration(
              AutoConfigurations.of(
                  CamundaSecurityConfiguration.class, OidcBeansConfiguration.class));

  @BeforeEach
  void startServers() throws Exception {
    keycloak = JwksTestServer.start("keycloak-rsa");
    azure = JwksTestServer.start("azure-rsa");
  }

  @AfterEach
  void stopServers() {
    keycloak.stop();
    azure.stop();
  }

  @Test
  void shouldDecodeTokenIssuedByKeycloak() throws Exception {
    runWithTwoProviders(
        ctx -> {
          final var decoder = ctx.getBean(JwtDecoder.class);
          final var token = sign(keycloak, KEYCLOAK_ISSUER);

          final var jwt = decoder.decode(token);

          assertThat(jwt.getIssuer().toString()).isEqualTo(KEYCLOAK_ISSUER);
          assertThat(jwt.getSubject()).isEqualTo("alice");
        });
  }

  @Test
  void shouldDecodeTokenIssuedByAzure() throws Exception {
    runWithTwoProviders(
        ctx -> {
          final var decoder = ctx.getBean(JwtDecoder.class);
          final var token = sign(azure, AZURE_ISSUER);

          final var jwt = decoder.decode(token);

          assertThat(jwt.getIssuer().toString()).isEqualTo(AZURE_ISSUER);
          assertThat(jwt.getSubject()).isEqualTo("alice");
        });
  }

  @Test
  void shouldRejectTokenWithUnknownIssuer() throws Exception {
    runWithTwoProviders(
        ctx -> {
          final var decoder = ctx.getBean(JwtDecoder.class);
          final var token = sign(keycloak, "https://unregistered-idp.example.com");

          assertThatThrownBy(() -> decoder.decode(token))
              .isInstanceOf(BadJwtException.class)
              .hasMessageContaining("unregistered-idp");
        });
  }

  @Test
  void shouldRejectCrossIssuerToken() throws Exception {
    runWithTwoProviders(
        ctx -> {
          final var decoder = ctx.getBean(JwtDecoder.class);
          // Signed by azure's key but claiming to be from Keycloak: key lookup goes to Keycloak's
          // JWK set which does not contain azure's key → signature verification fails.
          final var tokenSignedByAzureClaimingKeycloak = sign(azure, KEYCLOAK_ISSUER);

          assertThatThrownBy(() -> decoder.decode(tokenSignedByAzureClaimingKeycloak))
              .isInstanceOf(BadJwtException.class);
        });
  }

  @Test
  void shouldEnforceAudiencePerIssuer() throws Exception {
    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.keycloak.client-id=kc-client",
            "camunda.security.authentication.providers.oidc.keycloak.issuer-uri=" + KEYCLOAK_ISSUER,
            "camunda.security.authentication.providers.oidc.keycloak.authorization-uri=https://kc.example.com/auth",
            "camunda.security.authentication.providers.oidc.keycloak.token-uri=https://kc.example.com/token",
            "camunda.security.authentication.providers.oidc.keycloak.jwk-set-uri="
                + keycloak.jwksUri(),
            "camunda.security.authentication.providers.oidc.keycloak.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.providers.oidc.keycloak.audiences=keycloak-audience",
            "camunda.security.authentication.providers.oidc.azure.client-id=az-client",
            "camunda.security.authentication.providers.oidc.azure.issuer-uri=" + AZURE_ISSUER,
            "camunda.security.authentication.providers.oidc.azure.authorization-uri=https://az.example.com/auth",
            "camunda.security.authentication.providers.oidc.azure.token-uri=https://az.example.com/token",
            "camunda.security.authentication.providers.oidc.azure.jwk-set-uri=" + azure.jwksUri(),
            "camunda.security.authentication.providers.oidc.azure.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}")
        .withBean(
            ClientRegistrationRepository.class,
            () ->
                new InMemoryClientRegistrationRepository(
                    List.of(
                        registration("keycloak", keycloak.jwksUri(), KEYCLOAK_ISSUER),
                        registration("azure", azure.jwksUri(), AZURE_ISSUER))))
        .run(
            ctx -> {
              final var decoder = ctx.getBean(JwtDecoder.class);
              final var kcTokenWrongAud =
                  signWithAudience(keycloak, KEYCLOAK_ISSUER, "wrong-audience");
              assertThatThrownBy(() -> decoder.decode(kcTokenWrongAud))
                  .isInstanceOf(BadJwtException.class);
              // Azure has no audiences configured → all tokens from Azure pass audience validation
              final var azToken = sign(azure, AZURE_ISSUER);
              assertThat(decoder.decode(azToken).getIssuer().toString()).isEqualTo(AZURE_ISSUER);
            });
  }

  private void runWithTwoProviders(final ContextConsumer<ApplicationContext> consumer)
      throws Exception {
    runner
        .withPropertyValues(
            "camunda.security.authentication.providers.oidc.keycloak.client-id=kc-client",
            "camunda.security.authentication.providers.oidc.keycloak.issuer-uri=" + KEYCLOAK_ISSUER,
            "camunda.security.authentication.providers.oidc.keycloak.authorization-uri=https://kc.example.com/auth",
            "camunda.security.authentication.providers.oidc.keycloak.token-uri=https://kc.example.com/token",
            "camunda.security.authentication.providers.oidc.keycloak.jwk-set-uri="
                + keycloak.jwksUri(),
            "camunda.security.authentication.providers.oidc.keycloak.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
            "camunda.security.authentication.providers.oidc.azure.client-id=az-client",
            "camunda.security.authentication.providers.oidc.azure.issuer-uri=" + AZURE_ISSUER,
            "camunda.security.authentication.providers.oidc.azure.authorization-uri=https://az.example.com/auth",
            "camunda.security.authentication.providers.oidc.azure.token-uri=https://az.example.com/token",
            "camunda.security.authentication.providers.oidc.azure.jwk-set-uri=" + azure.jwksUri(),
            "camunda.security.authentication.providers.oidc.azure.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}")
        .withBean(
            ClientRegistrationRepository.class,
            () ->
                new InMemoryClientRegistrationRepository(
                    List.of(
                        registration("keycloak", keycloak.jwksUri(), KEYCLOAK_ISSUER),
                        registration("azure", azure.jwksUri(), AZURE_ISSUER))))
        .run(consumer);
  }

  private static ClientRegistration registration(
      final String id, final String jwksUri, final String issuerUri) {
    return ClientRegistration.withRegistrationId(id)
        .clientId("test-client")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .authorizationUri("https://example.com/auth")
        .tokenUri("https://example.com/token")
        .jwkSetUri(jwksUri)
        .issuerUri(issuerUri)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .build();
  }

  private static String sign(final JwksTestServer server, final String issuer) throws Exception {
    return signWithAudience(server, issuer, null);
  }

  private static String signWithAudience(
      final JwksTestServer server, final String issuer, final String audience) throws Exception {
    final var header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(server.kid()).build();
    final var claims =
        new JWTClaimsSet.Builder()
            .subject("alice")
            .issuer(issuer)
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(60)));
    if (audience != null) {
      claims.audience(audience);
    }
    final var jwt = new SignedJWT(header, claims.build());
    jwt.sign(server.signer());
    return jwt.serialize();
  }

  /**
   * Minimal JWKS HTTP server backed by a freshly generated RSA key pair. Serves the public key as
   * JSON at {@code /jwks} on a loopback ephemeral port.
   */
  private static final class JwksTestServer {
    private final HttpServer server;
    private final String kid;
    private final JWSSigner signer;

    private JwksTestServer(final HttpServer server, final String kid, final JWSSigner signer) {
      this.server = server;
      this.kid = kid;
      this.signer = signer;
    }

    static JwksTestServer start(final String kid) throws Exception {
      final var generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      final var pair = generator.generateKeyPair();
      final var jwk =
          new RSAKey.Builder((RSAPublicKey) pair.getPublic())
              .privateKey((RSAPrivateKey) pair.getPrivate())
              .keyUse(KeyUse.SIGNATURE)
              .algorithm(JWSAlgorithm.RS256)
              .keyID(kid)
              .build();
      final var jwkSet = new JWKSet(jwk).toPublicJWKSet().toString();
      final var httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
      httpServer.createContext(
          "/jwks",
          exchange -> {
            final var body = jwkSet.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (exchange) {
              exchange.getResponseBody().write(body);
            }
          });
      httpServer.start();
      return new JwksTestServer(httpServer, kid, new RSASSASigner(jwk));
    }

    String kid() {
      return kid;
    }

    JWSSigner signer() {
      return signer;
    }

    String jwksUri() {
      return "http://127.0.0.1:" + server.getAddress().getPort() + "/jwks";
    }

    void stop() {
      server.stop(0);
    }
  }

  /**
   * Stubs the OIDC infrastructure beans other than {@link JwtDecoder} and {@link
   * ClientRegistrationRepository} so the bean under test is the one exercised. Each test provides
   * its own {@link InMemoryClientRegistrationRepository} via {@code runner.withBean(...)}.
   */
  @Configuration
  static class StubOidcInfrastructure {

    @Bean
    OAuth2AuthorizedClientRepository authorizedClientRepository() {
      return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager() {
      return request -> null;
    }
  }
}
