/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;
import java.util.List;

/**
 * Reusable test-support fixture: an ephemeral JDK {@link HttpServer} on a loopback port serving
 * JWKS and/or an OIDC discovery document. Backed by a freshly generated RSA or EC key pair;
 * supports JWT signing for integration tests.
 *
 * <p>Factory methods:
 *
 * <ul>
 *   <li>{@link #startRsa(String)} — RSA 2048 key, {@code /jwks} + {@code
 *       /.well-known/openid-configuration}
 *   <li>{@link #startEc(String)} — EC P-256 key, {@code /jwks} + {@code
 *       /.well-known/openid-configuration}
 *   <li>{@link #startDiscovery(String)} — discovery document only, no key material; the {@code %s}
 *       placeholder in the template is replaced with the actual issuer URI
 * </ul>
 *
 * <p>Implements {@link AutoCloseable} for try-with-resources or {@code @AfterEach} use.
 */
public final class OidcTestServer implements AutoCloseable {

  private final HttpServer server;
  private final String kid;
  private final JWSAlgorithm algorithm;
  private final JWSSigner signer;

  private OidcTestServer(
      final HttpServer server,
      final String kid,
      final JWSAlgorithm algorithm,
      final JWSSigner signer) {
    this.server = server;
    this.kid = kid;
    this.algorithm = algorithm;
    this.signer = signer;
  }

  /**
   * Starts an RSA-backed server. Serves {@code /jwks} (public RSA JWK set) and {@code
   * /.well-known/openid-configuration} (standard discovery document).
   */
  public static OidcTestServer startRsa(final String kid) throws Exception {
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
    final var jwkJson = new JWKSet(jwk).toPublicJWKSet().toString();
    final var httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    final var base = "http://127.0.0.1:" + httpServer.getAddress().getPort();
    registerJsonContext(httpServer, "/jwks", jwkJson);
    registerJsonContext(
        httpServer, "/.well-known/openid-configuration", buildDiscovery(base, JWSAlgorithm.RS256));
    httpServer.start();
    return new OidcTestServer(httpServer, kid, JWSAlgorithm.RS256, new RSASSASigner(jwk));
  }

  /**
   * Starts an EC-backed server (P-256 / ES256). Serves {@code /jwks} (public EC JWK set) and {@code
   * /.well-known/openid-configuration} (standard discovery document).
   */
  public static OidcTestServer startEc(final String kid) throws Exception {
    final var generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    final var pair = generator.generateKeyPair();
    final var jwk =
        new ECKey.Builder(Curve.P_256, (ECPublicKey) pair.getPublic())
            .keyID(kid)
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.ES256)
            .build();
    final var jwkJson = new JWKSet(jwk).toPublicJWKSet().toString();
    final var httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    final var base = "http://127.0.0.1:" + httpServer.getAddress().getPort();
    registerJsonContext(httpServer, "/jwks", jwkJson);
    registerJsonContext(
        httpServer, "/.well-known/openid-configuration", buildDiscovery(base, JWSAlgorithm.ES256));
    httpServer.start();
    return new OidcTestServer(
        httpServer, kid, JWSAlgorithm.ES256, new ECDSASigner((ECPrivateKey) pair.getPrivate()));
  }

  /**
   * Starts a discovery-only server (no JWKS, no key material). The {@code responseTemplate} is
   * formatted with the server's actual issuer URI substituted for the single {@code %s}
   * placeholder.
   */
  public static OidcTestServer startDiscovery(final String responseTemplate) throws IOException {
    final var httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    final var issuer = "http://127.0.0.1:" + httpServer.getAddress().getPort();
    registerJsonContext(
        httpServer, "/.well-known/openid-configuration", responseTemplate.formatted(issuer));
    httpServer.start();
    return new OidcTestServer(httpServer, null, null, null);
  }

  /** Returns the key ID ({@code kid}) used in JWT headers. */
  public String kid() {
    requireKeyMaterial();
    return kid;
  }

  /** Returns the base URL of this server, e.g. {@code http://127.0.0.1:54321}. */
  public String issuerUri() {
    return "http://127.0.0.1:" + server.getAddress().getPort();
  }

  /** Returns the URL of the {@code /jwks} endpoint. */
  public String jwksUri() {
    requireKeyMaterial();
    return issuerUri() + "/jwks";
  }

  /**
   * Builds an {@link OidcConfiguration} backed by this server. Supplies explicit {@code issuerUri},
   * {@code authorizationUri}, {@code tokenUri}, and {@code jwkSetUri} so that no external IdP or
   * OIDC discovery call is required.
   */
  public OidcConfiguration oidcConfiguration(final String clientId) {
    requireKeyMaterial();
    final var base = issuerUri();
    return OidcConfiguration.builder()
        .clientId(clientId)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .issuerUri(base)
        .authorizationUri(base + "/auth")
        .tokenUri(base + "/token")
        .jwkSetUri(base + "/jwks")
        .build();
  }

  /**
   * Signs a JWT with subject {@code alice}, the given {@code issuer}, and a 60-second expiry, using
   * this server's algorithm and key.
   */
  public String sign(final String issuer) throws Exception {
    return signWithAudience(issuer, List.of());
  }

  /**
   * Signs a JWT with subject {@code alice}, the given {@code issuer}, and a 60-second expiry, with
   * the given {@code typ} set in the JOSE header. Useful for testing JOSE type verification logic.
   */
  public String signWithTyp(final String issuer, final String typ) throws Exception {
    requireKeyMaterial();
    if (typ == null || typ.isBlank()) {
      throw new IllegalArgumentException("typ must be non-blank");
    }
    final var header =
        new JWSHeader.Builder(algorithm).keyID(kid).type(new JOSEObjectType(typ)).build();
    final var claims =
        new JWTClaimsSet.Builder()
            .subject("alice")
            .issuer(issuer)
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(60)))
            .build();
    final var jwt = new SignedJWT(header, claims);
    jwt.sign(signer);
    return jwt.serialize();
  }

  /**
   * Signs a JWT with subject {@code alice} and a 60-second expiry but no issuer claim. Useful when
   * the decoder under test does not validate the issuer.
   */
  public String sign() throws Exception {
    requireKeyMaterial();
    final var header = new JWSHeader.Builder(algorithm).keyID(kid).build();
    final var claims =
        new JWTClaimsSet.Builder()
            .subject("alice")
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(60)))
            .build();
    final var jwt = new SignedJWT(header, claims);
    jwt.sign(signer);
    return jwt.serialize();
  }

  /**
   * Signs a JWT with subject {@code alice}, the given {@code issuer}, the given {@code audiences}
   * (omitted when empty), and a 60-second expiry.
   */
  public String signWithAudience(final String issuer, final List<String> audiences)
      throws Exception {
    requireKeyMaterial();
    final var header = new JWSHeader.Builder(algorithm).keyID(kid).build();
    final var builder =
        new JWTClaimsSet.Builder()
            .subject("alice")
            .issuer(issuer)
            .issueTime(Date.from(Instant.now()))
            .expirationTime(Date.from(Instant.now().plusSeconds(60)));
    if (!audiences.isEmpty()) {
      builder.audience(audiences);
    }
    final var jwt = new SignedJWT(header, builder.build());
    jwt.sign(signer);
    return jwt.serialize();
  }

  /**
   * Signs a JWT with a single audience string. A {@code null} audience is treated as absent (no
   * {@code aud} claim).
   */
  public String signWithAudience(final String issuer, final String audience) throws Exception {
    return signWithAudience(issuer, audience != null ? List.of(audience) : List.of());
  }

  /** Stops the underlying HTTP server. */
  public void stop() {
    server.stop(0);
  }

  @Override
  public void close() {
    stop();
  }

  private void requireKeyMaterial() {
    if (signer == null) {
      throw new IllegalStateException("No key material — server was started with startDiscovery()");
    }
  }

  private static String buildDiscovery(final String base, final JWSAlgorithm algorithm) {
    return """
        {
          "issuer": "%s",
          "authorization_endpoint": "%s/auth",
          "token_endpoint": "%s/token",
          "jwks_uri": "%s/jwks",
          "response_types_supported": ["code"],
          "subject_types_supported": ["public"],
          "id_token_signing_alg_values_supported": ["%s"]
        }
        """
        .formatted(base, base, base, base, algorithm.getName());
  }

  private static void registerJsonContext(
      final HttpServer httpServer, final String path, final String responseJson) {
    httpServer.createContext(
        path,
        exchange -> {
          try (exchange) {
            final byte[] bytes = responseJson.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
          } catch (final IOException ex) {
            throw new IllegalStateException("Failed to serve " + path, ex);
          }
        });
  }
}
