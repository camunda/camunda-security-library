/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.scope;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * An OpenID provider on a loopback port for runtime-reload tests: discovery, JWKS and a token
 * endpoint that authenticates clients by {@code client_secret_basic} or {@code private_key_jwt}
 * against credentials the test can rotate, and records every token request.
 */
final class MockIdentityProvider implements AutoCloseable {

  private static final Charset UTF8 = StandardCharsets.UTF_8;

  private final HttpServer server;
  private final RSAKey signingKey;
  private final AtomicBoolean available = new AtomicBoolean(true);
  private final Map<String, Set<String>> secretsByClient = new ConcurrentHashMap<>();
  private final Map<String, Set<RSAPublicKey>> assertionKeysByClient = new ConcurrentHashMap<>();
  private final Map<String, Grant> codes = new ConcurrentHashMap<>();
  private final Map<String, Grant> refreshTokens = new ConcurrentHashMap<>();
  private final List<TokenRequest> tokenRequests = new CopyOnWriteArrayList<>();
  private final AtomicInteger accessTokenLifetimeSeconds = new AtomicInteger(300);

  private MockIdentityProvider(final HttpServer server, final RSAKey signingKey) {
    this.server = server;
    this.signingKey = signingKey;
  }

  static MockIdentityProvider start() throws Exception {
    final var generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    final var pair = generator.generateKeyPair();
    final var key =
        new RSAKey.Builder((RSAPublicKey) pair.getPublic())
            .privateKey((RSAPrivateKey) pair.getPrivate())
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.RS256)
            .keyID("idp-" + UUID.randomUUID())
            .build();
    final var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    final var idp = new MockIdentityProvider(server, key);
    server.createContext("/.well-known/openid-configuration", idp::discovery);
    server.createContext("/jwks", idp::jwks);
    server.createContext("/token", idp::token);
    server.start();
    return idp;
  }

  String issuer() {
    return "http://127.0.0.1:" + server.getAddress().getPort();
  }

  /** Accepts exactly these secrets for the client from now on. */
  void acceptSecrets(final String clientId, final String... secrets) {
    secretsByClient.put(clientId, Set.of(secrets));
  }

  /** Accepts exactly these assertion keys for the client from now on. */
  void acceptAssertionKeys(final String clientId, final RSAPublicKey... keys) {
    assertionKeysByClient.put(clientId, Set.of(keys));
  }

  /** Lets the next authorization-code exchange of {@code code} log {@code subject} in. */
  void issueCode(
      final String code, final String clientId, final String nonce, final String subject) {
    codes.put(code, new Grant(clientId, nonce, subject));
  }

  /** The {@code expires_in} of the access tokens issued from now on. */
  void setAccessTokenLifetimeSeconds(final int seconds) {
    accessTokenLifetimeSeconds.set(seconds);
  }

  void setAvailable(final boolean available) {
    this.available.set(available);
  }

  List<TokenRequest> tokenRequests() {
    return List.copyOf(tokenRequests);
  }

  /** A signed access token for the API chain's bearer validation. */
  String accessToken(final String subject, final String audience) throws Exception {
    return sign(
        new JWTClaimsSet.Builder()
            .issuer(issuer())
            .subject(subject)
            .audience(audience)
            .issueTime(new Date())
            .expirationTime(Date.from(Instant.now().plusSeconds(300)))
            .build());
  }

  @Override
  public void close() {
    server.stop(0);
  }

  private void discovery(final HttpExchange exchange) throws IOException {
    final var base = issuer();
    respond(
        exchange,
        200,
        """
        {
          "issuer": "%s",
          "authorization_endpoint": "%s/auth",
          "token_endpoint": "%s/token",
          "jwks_uri": "%s/jwks",
          "response_types_supported": ["code"],
          "subject_types_supported": ["public"],
          "id_token_signing_alg_values_supported": ["RS256"],
          "token_endpoint_auth_methods_supported": ["client_secret_basic", "private_key_jwt"]
        }
        """
            .formatted(base, base, base, base));
  }

  private void jwks(final HttpExchange exchange) throws IOException {
    respond(exchange, 200, new JWKSet(signingKey).toPublicJWKSet().toString());
  }

  private void token(final HttpExchange exchange) throws IOException {
    if (!available.get()) {
      respond(exchange, 503, "{}");
      return;
    }
    final var form = form(new String(exchange.getRequestBody().readAllBytes(), UTF8));
    final var grantType = form.get("grant_type");
    final var client = authenticate(exchange, form);
    if (client == null) {
      tokenRequests.add(new TokenRequest(grantType, null, null, false));
      respond(exchange, 401, "{\"error\":\"invalid_client\"}");
      return;
    }
    final var grant =
        "refresh_token".equals(grantType)
            ? refreshTokens.get(form.get("refresh_token"))
            : codes.remove(form.get("code"));
    if (grant == null || !grant.clientId().equals(client.clientId())) {
      tokenRequests.add(new TokenRequest(grantType, client.clientId(), client.credential(), false));
      respond(exchange, 400, "{\"error\":\"invalid_grant\"}");
      return;
    }
    tokenRequests.add(new TokenRequest(grantType, client.clientId(), client.credential(), true));
    try {
      respond(exchange, 200, tokens(grantType, grant));
    } catch (final Exception e) {
      respond(exchange, 500, "{}");
    }
  }

  private String tokens(final String grantType, final Grant grant) throws Exception {
    final var refreshToken = "rt-" + UUID.randomUUID();
    refreshTokens.put(refreshToken, grant);
    final var access = accessToken(grant.subject(), grant.clientId());
    if ("refresh_token".equals(grantType)) {
      return """
          {"access_token":"%s","token_type":"Bearer","expires_in":%d,"refresh_token":"%s"}
          """
          .formatted(access, accessTokenLifetimeSeconds.get(), refreshToken);
    }
    final var idToken =
        sign(
            new JWTClaimsSet.Builder()
                .issuer(issuer())
                .subject(grant.subject())
                .audience(grant.clientId())
                .claim("nonce", grant.nonce())
                .claim("azp", grant.clientId())
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .build());
    return """
        {"access_token":"%s","token_type":"Bearer","expires_in":%d,"refresh_token":"%s",\
        "id_token":"%s","scope":"openid"}
        """
        .formatted(access, accessTokenLifetimeSeconds.get(), refreshToken, idToken);
  }

  /** The authenticated client and the credential it used, or {@code null}. */
  private Client authenticate(final HttpExchange exchange, final Map<String, String> form) {
    final var header = exchange.getRequestHeaders().getFirst("Authorization");
    if (header != null && header.startsWith("Basic ")) {
      final var decoded =
          new String(Base64.getDecoder().decode(header.substring(6)), StandardCharsets.UTF_8);
      final var separator = decoded.indexOf(':');
      final var clientId = URLDecoder.decode(decoded.substring(0, separator), UTF8);
      final var secret = URLDecoder.decode(decoded.substring(separator + 1), UTF8);
      return secretsByClient.getOrDefault(clientId, Set.of()).contains(secret)
          ? new Client(clientId, "secret:" + secret)
          : null;
    }
    final var assertion = form.get("client_assertion");
    if (assertion != null) {
      try {
        final var jwt = SignedJWT.parse(assertion);
        final var clientId = jwt.getJWTClaimsSet().getSubject();
        for (final var key : assertionKeysByClient.getOrDefault(clientId, Set.of())) {
          if (jwt.verify(new RSASSAVerifier(key))) {
            return new Client(clientId, "assertion:" + jwt.getHeader().getKeyID());
          }
        }
      } catch (final Exception e) {
        return null;
      }
    }
    return null;
  }

  private String sign(final JWTClaimsSet claims) throws Exception {
    final var jwt =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build(), claims);
    jwt.sign(new RSASSASigner(signingKey));
    return jwt.serialize();
  }

  private static Map<String, String> form(final String body) {
    final Map<String, String> values = new HashMap<>();
    for (final var pair : body.split("&")) {
      final var separator = pair.indexOf('=');
      if (separator > 0) {
        values.put(
            URLDecoder.decode(pair.substring(0, separator), UTF8),
            URLDecoder.decode(pair.substring(separator + 1), UTF8));
      }
    }
    return values;
  }

  private void respond(final HttpExchange exchange, final int status, final String json)
      throws IOException {
    try (exchange) {
      if (!available.get() && status != 503) {
        exchange.sendResponseHeaders(503, -1);
        return;
      }
      final var bytes = json.getBytes(StandardCharsets.UTF_8);
      exchange.getResponseHeaders().add("Content-Type", "application/json");
      exchange.sendResponseHeaders(status, bytes.length);
      exchange.getResponseBody().write(bytes);
    }
  }

  /** One request to the token endpoint. */
  record TokenRequest(String grantType, String clientId, String credential, boolean granted) {}

  private record Grant(String clientId, String nonce, String subject) {}

  private record Client(String clientId, String credential) {}
}
