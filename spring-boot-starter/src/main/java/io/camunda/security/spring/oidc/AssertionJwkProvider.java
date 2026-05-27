/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;
import io.camunda.security.api.model.config.AssertionConfiguration;
import io.camunda.security.api.model.config.AssertionConfiguration.KidCase;
import io.camunda.security.api.model.config.AssertionConfiguration.KidDigestAlgorithm;
import io.camunda.security.api.model.config.AssertionConfiguration.KidSource;
import io.camunda.security.core.port.in.OidcProviderConfigurationPort;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.HexFormat;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

public final class AssertionJwkProvider {

  private static final Logger LOG = LoggerFactory.getLogger(AssertionJwkProvider.class);
  private final OidcProviderConfigurationPort oidcProviderConfigurationPort;

  public AssertionJwkProvider(final OidcProviderConfigurationPort oidcProviderConfigurationPort) {
    this.oidcProviderConfigurationPort = oidcProviderConfigurationPort;
  }

  public JWK createJwk(final String clientRegistrationId) {
    final var oidcConfig =
        oidcProviderConfigurationPort.getOidcAuthenticationConfigurationById(clientRegistrationId);
    if (oidcConfig == null) {
      throw new IllegalArgumentException(
          "No OIDC configuration found for registrationId '" + clientRegistrationId + "'");
    }

    final var assertionConfig = oidcConfig.getAssertion();
    if (assertionConfig == null) {
      throw new IllegalStateException(
          "Assertion configuration is missing for registrationId '" + clientRegistrationId + "'");
    }
    final var keystoreConfig = assertionConfig.getKeystore();
    if (keystoreConfig == null) {
      throw new IllegalStateException(
          "Keystore configuration is missing for registrationId '" + clientRegistrationId + "'");
    }
    final var alias = keystoreConfig.getKeyAlias();
    if (!StringUtils.hasText(alias)) {
      throw new IllegalStateException("Keystore keyAlias must be configured");
    }
    final var keyPassword = keystoreConfig.getKeyPassword();
    if (!StringUtils.hasText(keyPassword)) {
      throw new IllegalStateException("Keystore keyPassword must be configured");
    }

    try {
      final KeyStore keyStore = keystoreConfig.loadKeystore();
      final var key = keyStore.getKey(alias, keyPassword.toCharArray());
      if (key == null) {
        throw new IllegalStateException("Keystore key for alias '" + alias + "' not found");
      }
      if (!(key instanceof PrivateKey pk)) {
        throw new IllegalStateException("Keystore entry '" + alias + "' is not a private key");
      }
      final var cert = keyStore.getCertificate(alias);
      if (cert == null) {
        throw new IllegalStateException("Keystore certificate for alias '" + alias + "' not found");
      }
      if (!(cert.getPublicKey() instanceof RSAPublicKey pub)) {
        throw new IllegalStateException(
            "Keystore certificate public key for alias '" + alias + "' is not an RSA key");
      }
      if (!(cert instanceof X509Certificate x509)) {
        throw new IllegalStateException(
            "Keystore certificate for alias '" + alias + "' is not an X.509 certificate");
      }
      final var thumbprint = X509CertUtils.computeSHA256Thumbprint(x509);
      if (thumbprint == null) {
        throw new IllegalStateException(
            "Unable to compute SHA-256 thumbprint for certificate alias '" + alias + "'");
      }
      return new RSAKey.Builder(pub)
          .privateKey(pk)
          .x509CertChain(List.of(Base64.encode(cert.getEncoded())))
          .keyID(generateKid(cert, assertionConfig))
          .x509CertSHA256Thumbprint(thumbprint)
          .build();
    } catch (final GeneralSecurityException | IOException e) {
      throw new IllegalStateException(
          "Unable to create assertion JWK for registrationId '" + clientRegistrationId + "'", e);
    }
  }

  /**
   * Generates the {@code key ID} expected by some IdPs to match a registered certificate for the
   * client.
   *
   * <p>The {@code kid} generation can be modified using the {@link AssertionConfiguration} to
   * control if the certificate or its public key is used, which hashing algorithm will be used,
   * what encoding the {@code kid} string will have, and whether it is lowercase or uppercase (hex
   * only).
   *
   * @implNote the default {@code kid} generated when no configuration is set is a SHA-256 digest of
   *     the public key with Base64URL encoding
   */
  private String generateKid(final Certificate cert, final AssertionConfiguration config) {
    final var digestAlg = getKidDigestAlgorithmInstance(config.getKidDigestAlgorithm());
    final var sourceBytes = getKidSourceBytes(cert, config.getKidSource());
    final var digest = digestAlg.digest(sourceBytes);
    final var kid =
        switch (config.getKidEncoding()) {
          case BASE64URL -> Base64URL.encode(digest).toString();
          case HEX -> getHexFormatWithCase(config.getKidCase()).formatHex(digest);
        };
    LOG.debug("generated kid '{}' from keystore '{}'", kid, config.getKeystore().getPath());
    return kid;
  }

  private MessageDigest getKidDigestAlgorithmInstance(final KidDigestAlgorithm alg) {
    try {
      return switch (alg) {
        case SHA256 -> MessageDigest.getInstance("SHA-256");
        case SHA1 -> MessageDigest.getInstance("SHA-1");
      };
    } catch (final NoSuchAlgorithmException e) {
      throw new IllegalStateException("failed to instantiate digest algorithm", e);
    }
  }

  private byte[] getKidSourceBytes(final Certificate cert, final KidSource source) {
    try {
      return switch (source) {
        case PUBLIC_KEY -> cert.getPublicKey().getEncoded();
        case CERTIFICATE -> cert.getEncoded();
      };
    } catch (final CertificateEncodingException e) {
      throw new IllegalStateException("failed to fetch encoded kid source", e);
    }
  }

  private HexFormat getHexFormatWithCase(final KidCase kidCase) {
    return switch (kidCase) {
      case UPPER -> HexFormat.of().withUpperCase();
      case LOWER -> HexFormat.of().withLowerCase();
      case null -> HexFormat.of();
    };
  }
}
