/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.api.model.config;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import org.jspecify.annotations.Nullable;

/** Configures PKCS12 keystore access for loading private keys used by security components. */
public class KeystoreConfiguration {
  private @Nullable String path;
  private @Nullable String password;
  private @Nullable String keyAlias;
  private @Nullable String keyPassword;

  public @Nullable String getPath() {
    return path;
  }

  public void setPath(final @Nullable String path) {
    this.path = path;
  }

  public @Nullable String getPassword() {
    return password;
  }

  public void setPassword(final @Nullable String password) {
    this.password = password;
  }

  public @Nullable String getKeyAlias() {
    return keyAlias;
  }

  public void setKeyAlias(final @Nullable String keyAlias) {
    this.keyAlias = keyAlias;
  }

  public @Nullable String getKeyPassword() {
    return keyPassword;
  }

  public void setKeyPassword(final @Nullable String keyPassword) {
    this.keyPassword = keyPassword;
  }

  public KeyStore loadKeystore()
      throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
    final String keystorePath = requireConfigured(path, "path");
    final String keystorePassword = requireConfigured(password, "password");
    final KeyStore keyStore = KeyStore.getInstance("PKCS12");
    try (final FileInputStream fis = new FileInputStream(keystorePath)) {
      keyStore.load(fis, keystorePassword.toCharArray());
    }
    return keyStore;
  }

  private static String requireConfigured(final @Nullable String value, final String fieldName) {
    if (value == null || value.isBlank()) {
      throw new IllegalStateException("Keystore " + fieldName + " must be configured");
    }
    return value;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {

    private @Nullable String path;
    private @Nullable String password;
    private @Nullable String keyAlias;
    private @Nullable String keyPassword;

    public Builder path(final String path) {
      this.path = path;
      return this;
    }

    public Builder password(final String password) {
      this.password = password;
      return this;
    }

    public Builder keyAlias(final String keyAlias) {
      this.keyAlias = keyAlias;
      return this;
    }

    public Builder keyPassword(final String keyPassword) {
      this.keyPassword = keyPassword;
      return this;
    }

    public KeystoreConfiguration build() {
      final KeystoreConfiguration config = new KeystoreConfiguration();
      config.setPath(path);
      config.setPassword(password);
      config.setKeyAlias(keyAlias);
      config.setKeyPassword(keyPassword);
      return config;
    }
  }
}
