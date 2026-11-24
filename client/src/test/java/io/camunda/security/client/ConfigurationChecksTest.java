/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

class ConfigurationChecksTest {

  @ParameterizedTest
  @NullSource
  @ValueSource(strings = {"", " ", "\t"})
  void requireTextRejectsMissingOrBlankValuesNamingTheField(final String value) {
    assertThatThrownBy(() -> ConfigurationChecks.requireText(value, "clientId"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("clientId must not be blank");
  }

  @Test
  void requireTextAcceptsText() {
    assertThatCode(() -> ConfigurationChecks.requireText("id", "clientId"))
        .doesNotThrowAnyException();
  }

  @ParameterizedTest
  @NullSource
  @ValueSource(strings = {"", " ", "\t", "\u2003"})
  void isBlankIsTrueForNullEmptyAndWhitespace(final String value) {
    assertThat(ConfigurationChecks.isBlank(value)).isTrue();
  }

  @Test
  void isBlankIsFalseForText() {
    assertThat(ConfigurationChecks.isBlank("a")).isFalse();
    assertThat(ConfigurationChecks.isBlank(" a ")).isFalse();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "https://idp.example/token",
        "HTTPS://idp.example:8443/token",
        "http://localhost:1/token",
        "http://LOCALHOST/token",
        "http://127.0.0.1:1/token",
        "http://[::1]:1/token"
      })
  void requireTokenUriAcceptsHttpsAndLoopbackHttp(final String uri) {
    assertThatCode(() -> ConfigurationChecks.requireTokenUri(URI.create(uri), "tokenUri"))
        .doesNotThrowAnyException();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "http://idp.example/token",
        "HTTP://idp.example/token",
        "http://127.0.0.2/token",
        "Http://127.0.0.2/token",
        "http://localhost.evil/t",
        "http://[::2]/t",
        "http://0.0.0.0/t"
      })
  void requireTokenUriRejectsHttpForOtherHosts(final String uri) {
    assertThatThrownBy(() -> ConfigurationChecks.requireTokenUri(URI.create(uri), "tokenUri"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage(
            "tokenUri must use https. Http is allowed only for localhost, 127.0.0.1 and [::1]");
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"urn:x", "file:/x", "ftp://idp.example/token", "/token", "//idp.example/token"})
  void requireTokenUriRejectsUrisThatAreNotHttp(final String uri) {
    assertThatThrownBy(() -> ConfigurationChecks.requireTokenUri(URI.create(uri), "tokenUri"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("tokenUri must be an absolute http or https URI");
  }

  @ParameterizedTest
  @ValueSource(strings = {"https:///x", "https://my_host/token"})
  void requireTokenUriRejectsAUriWithoutAReadableHost(final String uri) {
    assertThatThrownBy(() -> ConfigurationChecks.requireTokenUri(URI.create(uri), "tokenUri"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("tokenUri has no host that java.net.URI can read");
  }

  @Test
  void requireTokenUriRejectsNullAndUserInfo() {
    assertThatThrownBy(() -> ConfigurationChecks.requireTokenUri(null, "tokenUri"))
        .hasMessage("tokenUri must be an absolute http or https URI");
    assertThatThrownBy(
            () ->
                ConfigurationChecks.requireTokenUri(
                    URI.create("https://u:p@idp.example/token"), "tokenUri"))
        .hasMessage("tokenUri must not contain user-info");
  }

  @Test
  void nullIfBlankKeepsOnlyText() {
    assertThat(ConfigurationChecks.nullIfBlank(null)).isNull();
    assertThat(ConfigurationChecks.nullIfBlank(" ")).isNull();
    assertThat(ConfigurationChecks.nullIfBlank("a")).isEqualTo("a");
  }

  @Test
  void requireNoColonRejectsAColon() {
    assertThatThrownBy(() -> ConfigurationChecks.requireNoColon("a:b", "username"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("username must not contain ':'");
    assertThatCode(() -> ConfigurationChecks.requireNoColon("ab", "username"))
        .doesNotThrowAnyException();
  }

  @Test
  void copyNonBlankCopiesAndRejectsBlankValues() {
    final List<String> values = new ArrayList<>(Arrays.asList("a"));
    final List<String> copy = ConfigurationChecks.copyNonBlank(values, "scopes");
    values.add("b");

    assertThat(copy).containsExactly("a");
    assertThatThrownBy(() -> copy.add("x")).isInstanceOf(UnsupportedOperationException.class);
    assertThat(ConfigurationChecks.copyNonBlank(null, "scopes")).isEmpty();
    assertThatThrownBy(() -> ConfigurationChecks.copyNonBlank(Arrays.asList("a", " "), "scopes"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("scopes must not contain blank values");
  }

  @Test
  void positiveOrDefaultChecksTheRange() {
    final Duration fallback = Duration.ofSeconds(7);

    assertThat(ConfigurationChecks.positiveOrDefault(null, fallback, "t")).isEqualTo(fallback);
    assertThat(
            ConfigurationChecks.positiveOrDefault(ConfigurationChecks.MAX_TIMEOUT, fallback, "t"))
        .isEqualTo(ConfigurationChecks.MAX_TIMEOUT);
    assertThatThrownBy(() -> ConfigurationChecks.positiveOrDefault(Duration.ZERO, fallback, "t"))
        .hasMessage("t must be positive");
    assertThatThrownBy(
            () -> ConfigurationChecks.positiveOrDefault(Duration.ofSeconds(-5), fallback, "t"))
        .hasMessage("t must be positive");
    assertThatThrownBy(
            () ->
                ConfigurationChecks.positiveOrDefault(
                    ConfigurationChecks.MAX_TIMEOUT.plusMillis(1), fallback, "t"))
        .hasMessage("t must not be longer than " + Integer.MAX_VALUE + " milliseconds");
  }
}
