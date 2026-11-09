/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.oidc;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.camunda.security.api.model.config.oidc.OidcConfiguration;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.slf4j.LoggerFactory;

class IssuerOwnershipTest {

  private final Logger log = (Logger) LoggerFactory.getLogger(IssuerOwnershipTest.class);
  private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

  @BeforeEach
  void attachAppender() {
    appender.start();
    log.addAppender(appender);
  }

  @AfterEach
  void detachAppender() {
    log.detachAppender(appender);
  }

  /**
   * Issuers that differ only by a trailing slash are one issuer: the provider declares one form,
   * discovery settles both registrations on it, and their tokens carry it. The first declared
   * provider owns both forms, in either order, and the other is named in a warning, as for an exact
   * duplicate.
   */
  @ParameterizedTest
  @CsvSource({"https://idp, https://idp/", "https://idp/, https://idp"})
  void shouldGiveBothFormsOfATwinIssuerToTheFirstDeclaredProvider(
      final String firstIssuer, final String secondIssuer) {
    // given
    final var providers = providers("first", firstIssuer, "second", secondIssuer);

    // when
    final var owners = IssuerOwnership.registrationIdByIssuer(providers, log, "the test settings");

    // then
    assertThat(owners)
        .containsExactlyInAnyOrderEntriesOf(Map.of(firstIssuer, "first", secondIssuer, "first"));
    assertThat(appender.list)
        .singleElement()
        .satisfies(
            event -> {
              assertThat(event.getLevel()).isEqualTo(Level.WARN);
              assertThat(event.getFormattedMessage())
                  .contains("differ only by a trailing slash")
                  .contains("'first' wins")
                  .contains("ignore the test settings of 'second'");
            });
  }

  /**
   * A step that must agree with a decoder routing a host's own registrations exactly keeps twin
   * issuers apart, so each provider keeps its own settings.
   */
  @Test
  void shouldKeepTwinIssuersApartWhenRoutingIsExact() {
    // given
    final var providers = providers("first", "https://idp", "second", "https://idp/");

    // when
    final var owners =
        IssuerOwnership.registrationIdByIssuer(providers, log, "the test settings", false);

    // then
    assertThat(owners)
        .containsExactlyInAnyOrderEntriesOf(
            Map.of("https://idp", "first", "https://idp/", "second"));
    assertThat(appender.list).isEmpty();
  }

  @Test
  void shouldKeepUnrelatedIssuersApart() {
    // given
    final var providers =
        providers("a", "https://idp.example.com/realm-a", "b", "https://idp.example.com/realm-b");

    // when
    final var owners = IssuerOwnership.registrationIdByIssuer(providers, log, "the test settings");

    // then
    assertThat(owners)
        .containsExactlyInAnyOrderEntriesOf(
            Map.of("https://idp.example.com/realm-a", "a", "https://idp.example.com/realm-b", "b"));
    assertThat(appender.list).isEmpty();
  }

  @Test
  void shouldStillGiveAnExactDuplicateToTheFirstDeclaredProvider() {
    // given
    final var providers = providers("first", "https://idp", "second", "https://idp");

    // when
    final var owners = IssuerOwnership.registrationIdByIssuer(providers, log, "the test settings");

    // then
    assertThat(owners).containsExactlyEntriesOf(Map.of("https://idp", "first"));
    assertThat(appender.list)
        .singleElement()
        .satisfies(
            event ->
                assertThat(event.getFormattedMessage())
                    .contains("'first' wins")
                    .contains("ignore the test settings of 'second'"));
  }

  private static Map<String, OidcConfiguration> providers(final String... idAndIssuer) {
    final Map<String, OidcConfiguration> providers = new LinkedHashMap<>();
    for (int i = 0; i < idAndIssuer.length; i += 2) {
      providers.put(
          idAndIssuer[i], OidcConfiguration.builder().issuerUri(idAndIssuer[i + 1]).build());
    }
    return providers;
  }
}
