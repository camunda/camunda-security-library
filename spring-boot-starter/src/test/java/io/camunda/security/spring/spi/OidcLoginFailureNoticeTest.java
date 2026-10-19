/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.spi;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;

import io.camunda.security.spring.spi.OidcLoginFailureNotice.Link;
import java.net.URI;
import java.util.Locale;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class OidcLoginFailureNoticeTest {

  @ParameterizedTest
  @ValueSource(ints = {401, 403})
  void shouldAcceptTheLoginFailureStatuses(final int status) {
    assertThat(new OidcLoginFailureNotice(status, "title", "message").status()).isEqualTo(status);
  }

  @ParameterizedTest
  @ValueSource(ints = {200, 302, 400, 404, 500})
  void shouldRejectOtherStatuses(final int status) {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcLoginFailureNotice(status, "title", "message"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "  "})
  void shouldRejectBlankText(final String blank) {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcLoginFailureNotice(401, blank, "message"));
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new OidcLoginFailureNotice(401, "title", blank));
    assertThatIllegalArgumentException()
        .isThrownBy(() -> new Link(blank, URI.create("https://console.example.com/")));
  }

  @ParameterizedTest
  @ValueSource(strings = {"https://console.example.com/org", "http://localhost:8080/", "/goodbye"})
  void shouldAcceptHttpAndHostRelativeLinks(final String target) {
    assertThatNoException().isThrownBy(() -> new Link("Go", URI.create(target)));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "javascript:alert(1)",
        "data:text/html,hi",
        "//evil.example.com/",
        "relative/path",
        "https:///no-host"
      })
  void shouldRejectLinksThatAreNotHttpOrHostRelative(final String target) {
    assertThatIllegalArgumentException().isThrownBy(() -> new Link("Go", URI.create(target)));
  }

  @Test
  void shouldExposeAnAbsentLinkAsEmpty() {
    assertThat(new OidcLoginFailureNotice(401, "title", "message").optionalLink()).isEmpty();
  }

  @Test
  void shouldDefaultToEnglish() {
    final var notice = new OidcLoginFailureNotice(401, "title", "message");

    assertThat(notice.language()).isEqualTo(Locale.ENGLISH);
    assertThat(notice.retryText()).isEqualTo(OidcLoginFailureNotice.DEFAULT_RETRY_TEXT);
  }

  @Test
  void shouldCarryTheLanguageAndRetryTextTogether() {
    final var link = new Link("Zur Console", URI.create("https://console.example.com/"));
    final var notice =
        new OidcLoginFailureNotice(403, "Kein Zugriff", "Nachricht", link)
            .withLanguage(Locale.GERMAN, "Erneut versuchen");

    assertThat(notice.language()).isEqualTo(Locale.GERMAN);
    assertThat(notice.retryText()).isEqualTo("Erneut versuchen");
    assertThat(notice.status()).isEqualTo(403);
    assertThat(notice.optionalLink()).contains(link);
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "  "})
  void shouldRejectABlankRetryText(final String blank) {
    final var notice = new OidcLoginFailureNotice(401, "title", "message");

    assertThatIllegalArgumentException()
        .isThrownBy(() -> notice.withLanguage(Locale.GERMAN, blank));
  }

  @Test
  void shouldRejectALocaleWithoutALanguage() {
    // Locale.ROOT renders as lang="und", which declares nothing a screen reader can use.
    final var notice = new OidcLoginFailureNotice(401, "title", "message");

    assertThatIllegalArgumentException()
        .isThrownBy(() -> notice.withLanguage(Locale.ROOT, "Try again"));
  }
}
