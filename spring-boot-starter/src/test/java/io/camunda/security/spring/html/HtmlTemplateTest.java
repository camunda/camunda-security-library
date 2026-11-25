/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.html;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class HtmlTemplateTest {

  private final Logger log = (Logger) LoggerFactory.getLogger(HtmlTemplateTest.class);
  private ListAppender<ILoggingEvent> logs;

  @BeforeEach
  void attachAppender() {
    logs = new ListAppender<>();
    logs.start();
    log.addAppender(logs);
  }

  @AfterEach
  void detachAppender() {
    log.detachAppender(logs);
  }

  @Test
  void shouldEscapeTextValues() {
    assertThat(
            HtmlTemplate.render(
                "<a href=\"{{href}}\">{{name}}</a>",
                Map.of("href", "/x?a=1&b=\"2\"", "name", "<script>alert(1)</script>")))
        .isEqualTo(
            "<a href=\"/x?a=1&amp;b=&quot;2&quot;\">&lt;script&gt;alert(1)&lt;/script&gt;</a>");
  }

  @Test
  void shouldInsertHtmlValuesAsTheyAre() {
    assertThat(
            HtmlTemplate.render(
                "<p>{{title}}</p>{{links}}",
                Map.of("title", "A & B"),
                Map.of("links", "<a href=\"/x\">x</a>")))
        .isEqualTo("<p>A &amp; B</p><a href=\"/x\">x</a>");
  }

  @Test
  void shouldNotSubstituteAPlaceholderInsideAValue() {
    assertThat(
            HtmlTemplate.render(
                "{{first}} {{second}}",
                Map.of("first", "{{second}}"),
                Map.of("second", "{{first}}")))
        .isEqualTo("{{second}} {{first}}");
  }

  @Test
  void shouldRejectAPlaceholderWithoutAValue() {
    assertThatIllegalArgumentException()
        .isThrownBy(() -> HtmlTemplate.render("{{title}} {{year}}", Map.of("title", "t")))
        .withMessageContaining("{{year}}");
  }

  @Test
  void shouldRejectANameThatIsBothTextAndHtml() {
    assertThatIllegalArgumentException()
        .isThrownBy(
            () ->
                HtmlTemplate.render("{{title}}", Map.of("title", "t"), Map.of("title", "<b>t</b>")))
        .withMessageContaining("title");
  }

  @Test
  void shouldLoadATemplateFromTheAnchorsPackage() {
    assertThat(
            HtmlTemplate.load(
                io.camunda.security.spring.security.CamundaLoginPickerFilter.class,
                "login-picker-page.html",
                log,
                "unused"))
        .hasValueSatisfying(template -> assertThat(template).contains("{{providers}}"));
    assertThat(logs.list).isEmpty();
  }

  @Test
  void shouldLogAMissingTemplateWithTheFallbackInsteadOfThrowing() {
    assertThat(
            HtmlTemplate.load(
                HtmlTemplateTest.class, "no-such-template.html", log, "the page is not shown."))
        .isEmpty();
    assertThat(logs.list)
        .singleElement()
        .satisfies(
            event -> {
              assertThat(event.getLevel()).isEqualTo(Level.ERROR);
              assertThat(event.getFormattedMessage())
                  .isEqualTo("Missing resource no-such-template.html; the page is not shown.");
            });
  }
}
