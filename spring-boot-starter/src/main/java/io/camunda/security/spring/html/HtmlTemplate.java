/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.spring.html;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.springframework.web.util.HtmlUtils;

/**
 * Loads and fills the classpath HTML templates that CSL renders itself, such as the login picker
 * and the failed-login page (ADR-0050). A template is plain HTML with {@code {{name}}}
 * placeholders.
 *
 * <p>{@link #render} HTML-escapes every text value, so a caller never escapes by hand. A value that
 * is already HTML, such as a fragment rendered from another template, is passed separately and
 * inserted as it is. Substitution is a single pass, so a value that contains a placeholder is never
 * substituted again.
 */
public final class HtmlTemplate {

  private static final Pattern PLACEHOLDER = Pattern.compile("\\{\\{(\\w+)}}");

  private HtmlTemplate() {}

  /**
   * Reads a template from {@code anchor}'s package, or returns empty and logs an ERROR when it is
   * missing or unreadable. Never throws: a resource filtered out of a shaded jar must not fail the
   * application, so the caller falls back to a plainer response instead.
   *
   * @param fallback what happens instead of the page, completing the log message
   */
  public static Optional<String> load(
      final Class<?> anchor, final String resource, final Logger log, final String fallback) {
    try (final InputStream template = anchor.getResourceAsStream(resource)) {
      if (template == null) {
        log.error("Missing resource {}; {}", resource, fallback);
        return Optional.empty();
      }
      return Optional.of(new String(template.readAllBytes(), StandardCharsets.UTF_8));
    } catch (final IOException | UncheckedIOException e) {
      log.error("Failed to read resource {}; {}", resource, fallback, e);
      return Optional.empty();
    }
  }

  /**
   * Fills {@code template}'s placeholders: those named in {@code text} with the HTML-escaped value,
   * those named in {@code html} with the value as it is.
   *
   * @throws IllegalArgumentException if the template has a placeholder that neither map names, or a
   *     name is in both maps
   */
  public static String render(
      final String template, final Map<String, String> text, final Map<String, String> html) {
    final Map<String, String> values = new HashMap<>(html);
    text.forEach(
        (name, value) -> {
          if (values.put(name, HtmlUtils.htmlEscape(value)) != null) {
            throw new IllegalArgumentException("Placeholder " + name + " is both text and HTML");
          }
        });
    return PLACEHOLDER
        .matcher(template)
        .replaceAll(
            placeholder -> {
              final String value = values.get(placeholder.group(1));
              if (value == null) {
                throw new IllegalArgumentException("No value for " + placeholder.group());
              }
              return Matcher.quoteReplacement(value);
            });
  }

  /** {@link #render(String, Map, Map)} for a template whose values are all text. */
  public static String render(final String template, final Map<String, String> text) {
    return render(template, text, Map.of());
  }
}
