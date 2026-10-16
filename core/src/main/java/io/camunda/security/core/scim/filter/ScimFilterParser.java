/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.core.scim.filter;

import io.camunda.security.core.scim.ScimException;
import io.camunda.security.core.scim.filter.ScimFilter.AttributePath;
import io.camunda.security.core.scim.filter.ScimFilter.Operator;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Recursive-descent parser for RFC 7644 §3.4.2.2 filters. Precedence, highest first: grouping and
 * value paths, {@code not}, {@code and}, {@code or}. Operators and logical keywords are
 * case-insensitive; strings use JSON escapes.
 */
public final class ScimFilterParser {

  private enum Kind {
    LPAREN,
    RPAREN,
    LBRACKET,
    RBRACKET,
    STRING,
    WORD
  }

  private record Token(Kind kind, String text) {}

  private final String source;
  private final List<Token> tokens;
  private int pos;

  private ScimFilterParser(final String source) {
    this.source = source;
    this.tokens = tokenize(source);
  }

  /** Parses a complete filter expression. */
  public static ScimFilter parse(final String filter) {
    if (filter == null || filter.isBlank()) {
      throw ScimException.invalidFilter("Filter must not be empty");
    }
    final ScimFilterParser parser = new ScimFilterParser(filter);
    final ScimFilter result = parser.parseOr();
    if (parser.pos < parser.tokens.size()) {
      throw parser.error("Unexpected '" + parser.tokens.get(parser.pos).text() + "'");
    }
    return result;
  }

  /** Splits {@code [urn:]attr[.sub]} into its components. */
  public static AttributePath parseAttributePath(final String word) {
    String urn = null;
    String rest = word;
    final int colon = word.lastIndexOf(':');
    if (colon >= 0) {
      urn = word.substring(0, colon);
      rest = word.substring(colon + 1);
    }
    String sub = null;
    final int dot = rest.indexOf('.');
    if (dot >= 0) {
      sub = rest.substring(dot + 1);
      rest = rest.substring(0, dot);
    }
    if (rest.isEmpty() || (sub != null && sub.isEmpty()) || (urn != null && urn.isEmpty())) {
      throw ScimException.invalidFilter("Invalid attribute path '" + word + "'");
    }
    return new AttributePath(urn, rest, sub);
  }

  private ScimFilter parseOr() {
    ScimFilter left = parseAnd();
    while (peekKeyword("or")) {
      pos++;
      left = new ScimFilter.Or(left, parseAnd());
    }
    return left;
  }

  private ScimFilter parseAnd() {
    ScimFilter left = parseUnary();
    while (peekKeyword("and")) {
      pos++;
      left = new ScimFilter.And(left, parseUnary());
    }
    return left;
  }

  private ScimFilter parseUnary() {
    final Token token = next("a filter expression");
    if (token.kind() == Kind.LPAREN) {
      final ScimFilter inner = parseOr();
      expect(Kind.RPAREN, "')'");
      return inner;
    }
    if (token.kind() != Kind.WORD) {
      throw error("Unexpected '" + token.text() + "'");
    }
    if (token.text().equalsIgnoreCase("not") && peek(Kind.LPAREN)) {
      pos++;
      final ScimFilter inner = parseOr();
      expect(Kind.RPAREN, "')'");
      return new ScimFilter.Not(inner);
    }
    return parseAttributeExpression(parseAttributePath(token.text()));
  }

  private ScimFilter parseAttributeExpression(final AttributePath path) {
    if (peek(Kind.LBRACKET)) {
      pos++;
      final ScimFilter inner = parseOr();
      expect(Kind.RBRACKET, "']'");
      return new ScimFilter.ValuePath(path, inner);
    }
    final Token op = next("an operator");
    if (op.kind() != Kind.WORD) {
      throw error("Expected an operator but found '" + op.text() + "'");
    }
    final String name = op.text().toLowerCase(Locale.ROOT);
    if (name.equals("pr")) {
      return new ScimFilter.Present(path);
    }
    final Operator operator = parseOperator(name);
    return new ScimFilter.Compare(path, operator, parseValue());
  }

  private Operator parseOperator(final String name) {
    try {
      return Operator.valueOf(name.toUpperCase(Locale.ROOT));
    } catch (final IllegalArgumentException e) {
      throw error("Unknown operator '" + name + "'");
    }
  }

  private Object parseValue() {
    final Token token = next("a comparison value");
    if (token.kind() == Kind.STRING) {
      return token.text();
    }
    if (token.kind() != Kind.WORD) {
      throw error("Expected a value but found '" + token.text() + "'");
    }
    switch (token.text()) {
      case "true":
        return Boolean.TRUE;
      case "false":
        return Boolean.FALSE;
      case "null":
        return null;
      default:
        return parseNumber(token.text());
    }
  }

  private Number parseNumber(final String text) {
    try {
      return text.contains(".") || text.contains("e") || text.contains("E")
          ? (Number) Double.valueOf(text)
          : (Number) Long.valueOf(text);
    } catch (final NumberFormatException e) {
      throw error("Invalid value '" + text + "'");
    }
  }

  private boolean peekKeyword(final String keyword) {
    return pos < tokens.size()
        && tokens.get(pos).kind() == Kind.WORD
        && tokens.get(pos).text().equalsIgnoreCase(keyword);
  }

  private boolean peek(final Kind kind) {
    return pos < tokens.size() && tokens.get(pos).kind() == kind;
  }

  private Token next(final String expected) {
    if (pos >= tokens.size()) {
      throw error("Unexpected end of filter, expected " + expected);
    }
    return tokens.get(pos++);
  }

  private void expect(final Kind kind, final String description) {
    if (!peek(kind)) {
      throw error("Expected " + description);
    }
    pos++;
  }

  private ScimException error(final String message) {
    return ScimException.invalidFilter(message + " in filter '" + source + "'");
  }

  private static List<Token> tokenize(final String text) {
    final List<Token> result = new ArrayList<>();
    int i = 0;
    while (i < text.length()) {
      final char c = text.charAt(i);
      if (Character.isWhitespace(c)) {
        i++;
      } else if (c == '(') {
        result.add(new Token(Kind.LPAREN, "("));
        i++;
      } else if (c == ')') {
        result.add(new Token(Kind.RPAREN, ")"));
        i++;
      } else if (c == '[') {
        result.add(new Token(Kind.LBRACKET, "["));
        i++;
      } else if (c == ']') {
        result.add(new Token(Kind.RBRACKET, "]"));
        i++;
      } else if (c == '"') {
        i = readString(text, i + 1, result);
      } else {
        final int start = i;
        while (i < text.length() && !isDelimiter(text.charAt(i))) {
          i++;
        }
        result.add(new Token(Kind.WORD, text.substring(start, i)));
      }
    }
    return result;
  }

  private static boolean isDelimiter(final char c) {
    return Character.isWhitespace(c) || c == '(' || c == ')' || c == '[' || c == ']' || c == '"';
  }

  private static int readString(final String text, final int from, final List<Token> out) {
    final StringBuilder sb = new StringBuilder();
    int i = from;
    while (i < text.length()) {
      final char c = text.charAt(i++);
      if (c == '"') {
        out.add(new Token(Kind.STRING, sb.toString()));
        return i;
      }
      if (c != '\\') {
        sb.append(c);
        continue;
      }
      if (i >= text.length()) {
        break;
      }
      i = readEscape(text, i, sb);
    }
    throw ScimException.invalidFilter("Unterminated string in filter '" + text + "'");
  }

  private static int readEscape(final String text, final int from, final StringBuilder sb) {
    final char e = text.charAt(from);
    switch (e) {
      case 'n':
        sb.append('\n');
        return from + 1;
      case 't':
        sb.append('\t');
        return from + 1;
      case 'r':
        sb.append('\r');
        return from + 1;
      case 'b':
        sb.append('\b');
        return from + 1;
      case 'f':
        sb.append('\f');
        return from + 1;
      case 'u':
        if (from + 5 > text.length()) {
          throw ScimException.invalidFilter("Bad unicode escape in filter '" + text + "'");
        }
        sb.append((char) Integer.parseInt(text.substring(from + 1, from + 5), 16));
        return from + 5;
      default:
        sb.append(e);
        return from + 1;
    }
  }
}
