/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.scim.poc;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.camunda.security.core.scim.ScimException;
import io.camunda.security.core.scim.ScimRequestHandler;
import io.camunda.security.core.scim.ScimResponse;
import io.camunda.security.core.scim.ScimUserService;
import io.camunda.security.core.scim.ScimUserValidator;
import io.camunda.security.core.scim.patch.ScimPatchEngine;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * Proof-of-concept SCIM 2.0 service provider (Users only). Wires the CSL SCIM core to a JDK HTTP
 * server and an in-memory repository that prints every entity to stdout.
 *
 * <p>Usage: {@code ScimPocCli [--port 8080] [--token secret] [--base-path /scim/v2] [--base-url
 * https://public.host/scim/v2]}. The token may also come from {@code SCIM_TOKEN}.
 */
public final class ScimPocCli {

  private static final Logger LOG = LoggerFactory.getLogger(ScimPocCli.class);
  private static final TypeReference<Map<String, Object>> TREE = new TypeReference<>() {};
  private static final String SCIM_JSON = "application/scim+json";

  private final ObjectMapper mapper =
      JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build();
  private final ScimRequestHandler scim;
  private final String basePath;
  private final byte[] token;

  private ScimPocCli(final ScimRequestHandler scim, final String basePath, final String token) {
    this.scim = scim;
    this.basePath = basePath;
    this.token = token.getBytes(StandardCharsets.UTF_8);
  }

  public static void main(final String[] args) throws IOException {
    final Map<String, String> options = parseArgs(args);
    final int port = Integer.parseInt(options.getOrDefault("port", "8080"));
    final String basePath = options.getOrDefault("base-path", "/scim/v2");
    final String token =
        options.getOrDefault(
            "token", System.getenv().getOrDefault("SCIM_TOKEN", "scim-poc-secret"));
    final String baseUrl = options.getOrDefault("base-url", "http://localhost:" + port + basePath);

    final ObjectMapper printer =
        JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build();
    final ScimUserValidator validator = new ScimUserValidator();
    final ScimUserService service =
        new ScimUserService(
            new PrintingScimUserRepositoryAdapter(printer),
            validator,
            new ScimPatchEngine(validator),
            Clock.systemUTC());
    final ScimPocCli cli =
        new ScimPocCli(new ScimRequestHandler(service, baseUrl), basePath, token);

    final HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext(basePath, cli::handle);
    server.start();
    System.out.println("SCIM POC listening on http://localhost:" + port + basePath);
    System.out.println("Bearer token: " + token);
    System.out.println("meta.location base URL: " + baseUrl);
  }

  private void handle(final HttpExchange exchange) throws IOException {
    try (exchange) {
      final String method = exchange.getRequestMethod();
      final String rawPath = exchange.getRequestURI().getRawPath();
      final byte[] requestBody = exchange.getRequestBody().readAllBytes();
      System.out.println("\n>>>>>>>> " + method + " " + exchange.getRequestURI());
      if (requestBody.length > 0) {
        System.out.println(new String(requestBody, StandardCharsets.UTF_8));
      }
      final ScimResponse response = process(exchange, method, rawPath, requestBody);
      write(exchange, response);
    }
  }

  private ScimResponse process(
      final HttpExchange exchange,
      final String method,
      final String rawPath,
      final byte[] requestBody) {
    if (!authorized(exchange.getRequestHeaders().getFirst("Authorization"))) {
      LOG.warn("Rejected {} {}: missing or invalid bearer token", method, rawPath);
      return ScimResponse.error(ScimException.unauthorized("Invalid or missing bearer token"));
    }
    final String path = URLDecoder.decode(rawPath, StandardCharsets.UTF_8);
    if (!path.startsWith(basePath)) {
      return ScimResponse.error(ScimException.notFound("Unknown path"));
    }
    final Map<String, Object> body;
    try {
      body = requestBody.length == 0 ? null : mapper.readValue(requestBody, TREE);
    } catch (final JacksonException e) {
      LOG.warn("Rejected {} {}: body is not a valid JSON object", method, path);
      return ScimResponse.error(ScimException.invalidSyntax("Request body is not valid JSON"));
    }
    return scim.handle(
        method,
        path.substring(basePath.length()),
        query(exchange.getRequestURI().getRawQuery()),
        body);
  }

  private boolean authorized(final String header) {
    if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
      return false;
    }
    final byte[] given = header.substring(7).trim().getBytes(StandardCharsets.UTF_8);
    return MessageDigest.isEqual(given, token);
  }

  private void write(final HttpExchange exchange, final ScimResponse response) throws IOException {
    exchange.getResponseHeaders().set("Content-Type", SCIM_JSON);
    response.headers().forEach((k, v) -> exchange.getResponseHeaders().set(k, v));
    System.out.println("<<<<<<<< " + response.status());
    if (response.body() == null) {
      exchange.sendResponseHeaders(response.status(), -1);
      return;
    }
    final String json = mapper.writeValueAsString(response.body());
    System.out.println(json);
    final byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(response.status(), bytes.length);
    try (OutputStream out = exchange.getResponseBody()) {
      out.write(bytes);
    }
  }

  private static Map<String, String> query(final String rawQuery) {
    final Map<String, String> result = new LinkedHashMap<>();
    if (rawQuery == null) {
      return result;
    }
    for (final String pair : rawQuery.split("&")) {
      final int eq = pair.indexOf('=');
      final String key = eq < 0 ? pair : pair.substring(0, eq);
      final String value = eq < 0 ? "" : pair.substring(eq + 1);
      result.putIfAbsent(
          URLDecoder.decode(key, StandardCharsets.UTF_8),
          URLDecoder.decode(value, StandardCharsets.UTF_8));
    }
    return result;
  }

  private static Map<String, String> parseArgs(final String[] args) {
    final Map<String, String> options = new LinkedHashMap<>();
    for (int i = 0; i + 1 < args.length; i += 2) {
      options.put(args[i].replaceFirst("^--", ""), args[i + 1]);
    }
    return options;
  }
}
