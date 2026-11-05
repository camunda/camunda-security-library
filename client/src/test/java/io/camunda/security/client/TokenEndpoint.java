/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/** Mock OAuth2 token endpoint on a loopback port. Issues {@code token-1}, {@code token-2}, ... */
final class TokenEndpoint implements AutoCloseable {

  private final HttpServer server;
  private final List<String> requestBodies = new CopyOnWriteArrayList<>();
  private final AtomicInteger issued = new AtomicInteger();
  private volatile int status = 200;
  private volatile String body;
  private volatile String contentType = "application/json";
  private final List<String> acceptHeaders = new CopyOnWriteArrayList<>();
  private final List<String> requestQueries = new CopyOnWriteArrayList<>();
  private volatile CountDownLatch release = new CountDownLatch(0);

  TokenEndpoint() throws IOException {
    server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.setExecutor(Executors.newCachedThreadPool());
    server.createContext("/token", this::handle);
    server.start();
  }

  URI uri() {
    return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/token");
  }

  int requestCount() {
    return requestBodies.size();
  }

  List<String> requestBodies() {
    return requestBodies;
  }

  /** Answers every request with a fixed status and body instead of a fresh token. */
  void respondWith(final int newStatus, final String newBody) {
    status = newStatus;
    body = newBody;
  }

  /** Answers with this content type instead of {@code application/json}. */
  void respondWithContentType(final String newContentType) {
    contentType = newContentType;
  }

  /** The {@code Accept} header of every request, in order; {@code null} if it was missing. */
  List<String> acceptHeaders() {
    return acceptHeaders;
  }

  /** The raw query of every request, in order; {@code null} if there was none. */
  List<String> requestQueries() {
    return requestQueries;
  }

  /** Holds every response until the returned latch is released. */
  CountDownLatch blockResponses() {
    release = new CountDownLatch(1);
    return release;
  }

  private void handle(final HttpExchange exchange) throws IOException {
    acceptHeaders.add(exchange.getRequestHeaders().getFirst("Accept"));
    requestQueries.add(exchange.getRequestURI().getRawQuery());
    requestBodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
    try {
      release.await();
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
    }
    final String response =
        body != null
            ? body
            : "{\"access_token\":\"token-%d\",\"token_type\":\"bearer\",\"expires_in\":3600}"
                .formatted(issued.incrementAndGet());
    final byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", contentType);
    exchange.sendResponseHeaders(status, bytes.length);
    exchange.getResponseBody().write(bytes);
    exchange.close();
  }

  @Override
  public void close() {
    server.stop(0);
    ((java.util.concurrent.ExecutorService) server.getExecutor()).shutdownNow();
  }
}
