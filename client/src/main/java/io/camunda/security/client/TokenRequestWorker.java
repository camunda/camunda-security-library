/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Sends the token request on one worker thread and enforces the request timeout.
 *
 * <p>A call waits at most {@code requestTimeout} for a token, the wait for another caller included.
 * The token request runs on one worker thread. When the time is up, the worker closes the
 * connection, which stops a slow response. The DNS lookup, the connect, the TLS handshake and the
 * request body cannot be stopped; the worker closes the connection when they end. Only the connect
 * and read timeouts limit them, and the DNS lookup has no timeout. While such a request still runs,
 * other token requests fail at once.
 */
final class TokenRequestWorker implements AutoCloseable {

  private final OidcClientCredentialsConfiguration config;
  private final TokenSender sender;
  private final ThreadPoolExecutor executor;
  // Set while the worker sends a token request; the worker clears it when the request ends.
  private final AtomicBoolean busy = new AtomicBoolean();
  // The connection of the running token request, so that close() can reach it.
  private final AtomicReference<RequestConnection> current = new AtomicReference<>();

  TokenRequestWorker(final OidcClientCredentialsConfiguration config, final TokenSender sender) {
    this.config = config;
    this.sender = sender;
    executor = new ThreadPoolExecutor(1, 1, 60, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
    executor.setThreadFactory(
        task -> {
          final Thread thread = new Thread(task, "csl-token-request-" + config.clientId());
          thread.setDaemon(true);
          return thread;
        });
    executor.allowCoreThreadTimeOut(true);
  }

  /**
   * Sends on the worker thread and waits until the deadline. Then it closes the connection, so the
   * worker ends too. If the worker is still before the response (DNS lookup, connect, TLS handshake
   * or request body), it closes the connection as soon as it has it.
   */
  HTTPResponse send(final HTTPRequest request, final long deadline) throws IOException {
    // Busy first: a hung request is the cause, also when the time is up as well.
    if (!busy.compareAndSet(false, true)) {
      throw noResponse("the previous token request is still running", null);
    }
    if (remaining(deadline) <= 0) {
      busy.set(false);
      throw timedOut();
    }
    final RequestConnection connection = new RequestConnection();
    current.set(connection);
    final Future<HTTPResponse> result;
    try {
      result = executor.submit(() -> sendAndRelease(request, connection));
    } catch (final RuntimeException e) {
      current.set(null);
      busy.set(false);
      throw e;
    }
    try {
      return result.get(remaining(deadline), TimeUnit.NANOSECONDS);
    } catch (final TimeoutException e) {
      connection.abandon();
      throw timedOut();
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      connection.abandon();
      throw noResponse("the caller was interrupted", e);
    } catch (final ExecutionException e) {
      throw rethrow(e.getCause());
    }
  }

  private HTTPResponse sendAndRelease(final HTTPRequest request, final RequestConnection connection)
      throws IOException {
    try {
      return sender.send(request, connection);
    } finally {
      current.compareAndSet(connection, null);
      busy.set(false);
    }
  }

  private TokenRequestException timedOut() {
    return noResponse("it did not finish within " + config.requestTimeout(), null);
  }

  TokenRequestException noResponse(final String reason, final Throwable cause) {
    return new TokenRequestException(
        String.format(
            "Token request for client '%s' to %s failed: %s",
            config.clientId(), config.redactedTokenUri(), reason),
        TokenRequestException.NO_RESPONSE,
        null,
        null,
        cause);
  }

  private static IOException rethrow(final Throwable cause) {
    if (cause instanceof IOException) {
      return (IOException) cause;
    }
    if (cause instanceof RuntimeException) {
      throw (RuntimeException) cause;
    }
    if (cause instanceof Error) {
      throw (Error) cause;
    }
    return new IOException(cause);
  }

  static long remaining(final long deadline) {
    return deadline - System.nanoTime();
  }

  /** Stops the worker thread and closes a running token request. */
  @Override
  public void close() {
    executor.shutdownNow();
    final RequestConnection running = current.get();
    if (running != null) {
      running.abandon();
    }
  }

  boolean isClosed() {
    return executor.isShutdown();
  }

  /**
   * Sends like {@link HTTPRequest#send()}, but publishes the connection first, so that another
   * thread can close it. {@code toHttpURLConnection} connects and writes the request body.
   */
  static HTTPResponse sendOverConnection(
      final HTTPRequest request, final RequestConnection connection) throws IOException {
    final HttpURLConnection conn = request.toHttpURLConnection();
    if (!connection.publish(conn)) {
      throw new IOException("The caller no longer waits for this token request");
    }
    int status;
    InputStream stream;
    try {
      stream = conn.getInputStream();
      status = conn.getResponseCode();
    } catch (final IOException e) {
      // HttpURLConnection throws for a 4xx or 5xx status; the error stream has the body then.
      status = conn.getResponseCode();
      if (status == -1) {
        throw e;
      }
      stream = conn.getErrorStream();
    }
    final String body = readBody(stream);
    final HTTPResponse response = new HTTPResponse(status);
    response.setStatusMessage(conn.getResponseMessage());
    copyHeaders(conn, response);
    if (!body.isEmpty()) {
      response.setBody(body);
    }
    return response;
  }

  /** Reads line by line, like the SDK; {@code null} means no body. */
  private static String readBody(final InputStream stream) throws IOException {
    if (stream == null) {
      return "";
    }
    final StringBuilder body = new StringBuilder();
    try (BufferedReader reader =
        new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        body.append(line).append(System.lineSeparator());
      }
    }
    return body.toString();
  }

  private static void copyHeaders(final HttpURLConnection conn, final HTTPResponse response) {
    for (final Map.Entry<String, List<String>> header : conn.getHeaderFields().entrySet()) {
      final List<String> values = header.getValue();
      // The status line has the key null.
      if (header.getKey() != null && values != null && !values.isEmpty() && values.get(0) != null) {
        response.setHeader(header.getKey(), values.toArray(new String[0]));
      }
    }
  }

  /** Sends the token request; tests replace it to hold the worker thread. */
  @FunctionalInterface
  interface TokenSender {
    HTTPResponse send(HTTPRequest request, RequestConnection connection) throws IOException;
  }

  /**
   * The connection of one token request. If the caller gives up before the worker has the
   * connection, the worker closes it as soon as it gets it.
   */
  static final class RequestConnection {
    private HttpURLConnection connection;
    private boolean abandoned;

    /** False if the caller gave up already; the connection is then closed. */
    boolean publish(final HttpURLConnection opened) {
      synchronized (this) {
        if (!abandoned) {
          connection = opened;
          return true;
        }
      }
      opened.disconnect();
      return false;
    }

    void abandon() {
      final HttpURLConnection opened;
      synchronized (this) {
        abandoned = true;
        opened = connection;
      }
      if (opened != null) {
        opened.disconnect();
      }
    }
  }
}
