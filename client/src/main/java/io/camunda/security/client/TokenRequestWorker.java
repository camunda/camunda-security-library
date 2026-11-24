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
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
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
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.config.TlsConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.TlsSocketStrategy;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.URIScheme;
import org.apache.hc.core5.http.config.Lookup;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;

/**
 * Sends the token request on one worker thread and enforces the request timeout.
 *
 * <p>A call waits at most {@code requestTimeout} for a token, the wait for another caller included.
 * The token request runs on one worker thread with Apache HttpClient 5. When the time is up, the
 * caller cancels the request. This stops a slow response and a TLS handshake. The DNS lookup cannot
 * be stopped, and the worker ends the request when the lookup ends. The connect timeout limits the
 * connect, and the DNS lookup has no timeout. While such a request still runs, other token requests
 * fail at once.
 */
final class TokenRequestWorker implements AutoCloseable {

  /** Sends the request with the HTTP client of the worker. Production code uses this directly. */
  static final TokenSender DIRECT = (request, real) -> real.send(request);

  private final OidcClientCredentialsConfiguration config;
  private final TokenSender sender;
  private final BasicHttpClientConnectionManager connections;
  private final CloseableHttpClient client;
  private final ThreadPoolExecutor executor;
  // Set while the worker sends a token request. The worker clears it when the request ends.
  private final AtomicBoolean busy = new AtomicBoolean();
  // The running token request, so that close() can reach it.
  private final AtomicReference<HttpUriRequestBase> current = new AtomicReference<>();

  TokenRequestWorker(final OidcClientCredentialsConfiguration config, final TokenSender sender) {
    this.config = config;
    this.sender = sender;
    connections = buildConnections(config);
    client = buildClient(config, connections);
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
   * One worker sends one request at a time, so the connection manager holds one connection. A token
   * request never follows a redirect. Only the caller repeats a request.
   */
  private static BasicHttpClientConnectionManager buildConnections(
      final OidcClientCredentialsConfiguration config) {
    final Timeout connectTimeout = timeout(config.connectTimeout());
    final Timeout readTimeout = timeout(config.readTimeout());
    final Lookup<TlsSocketStrategy> tls =
        RegistryBuilder.<TlsSocketStrategy>create()
            .register(
                URIScheme.HTTPS.getId(),
                ClientTlsStrategyBuilder.create().useSystemProperties().buildClassic())
            .build();
    final BasicHttpClientConnectionManager connections =
        BasicHttpClientConnectionManager.create(tls);
    connections.setConnectionConfig(
        ConnectionConfig.custom()
            .setConnectTimeout(connectTimeout)
            .setSocketTimeout(readTimeout)
            .build());
    connections.setTlsConfig(TlsConfig.custom().setHandshakeTimeout(readTimeout).build());
    return connections;
  }

  private static CloseableHttpClient buildClient(
      final OidcClientCredentialsConfiguration config,
      final BasicHttpClientConnectionManager connections) {
    return HttpClients.custom()
        .setConnectionManager(connections)
        .setDefaultRequestConfig(
            RequestConfig.custom().setResponseTimeout(timeout(config.readTimeout())).build())
        .useSystemProperties()
        .disableRedirectHandling()
        .disableAutomaticRetries()
        .disableCookieManagement()
        .disableContentCompression()
        .disableDefaultUserAgent()
        .build();
  }

  /** At least 1 ms, because HttpClient reads 0 as "wait forever". */
  private static Timeout timeout(final Duration duration) {
    return Timeout.ofMilliseconds(Math.max(1L, (duration.toNanos() + 999_999L) / 1_000_000L));
  }

  /**
   * Sends on the worker thread and waits until the deadline. Then it cancels the request, so the
   * worker ends too. If the worker is still before the response (DNS lookup), the request fails as
   * soon as the lookup ends.
   */
  HTTPResponse send(final HTTPRequest nimbusRequest, final long deadline) throws IOException {
    final HttpUriRequestBase request = toHttpRequest(nimbusRequest);
    // Busy first: a hung request is the cause, also when the time is up as well.
    if (!busy.compareAndSet(false, true)) {
      throw noResponse("the previous token request is still running", null);
    }
    if (remaining(deadline) <= 0) {
      busy.set(false);
      throw timedOut();
    }
    current.set(request);
    final Future<HTTPResponse> result;
    try {
      result = executor.submit(() -> sendAndRelease(request));
    } catch (final RuntimeException e) {
      current.set(null);
      busy.set(false);
      throw e;
    }
    try {
      return result.get(remaining(deadline), TimeUnit.NANOSECONDS);
    } catch (final TimeoutException e) {
      cancel(request);
      throw timedOut();
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      cancel(request);
      throw noResponse("the caller was interrupted", e);
    } catch (final ExecutionException e) {
      throw rethrow(e.getCause());
    }
  }

  private HTTPResponse sendAndRelease(final HttpUriRequestBase request) throws IOException {
    try {
      return sender.send(request, this::execute);
    } finally {
      if (request.isCancelled()) {
        dropDeadConnection();
      }
      current.compareAndSet(request, null);
      busy.set(false);
    }
  }

  private void cancel(final HttpUriRequestBase request) {
    request.cancel();
    dropDeadConnection();
  }

  /**
   * A cancel during the TLS handshake can leave a dead socket in the connection manager. Without
   * this, every next request can fail with "Socket is closed". The caller drops it after the
   * cancel, and the worker drops it when the request ends.
   */
  private void dropDeadConnection() {
    connections.closeIdle(TimeValue.ZERO_MILLISECONDS);
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

  /** Stops the worker thread, cancels a running token request and closes the HTTP client. */
  @Override
  public void close() {
    executor.shutdownNow();
    final HttpUriRequestBase running = current.get();
    if (running != null) {
      running.cancel();
    }
    client.close(CloseMode.IMMEDIATE);
  }

  boolean isClosed() {
    return executor.isShutdown();
  }

  /** Converts the SDK request: method, URI with query, headers and the form body. */
  private static HttpUriRequestBase toHttpRequest(final HTTPRequest request) throws IOException {
    final URI uri;
    try {
      uri = request.getURL().toURI();
    } catch (final URISyntaxException e) {
      throw new IOException("The token URI is not valid", e);
    }
    final HttpUriRequestBase result = new HttpUriRequestBase(request.getMethod().name(), uri);
    for (final Map.Entry<String, List<String>> header : request.getHeaderMap().entrySet()) {
      if (!isSetByTheEntity(header.getKey())) {
        for (final String value : header.getValue()) {
          result.addHeader(header.getKey(), value);
        }
      }
    }
    if (request.getBody() != null) {
      result.setEntity(
          new StringEntity(
              request.getBody(),
              ContentType.parse(request.getHeaderValue(HttpHeaders.CONTENT_TYPE))));
    }
    return result;
  }

  private static boolean isSetByTheEntity(final String name) {
    return HttpHeaders.CONTENT_LENGTH.equalsIgnoreCase(name)
        || HttpHeaders.TRANSFER_ENCODING.equalsIgnoreCase(name)
        || HttpHeaders.HOST.equalsIgnoreCase(name)
        || HttpHeaders.CONTENT_TYPE.equalsIgnoreCase(name);
  }

  /** Executes the request and maps the response, also a 4xx or 5xx one, to an SDK response. */
  private HTTPResponse execute(final HttpUriRequestBase request) throws IOException {
    return client.execute(request, TokenRequestWorker::toResponse);
  }

  private static HTTPResponse toResponse(final ClassicHttpResponse source) throws IOException {
    final HTTPResponse response = new HTTPResponse(source.getCode());
    response.setStatusMessage(source.getReasonPhrase());
    final Map<String, List<String>> headers = new LinkedHashMap<>();
    for (final Header header : source.getHeaders()) {
      headers.computeIfAbsent(header.getName(), name -> new ArrayList<>()).add(header.getValue());
    }
    headers.forEach((name, values) -> response.setHeader(name, values.toArray(new String[0])));
    final String body = readBody(source.getEntity());
    if (!body.isEmpty()) {
      response.setBody(body);
    }
    return response;
  }

  private static String readBody(final HttpEntity entity) throws IOException {
    if (entity == null) {
      return "";
    }
    try {
      return EntityUtils.toString(entity, StandardCharsets.UTF_8);
    } catch (final ParseException e) {
      throw new IOException("The token response has an invalid Content-Type", e);
    }
  }

  /** Sends the token request. Tests replace it to hold the worker thread. */
  @FunctionalInterface
  interface TokenSender {
    HTTPResponse send(HttpUriRequestBase request, RealSend real) throws IOException;
  }

  /** Executes the request with the HTTP client of the worker. */
  @FunctionalInterface
  interface RealSend {
    HTTPResponse send(HttpUriRequestBase request) throws IOException;
  }
}
