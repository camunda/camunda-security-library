/*
 * Copyright Camunda Services GmbH and/or licensed to Camunda Services GmbH under
 * one or more contributor license agreements. See the NOTICE file distributed
 * with this work for additional information regarding copyright ownership.
 * Licensed under the Camunda License 1.0. You may not use this file
 * except in compliance with the Camunda License 1.0.
 */
package io.camunda.security.client;

import java.io.IOException;

/**
 * Adds credentials to an outgoing call to a CSL-protected service.
 *
 * <p>The shape follows the Java Camunda client's {@code CredentialsProvider}: {@link
 * #applyCredentials} sets headers on a request, and {@link #shouldRetryRequest} tells the caller
 * whether a new attempt can succeed. The provider never repeats a request itself; the caller
 * decides, because only the caller knows whether the request is safe to send twice (a {@code POST}
 * usually is not). Callers retry at most once per request.
 *
 * <p>Implementations are thread-safe. Every provider can be closed; the default does nothing, and a
 * provider that holds resources, such as an HTTP client, releases them.
 *
 * <p>Usage with the JDK {@code HttpClient}. The example needs Java 11 or later; on Java 8, use your
 * own HTTP client in the same way:
 *
 * <pre>{@code
 * HttpRequest.Builder builder = HttpRequest.newBuilder(uri);
 * provider.applyCredentials(builder::header);
 * HttpResponse<String> response = http.send(builder.build(), BodyHandlers.ofString());
 * if (provider.shouldRetryRequest(StatusCode.ofHttp(response.statusCode()))) {
 *   // rebuild the request, apply credentials again, send once more
 * }
 * }</pre>
 *
 * <p>See ADR-0042.
 */
public interface OutboundCredentialsProvider extends AutoCloseable {

  /**
   * Sets the credential headers, for example {@code Authorization}, through the applier.
   *
   * @throws IOException if the credentials cannot be obtained. A failed token request is a {@link
   *     TokenRequestException}, also when the token endpoint gave no response.
   */
  void applyCredentials(CredentialsApplier applier) throws IOException;

  /**
   * Tells whether a request that failed with the given status can succeed on a new attempt, for
   * example because the provider fetched a new token after a {@code 401}. Does not repeat anything
   * itself.
   *
   * <p>May block on one token request and may be called from any thread, not only the one that
   * applied the credentials, so it works with {@code sendAsync}. Callers retry at most once.
   */
  boolean shouldRetryRequest(StatusCode statusCode);

  /** Releases the resources of this provider. Does nothing by default. */
  @Override
  default void close() {}

  /** Receives the headers a provider wants set on a request. */
  @FunctionalInterface
  interface CredentialsApplier {
    void put(String header, String value);
  }

  /** Transport-neutral status of a failed call, so non-HTTP callers can reuse providers. */
  interface StatusCode {

    int code();

    boolean isUnauthorized();

    /** HTTP status code; {@code 401} is unauthorized. */
    static StatusCode ofHttp(final int httpStatus) {
      return new StatusCode() {
        @Override
        public int code() {
          return httpStatus;
        }

        @Override
        public boolean isUnauthorized() {
          return httpStatus == 401;
        }
      };
    }
  }
}
