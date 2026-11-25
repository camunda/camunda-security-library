# Calling CSL-protected services: the outbound client

CSL protects services, and the `client` module is the other direction: it adds credentials to
your outgoing HTTP calls to a service CSL protects. It supports OIDC client credentials
(`client_secret_post`) and HTTP Basic. It needs no Spring and no other CSL module, so it works on a
plain Java thread. The module runs on Java 8 and later. Decision record: [ADR-0049](../adr/0049-spring-free-client-for-csl-protected-services.md).

The module does not retry requests. After a `401`, `shouldRetryRequest` fetches a new token and
tells you whether it differs from the cached one; you decide whether to send again. Retry
at most once per request, and only if the request is safe to repeat. Retry policy, `private_key_jwt`,
mTLS and a disk cache are not part of this module.

## Plain Java

Add the Maven artifact `io.camunda:camunda-security-library-client`. Build a provider and apply it
to each request:

```java
final var provider =
    OutboundCredentialsProviders.oidc(
        OidcClientCredentialsConfiguration.builder(
                URI.create("https://idp.example/oauth/token"), "my-client-id", "my-client-secret")
            .audience("hub-api") // optional, like scopes, resource and the three timeouts
            .build());

// This example uses the JDK HttpClient. It needs Java 11 or later.
// On Java 8, use your own HTTP client in the same way.
final HttpClient http = HttpClient.newHttpClient();

HttpResponse<String> send(final URI uri) throws IOException, InterruptedException {
  HttpResponse<String> response = http.send(request(uri), BodyHandlers.ofString());
  if (provider.shouldRetryRequest(StatusCode.ofHttp(response.statusCode()))) {
    response = http.send(request(uri), BodyHandlers.ofString()); // once, a fresh token
  }
  return response;
}

HttpRequest request(final URI uri) throws IOException {
  final HttpRequest.Builder builder = HttpRequest.newBuilder(uri);
  provider.applyCredentials(builder::header);
  return builder.build();
}
```

Use `OutboundCredentialsProviders.basic(new BasicAuthConfiguration("user", "password"))` for Basic
authentication.

### Retries and token caching

`shouldRetryRequest(StatusCode.ofHttp(status))` is `false` for anything but `401`. For a `401` the
provider drops the cached token and requests a new one. It returns `true` if the new token
differs from the token that was cached when the `401` was reported. If the IdP hands out the same token again, or fails, it returns
`false` and logs the failure. If the token request fails, the next call requests a new token
again. The call may block on one token request, and it may run on any thread, so it works with
`sendAsync` where the response arrives on another thread than the request.

The provider compares the new token with the cached one. It does not know which token the failed
request carried. Suppose several requests get a `401` for the same old token. The first call fetches
a new token. A late `401` for the old token drops the new token too, and the next call waits for
one more token request. Retry at most once per request, as above, to limit this.

The token is cached and refreshed 30 seconds before it expires, or halfway through its lifetime if
that is shorter. If the refresh fails, the provider keeps sending the old token until it expires.
It does not do this after a `401` for that token, because the IdP rejected it. The first failed
refresh that keeps the old token logs a WARN. When no valid token is left and a call fails, the
provider logs a WARN too. A failure with the same cause as the last one logs at DEBUG, and every
100th one logs a WARN again. A successful token request resets this. A response without `expires_in`, or with `0`, is not cached.

One caller at a time makes a token request. The other callers wait, and then use the token that it
cached. If that request failed, each waiting caller makes its own request.

The provider uses the Nimbus OAuth SDK (`oauth2-oidc-sdk`) for the token request. It accepts only
responses that follow RFC 6749:

- The success response has `Content-Type: application/json`.
- `access_token` is a string that is not blank.
- `token_type` is `Bearer` (any case). DPoP is not supported.
- `expires_in`, if present, is a number or a numeric string with no spaces, and it is not
  negative.

Other responses fail with a `TokenRequestException`. The message does not quote the response,
because the response can contain the token. A token response larger than 64 KiB fails too. A real token response is a few KB.

### Timeouts

A call waits at most `requestTimeout` (default 30 seconds) for a token. A body that stops in the
middle is an exception (see below). This includes the wait for
a token request of another caller. If the time is up and no valid token is cached, the call fails.
If the token request of a call runs out of time and the old token is still valid, the call uses the
old token, as after any failed refresh.

The token request runs on one worker thread for each provider. When the time is up, the provider
closes the connection. This stops a response that is slow. If the response stops in the middle of
the body, closing the connection waits until the read of the worker ends. A call that runs out of
time can then wait up to `readTimeout` longer than `requestTimeout`. An interrupted call and
`close()` can wait up to `readTimeout`. Other calls that wait for that token request fail at their
own `requestTimeout`, also when the old token is still valid. The provider cannot stop the DNS
lookup, the connect, the TLS handshake or the request body. The worker closes the connection when
these steps end. Only `connectTimeout` and `readTimeout` limit them, and the DNS lookup has no
timeout. While such a request still runs, the next token requests fail at once, so threads do not
pile up.

`readTimeout` limits each wait for data, not the whole request. An interrupt does not stop the
token request, because the SDK sends with `HttpURLConnection`. An interrupt stops the caller that
waits, and that caller always fails, also when the old token is still valid. If the body stopped
in the middle, the caller can first wait up to `readTimeout`.

### Lifecycle

Every provider has a `close()` (`OutboundCredentialsProvider` extends `AutoCloseable`; it throws no
checked exception). For the OIDC provider, `close()` stops the worker thread and closes a running
token request. After `close()`, calls fail with a `TokenRequestException`, also when a token is
cached. `shouldRetryRequest` returns `false`. For the Basic provider, `close()` does nothing. Call `close()` on a provider, or on `OutboundCredentialsProviders` to close
all of its providers, when you are done.

### Errors

Every failed token request surfaces as a `TokenRequestException` (an `IOException`), whether the
token endpoint answered with an error, sent an unusable response, could not be reached, did not
finish in time, or the caller was interrupted. It carries the HTTP status, the OAuth `error` and a
truncated `error_description`, never the secret. `getStatus()` is
`TokenRequestException.NO_RESPONSE` (`-1`) when the IdP gave no response.

Invalid configuration fails with an `IllegalArgumentException` that names the field. Examples:

- a `tokenUri` that is not `http` or `https` with a host, or that has user-info;
- a `tokenUri` with `http` and a host other than `localhost`, `127.0.0.1` or `[::1]`, because
  `client_secret_post` would send the secret in clear text;
- a blank scope;
- a timeout that is not positive, or that does not fit into an `int` of milliseconds.

## Spring

Spring hosts will bind named clients under `camunda.security.client.<name>` through the CSL starter.
That binding comes in a later pull request. Until then, build the providers with the factories in
`OutboundCredentialsProviders`, as shown above.
