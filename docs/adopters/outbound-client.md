# Calling CSL-protected services: the outbound client

CSL protects services, and the `client` module is the other direction: it adds credentials to
your outgoing HTTP calls to a service CSL protects. It supports OIDC client credentials
(`client_secret_post`) and HTTP Basic. It needs no Spring and no other CSL module, so it works on a
plain Java thread. The module runs on Java 8 and later. Decision record: [ADR-0042](../adr/0042-spring-free-client-for-csl-protected-services.md).

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
        new OidcClientCredentialsConfiguration(
            URI.create("https://idp.example/oauth/token"),
            "my-client-id",
            "my-client-secret",
            "hub-api", // audience, optional
            List.of(), // scopes, optional
            null, // resource, optional
            null, // connect timeout, default 10 s
            null)); // read timeout, default 10 s

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
provider requests a new token and returns `true` if it differs from the cached one; if the IdP hands
out the same token again, or fails, it returns `false` and logs the failure. If the token request
fails, the provider drops the rejected token, so the next call requests a new token. The call may
block on one token request, and it may run on any thread, so it works with `sendAsync` where the
response arrives on another thread than the request.

The provider compares the new token with the cached one. It does not know which token the failed
request carried. Suppose several requests get a `401` for the same old token. The first call fetches
a new token. A late `401` for the old token can fetch one more token. If the IdP is down then, the
late call can drop the new token. Retry at most once per request, as above, to limit this.

The token is cached and refreshed 30 seconds before it expires, or halfway through its lifetime if
that is shorter. If the refresh fails, the provider keeps sending the old token until it expires.
It does not do this after a `401` for that token, because the IdP rejected it. A response without
`expires_in`, or with `0`, is not cached. Concurrent callers share one token request, and its
failure: if the IdP is slow or down, every waiting caller fails after one timeout, not one each.

The provider uses the Nimbus OAuth SDK (`oauth2-oidc-sdk`) for the token request. It accepts only
responses that follow RFC 6749:

- The success response has `Content-Type: application/json`.
- `access_token` is a string that is not blank. It has only visible ASCII characters (no space,
  no control character), because it goes into an HTTP header.
- `token_type` is `Bearer` or `DPoP` (any case).
- `expires_in`, if present, is a number or a numeric string with no spaces, and it is not
  negative.

Other responses fail with a `TokenRequestException` that names the field.

### Lifecycle

Every provider has a `close()` (`OutboundCredentialsProvider` extends `AutoCloseable`; it throws no
checked exception). Today it does nothing for both providers, because they hold no open
connections. Call `close()` on a provider, or on `OutboundCredentialsProviders` to close all of its
providers, when you are done, so that later versions can free resources.

### Errors

Every failed token request surfaces as a `TokenRequestException` (an `IOException`), whether the
token endpoint answered with an error, sent an unusable response, could not be reached, or a
waiting caller was interrupted. It carries the HTTP status, the OAuth `error` and a truncated
`error_description`, never the secret. `getStatus()` is `TokenRequestException.NO_RESPONSE` (`-1`)
when the IdP gave no response. A caller that was waiting on another caller's failed request gets its
own `TokenRequestException` with the same status and `error`, and the original as cause. Invalid
configuration, such as a `tokenUri` that is not `http` or `https` with a host, a `tokenUri` with
user-info, a blank scope, or a timeout that does not fit into an `int` of milliseconds, fails with an `IllegalArgumentException` naming the
field.

`readTimeout` limits each wait for data, not the whole request. A server that sends data slowly can
keep the request open for longer. The DNS lookup has no timeout. A token request that sends no data
ends at `readTimeout`. An interrupt does not stop it, because the SDK
sends with `HttpURLConnection`. An interrupt stops only a caller that waits for another caller's
request.

## Spring

Spring hosts will bind named clients under `camunda.security.client.<name>` through the CSL starter.
That binding comes in a later pull request. Until then, build the providers with the factories in
`OutboundCredentialsProviders`, as shown above.
