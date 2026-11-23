# Calling CSL-protected services: the outbound client

CSL protects services, and the `client` module is the other direction: it adds credentials to
your outgoing HTTP calls to a service CSL protects. It supports HTTP Basic. It needs no Spring and
no other CSL module, so it works on a plain Java thread. The module runs on Java 8 and later.
Decision record: [ADR-0049](../adr/0049-spring-free-client-for-csl-protected-services.md).

The module does not retry requests. `shouldRetryRequest` tells you whether a new attempt can
succeed; you decide whether to send again. Retry at most once per request, and only if the request
is safe to repeat.

## Plain Java

Add the Maven artifact `io.camunda:camunda-security-library-client`. Build a provider and apply it
to each request:

```java
final var provider =
    OutboundCredentialsProviders.basic(new BasicAuthConfiguration("user", "password"));

// This example uses the JDK HttpClient. It needs Java 11 or later.
// On Java 8, use your own HTTP client in the same way.
final HttpClient http = HttpClient.newHttpClient();

HttpResponse<String> send(final URI uri) throws IOException, InterruptedException {
  final HttpRequest.Builder builder = HttpRequest.newBuilder(uri);
  provider.applyCredentials(builder::header);
  return http.send(builder.build(), BodyHandlers.ofString());
}
```

For Basic, `shouldRetryRequest` is always `false`: the same user name and password would be
rejected again.

### Lifecycle

Every provider has a `close()` (`OutboundCredentialsProvider` extends `AutoCloseable`; it throws no
checked exception). For the Basic provider, `close()` does nothing. Call `close()` on a provider,
or on `OutboundCredentialsProviders` to close all of its providers, when you are done.

### Errors

Invalid configuration fails with an `IllegalArgumentException` that names the field, for example a
blank user name, or a user name that contains `:`. A missing password fails with a
`NullPointerException`.

## Spring

Spring hosts will bind named clients under `camunda.security.client.<name>` through the CSL starter.
That binding comes in a later pull request. Until then, build the providers with the factories in
`OutboundCredentialsProviders`, as shown above.
