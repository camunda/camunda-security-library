---
status: Accepted
---

# ADR-0035: Explain failed OIDC browser logins on a page the host can word

**Deciders**: Timothy Cline

## Status

Accepted

## Context

When an OIDC login fails at the redirect endpoint, the webapp chains hand the failure to
`OAuth2AuthenticationExceptionHandler`. That handler only recovers from
`authorization_request_not_found`; every other failure went to Spring's
`SimpleUrlAuthenticationFailureHandler`, which sends a bare `401`. The host's error controller turns
that into a JSON problem detail, so a user who followed a link in the browser sees a raw JSON
document with no explanation and no way forward.

The common case is a token the host's own validator rejects. On CCSaaS, a user who opens a link to
a cluster of another organization signs in at Auth0, and the host's organization validator rejects
the ID token (camunda/camunda-hub#30293). Before CSL owned these chains, the host rethrew the
exception, so the user saw a `500` whose detail quoted the token's organization claims. CSL fixed
the status but not the experience, and the reason for the failure was only logged at `DEBUG`.

Two constraints shape any fix. CSL is scope-agnostic and knows nothing about organizations, so it
cannot word a SaaS-specific explanation itself. And the obvious recovery, redirecting the user
somewhere that starts a new login, loops: an IdP that keeps its own session signs the user straight
back in, and the same validator rejects the token again.

What should a failed OIDC browser login show, and how does a host explain failures only it
understands without CSL learning the host's vocabulary?

## Decision

A failed OIDC login of a browser request renders a small, self-contained HTML page instead of the
bare `401`. Non-browser requests keep the `401`, and the `authorization_request_not_found` redirect
is unchanged.

- **Page.** `OAuth2AuthenticationExceptionHandler` renders a title, a message and a "Try again" link
  to the chain's application root (`/` on the primary chain, `<basePath>/` on a scoped one), plus an
  optional host-supplied link. It never redirects or refreshes on its own, and it sends
  `Cache-Control: no-store`. A request counts as a browser request when its `Accept` header prefers
  `text/html`; a bare `*/*` does not.
- **Host SPI.** `io.camunda.security.spring.spi.OidcLoginFailurePort` has one method,
  `Optional<OidcLoginFailureNotice> explain(HttpServletRequest, AuthenticationException)`. When a bean
  is present, both OIDC chains ask it first; an empty result, or an exception from the port, falls
  back to generic text.
- **Notice.** `OidcLoginFailureNotice(int status, String title, String message, Link link)`, with
  `Link(String text, URI target)` optional. The status is `401` or `403`, the text must not be blank,
  and a link target must be an absolute `http`/`https` URI or a host-relative path.
- **No failure details on the page.** The page renders only CSL's generic text or the host's notice,
  all of it HTML-escaped. It never renders the exception message or the OAuth2 error description.
- **Logging.** Every failure other than the recovered redirect is logged once at `WARN` with the
  request path and the OAuth2 error code, or the exception type for a non-OAuth2 failure, never the
  description.

`ScopedWebappSecurityChainBuilder` takes an `ObjectProvider<OidcLoginFailurePort>` through a new
constructor and builds one handler per chain. The previous constructor stays and builds without a
port.

### Why these particular boundaries

- **The host words the explanation.** Hosts recognise their own validators' errors: a rejected ID
  token reaches the handler as an `OAuth2AuthenticationException` whose cause is a
  `JwtValidationException`, and its `getErrors()` carries the host validator's `OAuth2Error`. CSL
  passes the exception through and keeps no knowledge of what any error means.
- **A link, not a redirect.** A redirect cannot be made safe against the SSO loop; a link the user
  chooses can.
- **The description stays out of the page and the log.** Spring builds the `invalid_id_token`
  description from the validator's message, and validators quote claim values in it, such as the
  organizations a token claims. The error code carries enough to diagnose without that.
- **`401` or `403` only.** These are the two statuses that describe a failed or refused login. A
  `2xx` would tell caches and monitoring that the login worked; a `5xx` is what this replaces.
- **Restricted link targets.** The page escapes the target, but escaping does not stop a
  `javascript:` URI. Restricting targets to `http`/`https` and host-relative paths does.

### Default implementations and override boundaries

| Type | Default | Host override |
|---|---|---|
| `OidcLoginFailurePort` | none: generic page | register a bean |
| `OidcLoginFailureNotice` | generic `401` text | returned by the port |

## Consequences

**Positive**

- A user whose login is rejected gets a readable page and a way to try again instead of a JSON error.
- Hosts can explain their own rejections, such as a cluster of another organization, without CSL
  learning their concepts.
- Failed logins are visible in production logs at `WARN`, with a reason that is safe to log.

**Negative / accepted trade-offs**

- The page is styled after the webapps' own forbidden page (Carbon g10 values) with an inline
  `<style>` block, because the user has no session and cannot load the webapps' assets. Camunda's
  default content security policies allow inline styles; under a policy that does not, the page
  still renders, just unstyled. The styling is a copy, so it can drift from the webapps' design.
- CSL has no localization: its generic text is English. A host that needs another language words
  the notice itself and declares that language with the retry control's label
  (`OidcLoginFailureNotice#withLanguage`), so the page's `lang` matches the text assistive
  technology reads out. The "Camunda" header stays as it is in every language.
- One `WARN` per failed login. A user who retries repeatedly logs once per attempt.
- The "Try again" link can fail the same way again if nothing about the user's account has changed.
  The host's notice is where to offer a real way forward.

## Alternatives Considered

- **Redirect to the webapps' `/<webApp>/forbidden` page.** Rejected: that page belongs to a signed-in
  user and loads the user's data, so an unauthenticated user would be sent back to login, which
  loops through the IdP's session.
- **Keep the `401` and only log the reason at `WARN`.** Rejected: it fixes diagnosis, not the user's
  experience, which is what the issue is about.
- **Let the host replace the whole failure handler.** Rejected: hosts would have to re-implement the
  `authorization_request_not_found` recovery, the browser detection and the safe rendering, and the
  primary and scoped chains build their handlers internally. A port that supplies only the words keeps
  those in one place.
- **Put SaaS wording in CSL.** Rejected: it breaks CSL's scope-agnostic boundary
  ([ADR-0013](0013-camunda-security-scope-provider-spi.md)).
