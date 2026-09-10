---
status: Accepted
---

# ADR-0022: Camunda-branded multi-IdP login picker, shown only when there is a real choice

**Deciders**: Ben Sheppard

## Status

Accepted

## Context

Under multi-IdP OIDC, an anonymous `GET /login` is rendered by Spring Security's stock
`DefaultLoginPageGeneratingFilter` (installed explicitly in `ScopedWebappSecurityChainBuilder`,
see ADR reference in `LoginLinksBuilder`/GH-269): a generic page with a bulleted list of blue
hyperlinks, one per OIDC client registration. It carries no Camunda branding and looks nothing
like the rest of the webapp.

Two problems were raised together while reviewing this page:

1. The page's look is Spring Security's own default template, which cannot be restyled — it has
   no hook for custom CSS/markup, only a fixed set of boolean toggles (`setOauth2LoginEnabled`,
   etc.) and a `Map<String, String>` of links.
2. `OidcWebappLoginPickerTest#anonymousLoginRendersPickerEvenWithSingleRegistration` documents that
   the picker also renders for a *single* registration when a user navigates to `/login` directly
   (e.g. via a bookmark or after logout) — showing a "choice" of exactly one provider, which is not
   a choice at all. The entry-point redirect for an unauthenticated protected-resource hit already
   avoids this (`ScopedWebappSecurityChainBuilder#resolveOauthRedirectTarget` sends the user
   straight to `/oauth2/authorization/{id}` when there is only one registration) — direct
   navigation to `/login` was the one path that didn't get the same treatment.

What replaces `DefaultLoginPageGeneratingFilter` as the library default so the picker page can
carry Camunda's own visual identity, and only appears when there is more than one provider to
choose from?

## Decision

Introduce `CamundaLoginPickerFilter` (`io.camunda.security.spring.security`), a `Filter` that:

- Matches `GET` requests to the configured login URL (mirroring
  `LoginLinksBuilder.buildLoginLinks`'s existing prefix handling for scoped chains).
- Builds the `authorizationUrl -> displayName` map via the existing
  `LoginLinksBuilder.buildLoginLinks(...)`.
- Renders a self-contained, Camunda-branded HTML page (inline CSS, no external font or script
  requests — this page must render standalone regardless of a host's CSP allowlist) when **two or
  more** registrations are present.
- **Redirects** straight to the sole provider's authorization endpoint when **exactly one**
  registration is present, instead of rendering a one-link picker. This is a deliberate behavior
  change: `anonymousLoginRendersPickerEvenWithSingleRegistration` is replaced by
  `anonymousLoginRedirectsStraightToSoleProviderInsteadOfRenderingPicker`, asserting a 302 to
  `/oauth2/authorization/{id}` instead of a 200 picker render. This makes direct navigation to
  `/login` consistent with the entry-point's own redirect target resolution.
- Falls through to the rest of the filter chain when zero registrations are present (unreachable
  in practice — every OIDC chain requires at least one provider — but avoids rendering a picker
  with nothing in it).

`ScopedWebappSecurityChainBuilder` installs `CamundaLoginPickerFilter` on both the primary and
per-scope OIDC webapp chains, in the same position `DefaultLoginPageGeneratingFilter` occupied
(`addFilterAfter(..., CsrfFilter.class)`, after CSRF header configuration — see the existing
ordering comment and `csrfTokenResponseHeaderFilterIsRegisteredBeforeLoginPicker`).

### Why these particular boundaries

- **Redirect, not a styled one-link page, for the single-provider case.** A picker offering one
  option isn't a picker. Redirecting reuses the exact destination the entry point already
  resolves to, so the two paths that can reach "let the user get to their IdP" (an auth-triggered
  redirect, and a direct `/login` visit) now agree.
- **`CamundaLoginPickerFilter` replaces `DefaultLoginPageGeneratingFilter` as the
  `ObjectProvider`-anchored override type**, changing
  `ScopedWebappSecurityChainBuilder`'s constructor signature and
  `ScopedWebappSecurityChainBuilderConfiguration`'s bean method signature. This was unavoidable:
  `DefaultLoginPageGeneratingFilter`'s HTML generation is a private, fixed template with no
  extension seam, so no wrapper around it could produce different markup. The new anchor type is
  also more consistent with the two other filter-shaped `ObjectProvider` hooks on this builder
  (`WebAppAuthorizationCheckFilter`, `AdminUserCheckFilter`), which are already CSL's own types
  rather than a reused Spring Security class.
- **Non-`final`, with a `protected renderPickerHtml(Map<String,String>)` hook**, as an explicit
  exception to the "sealed by default" convention: a host wanting different branding subclasses
  `CamundaLoginPickerFilter` and registers its own instance as the `CamundaLoginPickerFilter` bean,
  reusing the matching/gating/redirect logic and overriding only the rendered markup. This
  preserves the override flexibility `hostProvidedLoginPickerFilterOverridesLibraryDefault`
  already tested against `DefaultLoginPageGeneratingFilter` (a host could configure it however it
  liked) without requiring the override anchor to be an arbitrary `Filter`.
- **No external font or stylesheet requests** in the rendered page. It must render correctly
  standalone, before any application shell has loaded, and must not depend on a host's
  Content-Security-Policy allowlisting a font CDN. Inline `<style>` matches the precedent already
  set by `DefaultLoginPageGeneratingFilter` itself (also inline `<style>`), so this introduces no
  new CSP requirement.
- **Provider display names are HTML-escaped** (`HtmlUtils.htmlEscape`) before being written into
  the page: `ClientRegistration#getClientName()` is host-configured, untrusted-enough input to
  treat defensively, and an unescaped name would be a markup/script injection vector into a
  pre-authentication page.

## Consequences

**Positive**

- The multi-IdP login page now carries Camunda's visual identity instead of Spring Security's
  generic default, matching the direction the webapp's own design system
  (`@camunda/design-system`) is moving toward (zinc neutrals, rounded corners, brand-orange
  accent).
- A direct `GET /login` with a single provider now behaves the same as an auth-triggered redirect:
  straight to the IdP, no intermediate page.
- Hosts retain a genuine override point (subclass and register a bean) rather than losing
  customizability entirely.

**Negative / accepted trade-offs**

- This is a breaking change for any host that supplied its own
  `DefaultLoginPageGeneratingFilter` bean to override the picker (as
  `hostProvidedLoginPickerFilterOverridesLibraryDefault` demonstrated was possible): that bean type
  no longer matches the `ObjectProvider<CamundaLoginPickerFilter>` seam, so it is silently ignored
  and the library default is used instead. No host is known to currently do this; if one exists, it
  must migrate to registering a `CamundaLoginPickerFilter` (or subclass) bean.
- `anonymousLoginRendersPickerEvenWithSingleRegistration`'s asserted behavior (render a one-link
  picker rather than redirect) is intentionally reversed. Any downstream test or documentation
  relying on the old behavior needs updating alongside this change.
- The rendered page's branding lives in Java string constants inside `CamundaLoginPickerFilter`
  rather than a template file or the webapp's own component library — acceptable for a small,
  rarely-changed page, but a host wanting pixel-parity with `@camunda/design-system` updates must
  track token changes manually via the subclass hook.

## Alternatives Considered

- **Keep `DefaultLoginPageGeneratingFilter` and only fix the single-provider redirect.** Rejected
  — this addresses the "only render when there's a choice" behavioral request but leaves the
  visual-branding problem this ADR was primarily raised to solve; `DefaultLoginPageGeneratingFilter`
  has no styling hook to fix that separately.
- **A full Spring MVC controller + view instead of a filter.** Rejected — every other host
  extension point on this chain (`WebAppAuthorizationCheckFilter`, `AdminUserCheckFilter`, the
  picker itself previously) is a filter anchored via `addFilterAfter`; a controller would need its
  own `RequestMappingHandlerMapping` wiring and a reason to diverge from that established shape
  that doesn't exist here.
- **Keep the `ObjectProvider` anchor type as `DefaultLoginPageGeneratingFilter` and layer
  Camunda's HTML on top via a wrapping `Filter`.** Rejected — `DefaultLoginPageGeneratingFilter`
  always renders when its internal matcher fires; there is no way to intercept and replace its
  output without either duplicating its request-matching logic anyway (at which point the wrapper
  *is* the real implementation) or fighting its private template method with reflection.
