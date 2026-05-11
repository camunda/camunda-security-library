---
status: Accepted
---

# ADR-0011: Lazy-load membership fields on `CamundaAuthentication`

**Deciders**: timcline

## Status

Accepted

## Context

`CamundaAuthentication` (`io.camunda.security.api.model`) is the authentication context produced once per inbound request and consumed across the platform — by authorization checks, tenant access providers, search filters, and broker request converters. It carries the principal (username or clientId), plus four membership lists: `authenticatedGroupIds`, `authenticatedRoleIds`, `authenticatedTenantIds`, and `authenticatedMappingRuleIds`.

Today every host application (e.g. the camunda monorepo's `DefaultMembershipService.resolveMemberships` and `UsernamePasswordAuthenticationTokenConverter.convert`) populates all four lists **eagerly** at authentication time, issuing three or four sequential service calls — group lookup, role lookup, tenant lookup, and (for OIDC) mapping-rule matching — before the request handler ever runs. Most request handlers only read one of those fields; some read none. The eager resolution puts the cost of every consumer on every authentication, which is a measurable latency hit on hot request paths.

The library has no way today to defer those lookups. The record's components are typed `List<String>` and the canonical constructor performs a defensive `List.copyOf(...)`, so the only thing a host can hand the builder is a fully materialised list. Hosts that want lazy memberships have nowhere to plug a `Supplier` in.

Two constraints shape the solution:

1. **The accessor signatures must stay `List<String>`.** Every existing consumer reads `auth.authenticatedGroupIds()` directly. Changing the return type or the method name would ripple across the platform and would not be a library-internal change.
2. **`CamundaAuthentication` must remain a `record`.** AGENTS.md and the rest of `api/model` enforce records for public models; replacing it with a class would establish a new convention for the wrong reason.

The core question:

> What library-level shape lets hosts hand `CamundaAuthentication` a deferred resolver for each membership field, while preserving the record, the public accessor signatures, and the defensive-copy guarantees the canonical constructor provides today?

## Decision

Introduce a `Supplier<List<String>>`-based opt-in lazy path on the existing `CamundaAuthentication.Builder`, materialised through a `LazyList<T> implements List<T>` decorator stored in the same record component the accessor already returns. The record component types, accessor names, and defensive-copy contract are all unchanged; lazy behaviour is smuggled in via the decorator.

Concretely:

- **`LazyList<T>` (package-private, `io.camunda.security.api.model`).** A `List<T>` decorator that wraps a `Supplier<List<T>>`. The supplier is invoked **at most once** on the first read operation; subsequent operations delegate to the memoised list. Mutators throw `UnsupportedOperationException`, matching the immutability contract of the lists returned today. `equals`/`hashCode` materialise. Serialisation goes through `writeReplace` so the wire form is always a plain `List<T>` — lazy state is never observable across a serialisation boundary. Memoisation is thread-safe (volatile double-checked locking or `AtomicReference`-based publishing).

- **`CamundaAuthentication.Builder` gains four supplier methods:** `groupIdsSupplier`, `roleIdsSupplier`, `tenantsSupplier`, `mappingRulesSupplier`, each accepting a `Supplier<List<String>>`. They sit alongside the existing eager `groupIds`, `roleIds`, `tenants`, `mappingRules` methods. Setting both an eager list **and** a supplier on the same field is a programmer error: `build()` rejects it with `IllegalStateException`. (Reasoning: the two paths express different intents, and silently picking one would mask bugs.)

- **`Builder.build()` produces a `LazyList`** for any field with a supplier set, and an eagerly-`List.copyOf`'d list for any field without one.

- **The canonical constructor's defensive-copy helper preserves `LazyList` instances.** A `LazyList` passing through the canonical constructor is returned as-is rather than copied — copying would force materialisation and defeat the entire feature. All other `List` inputs continue to be defensively copied with `List.copyOf(...)` as today.

- **No changes to consumer-facing accessor signatures.** `authenticatedGroupIds()`, `authenticatedRoleIds()`, `authenticatedTenantIds()`, `authenticatedMappingRuleIds()` still return `List<String>`. Consumers iterate, call `.size()`, `.contains()`, etc. — the LazyList materialises transparently on the first such call.

The library exposes the four supplier slots as **independent** — there is no inter-field coordination baked into `CamundaAuthentication`. Hosts that want to share fetched prerequisites across fields (because in their domain, e.g. roles depends on groups+mappings) wire their suppliers behind a shared memoised resolver they own. The library's responsibility ends at "this field is computed on demand."

### Why these particular boundaries

- **Decorator over record-component retyping.** Retyping `authenticatedGroupIds` to `Supplier<List<String>>` would break every caller. Adding parallel `*Supplier` components would expose suppliers as part of the public surface and double the field count. A `LazyList` decorator keeps the public record shape identical.
- **Package-private `LazyList`.** It is an implementation detail of `CamundaAuthentication`, not a general-purpose collection. Hosts interact with it only through the `Supplier` they hand the builder. Exporting it would invite misuse.
- **`Builder` gates rather than constructor gates.** Mixing eager and supplier paths is caught at the only entry point hosts use (`Builder.build()`), keeping the canonical constructor simple and avoiding two failure modes.
- **Memoisation in the library, not the host.** Every host needs the same memoise-on-first-read semantics; pushing it down to `LazyList` ensures consistency and shields hosts from getting it subtly wrong (re-running the supplier per `iterator()` call, etc.).
- **`writeReplace` for serialisation.** `CamundaAuthentication implements Serializable` and is stored in sessions today. Serialising the lazy thunk would couple wire format to host-specific service references; serialising the materialised list keeps the contract stable and forces resolution at the (well-defined) serialisation boundary.
- **Independent supplier slots, not a cascade.** Coupling fields inside the library would force one resolution strategy on every host. Independent slots are a smaller, more orthogonal primitive; hosts that care about shared prerequisites compose them themselves.

## Consequences

**Positive**

- Hosts can defer membership lookups until a consumer actually reads the field. Requests that only check tenants don't pay for role and group lookups.
- No change required at consumer sites — `auth.authenticatedRoleIds()` keeps working unchanged whether the field was constructed eagerly or lazily.
- The record stays a record; the public model surface, immutability guarantees, and accessor signatures are preserved.
- Memoisation lives in one place (`LazyList`), so every host inherits the same thread-safety and once-only semantics.
- Existing eager construction paths (and all existing tests) continue to work unchanged.

**Negative / accepted trade-offs**

- Public surface area grows by four Builder methods. This is the smallest additive surface that expresses the feature, but it does grow the API.
- `LazyList`'s `equals`/`hashCode`/`iterator`/`size`/etc. all trigger materialisation. Code that probes the list shape (e.g. defensive `if (!list.isEmpty())`) materialises just as eagerly as code that consumes it. This is the intended contract — lazy only means "not before first read."
- Independent supplier slots mean hosts whose membership fields share prerequisites must own the cross-field memoisation themselves. The library cannot help them avoid duplicate fetches across fields.
- A supplier set on a field but never read leaves the field unresolved — by design. If a serialised auth crosses a boundary, `writeReplace` forces resolution there; otherwise unresolved suppliers are simply not invoked. Hosts should not rely on the supplier running for its side-effects.
- `LazyList` adds one new class to the `api` module's public bytecode footprint (though it is package-private to consumers).

## Alternatives Considered

- **Retype the record components to `Supplier<List<String>>` and add wrapper accessors.** Rejected. Record accessors are auto-generated from the component name and type; the auto-accessor `authenticatedGroupIds()` would return `Supplier<List<String>>`, breaking every consumer. Even adding a differently-named wrapper accessor still exposes the supplier publicly via the auto-accessor.
- **Add parallel `*Supplier` record components alongside the existing lists.** Rejected. Doubles the component count, requires consumers to know which side to read, and offers no migration path to "supplier wins when set" without runtime branching at every call site.
- **Replace the record with a `final class` that has custom lazy accessors.** Rejected. AGENTS.md mandates records for public models in `api/model`. The benefit (slightly simpler internals) does not justify breaking a project-wide convention or paying the equals/hashCode/toString boilerplate cost.
- **Move lazy resolution into the host (e.g. a per-thread membership cache in the camunda monorepo).** Rejected. Every host that consumes `CamundaAuthentication` would have to reinvent the same pattern, and the laziness would have to be plumbed through a parallel API surface. The accessor on `CamundaAuthentication` is the natural pinch point; that's where laziness belongs.
- **Bundle a single "membership resolver" supplier slot covering all four fields.** Rejected. It hardcodes one resolution strategy (cascade) into the library and prevents hosts from making per-field decisions. The decision to share prerequisites is a host-level optimisation; the library exposes the four slots and lets hosts compose them.
