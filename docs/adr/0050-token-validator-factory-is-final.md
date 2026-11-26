# ADR-0050: `TokenValidatorFactory` is final, and hosts add token checks through extra validators

**DRI**: Sebastian Bathke (megglos)

**Deciders**: Sebastian Bathke (megglos), Patrick Wunderlich (p-wunderlich)

**Status**: Accepted (1.4.0)

**Purpose**: Defines how a host adds its own access-token checks, now that the scoped decoders use the factory of the host.

**Audience**: CSL maintainers, and OC and Hub engineers who add access-token checks.

## Context

[ADR-0006](0006-multi-idp-oidc-configuration.md) lets a host replace `TokenValidatorFactory` with its own `@Bean`. Its consequences also say that a host overrides `TokenValidatorFactory` to get a clock skew per registration. That path needs a subclass, because only `createTokenValidator` sees the registration.

Since [#882](https://github.com/camunda/camunda-security-library/issues/882), the scoped decoders take the clock skew and the extra validators from the factory of the host. `withProviders` gives each scope a copy of that factory. The copy is a `TokenValidatorFactory`, not a subclass. A subclass with its own `createTokenValidator` therefore loses its checks on every scoped decoder. Nothing reports this. The scoped decoders accept tokens that the host wants to reject.

No consumer subclasses the class. `camunda/camunda` and `camunda/camunda-hub` only construct it. Only two test doubles in CSL were subclasses. The repository rule says that a production class is final, unless it is an intentional extension point.

## Decision

**D1. `TokenValidatorFactory` is final.**
It is not an extension point. A host cannot subclass it.

**D2. A host adds access-token checks through the extra validators of the factory.**
The host gives them to the constructor of its `@Bean TokenValidatorFactory`, as ADR-0006 describes. The global decoder and every scoped decoder apply them.

**D3. A clock skew per registration needs a change in CSL.**
D3 replaces one sentence in the consequences of ADR-0006: "hosts needing per-registration skew override `TokenValidatorFactory`". All other decisions of ADR-0006 stay in force.

## Alternatives considered

**Keep the class open, and tell subclasses in the Javadoc to also override `withProviders`.**
Rejected. A subclass that misses this note loses its checks on the scoped decoders, and nothing reports it. A security check must not fail open because a developer missed a note.

**Let `withProviders` copy a subclass, for example through a protected copy method.**
Rejected. This adds an extension contract that no consumer uses.

## Consequences

- This is a breaking change. A subclass of `TokenValidatorFactory` does not compile with CSL 1.4.0. No known consumer has one.
- The scoped decoders apply the same host checks as the global decoder. A host cannot lose a check through a subclass.
- A host cannot set a clock skew per registration. This gap existed before. Now a host also cannot use a subclass for it.
- Tests that need a special factory use a Mockito mock. Mockito 5 mocks final classes by default.

## Source

- [#882](https://github.com/camunda/camunda-security-library/issues/882): scoped decoders ignore the extra validators and the clock skew of the host.
- [#883](https://github.com/camunda/camunda-security-library/pull/883): the fix, and this decision.
- [ADR-0006](0006-multi-idp-oidc-configuration.md): partially superseded by D3.
