# ADR-0045: Integration tests run against a container, in the verify phase

**DRI**: Joaquín Felici (joaquinfelici)

**Deciders**: Joaquín Felici (joaquinfelici), Bojan Mudric (bmudric), Ben Sheppard (Ben-Sheppard)

**Status**: Accepted (1.2.2)

**Purpose**: Record where the integration tests of CSL run, what they need, and why they live in
this repository.

**Audience**: CSL maintainers, and anyone who runs the build.

## Context

CSL had no integration test. Every test ran in the `test` phase, against a stub identity provider
that this repository owns. The tests with a real identity provider lived in the monorepo
`camunda/camunda`.

[ADR-0044](0044-pkce-through-the-spring-security-default.md) shows the limit of a stub. CSL writes
no PKCE parameters and no token request of its own, so a test of CSL code proves only what CSL
hands to Spring. A stub that CSL also writes cannot refuse a wrong verifier, because nothing in it
knows what a right one is. Task [#809](https://github.com/camunda/camunda-security-library/issues/809)
needs evidence that a public client logs in, refreshes and logs out against a provider that CSL
does not control.

The Engineering DRI of epic [#800](https://github.com/camunda/camunda-security-library/issues/800)
asked whether the absence of such tests here was a decision. It was not, and the team agreed to add
them to this repository on 2026-11-13.

## Decision

**D1. A test that needs a container is an integration test. It is named `*IT` and it runs in the
`integration-test` phase.**

`mvn test` keeps its meaning: fast, no Docker, every unit test. `mvn verify` runs both, which the
contributing guide already names as the command to run before a pull request. The Failsafe plugin
is declared in `spring-boot-starter` alone, because that module holds the Spring wiring that a
container test exercises.

**D2. The identity provider of an integration test is Keycloak in a Testcontainers container, with
a realm this repository imports.**

Keycloak runs locally, and it enforces what a weaker double cannot. It refuses a token request of
the public client that carries no verifier, and it refuses a revoked refresh token. The realm files
hold one client of each type and one user, and the test reads nothing from the admin API, so the
fixture stays a file an engineer can read.

CSL takes no Keycloak module as a dependency. The core `testcontainers` artifact starts the image
and waits for the discovery document of the realm. A module for Keycloak would add a dependency for
three lines of setup.

**D3. A provider that cannot run locally is verified by hand, and not in this build.**

Entra, Auth0, Okta and PingFederate have no local form. Sub-issue
[#811](https://github.com/camunda/camunda-security-library/issues/811) covers them. Whether a
scheduled test against a live tenant is worth its flakiness is a question for the team, and not for
this record.

## Alternatives considered

The team considered these alternatives and rejected each one:

- Keep the tests with a real identity provider in the monorepo. The code under test is here, so a
  failure would surface one repository away from the change that caused it, and after a release.
- Extend the existing stub server with a token endpoint that checks the verifier. The stub would
  then assert what its own author believed PKCE to be. The value of this test is exactly that
  nobody in this repository wrote the other side.
- Run the integration tests in the `test` phase. Every developer without Docker would then lose
  `mvn test`, and the pre-push hook could no longer skip them with `-DskipITs`.
- Start Keycloak once for the whole build, outside the test. A container that the test owns is
  started and stopped with it, and the build needs no step before it.

## Consequences

These results are positive:

- A public client login is proven against a provider that enforces PKCE, and not only against the
  expectations of CSL.
- The tests of the API chains in [#810](https://github.com/camunda/camunda-security-library/issues/810)
  can use the same realm and the same pattern.
- A failure lands in the pull request that caused it.

The team accepts these trade-offs:

- `mvn verify` now needs Docker. A developer without it runs `mvn verify -DskipITs`, which is what
  the pre-push hook passes already.
- The build pulls a container image, so a clean run is slower, and CI needs Docker on the runner.
  The GitHub runner provides it.
- The image tag is pinned in the test. An upgrade of Keycloak is a deliberate change, and a login
  page that changes its form would break the test.

## Source

- Task: [#809](https://github.com/camunda/camunda-security-library/issues/809), decision 2.
- Epic: [#800](https://github.com/camunda/camunda-security-library/issues/800). The Engineering DRI
  agreed to integration tests in this repository on 2026-11-13.
- Related record: [ADR-0044](0044-pkce-through-the-spring-security-default.md).
