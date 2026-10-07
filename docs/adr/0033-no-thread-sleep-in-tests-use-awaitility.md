---
status: Accepted
---

# ADR-0033: No `Thread.sleep` in tests; wait on conditions with Awaitility

**Deciders**: Ben Sheppard

## Status

Accepted

## Context

Tests that touch background work (schedulers, async refreshes, concurrent callers) need to wait
for something to happen. A fixed `Thread.sleep` is either too short, so the test is flaky on a
slow CI machine, or too long, so every run pays an unnecessary delay. It also says nothing when it
fails: the assertion after the sleep reports the symptom, not what was being waited for. The
review of the JWKS refresh work (#707) found several of these in new tests, and the Camunda
Orchestration Cluster codebase already discourages them for the same reasons.

What should tests do instead of sleeping while they wait for asynchronous behaviour?

## Decision

Tests do not call `Thread.sleep` to wait for something to happen.

- **Wait on a condition.** Use [Awaitility](https://github.com/awaitility/awaitility)
  (`await().atMost(...).until(...)` / `untilAsserted(...)`) with a generous upper bound. The test
  continues as soon as the condition holds, and a failure names the condition that was never met.
- **Control the event instead of waiting for it.** Where the test owns both sides, use a
  `CountDownLatch` or similar to force the interleaving (for example, a fake endpoint that holds
  its response until the test releases it) rather than hoping a delay is long enough.
- **Injected time over real time.** Where production code accepts a clock, pass a controllable one.

`org.awaitility:awaitility` is added as a `test`-scope dependency of `spring-boot-starter`; its
version is managed by the Spring Boot BOM. The rule is recorded in `AGENTS.md` and
`.claude/docs/conventions.md` so humans and agents see it.

## Consequences

**Positive**

- Fewer flaky tests, and no fixed delays added to every build.
- Failures point at the unmet condition.

**Negative / accepted trade-offs**

- One more test dependency to keep in sync with the BOM.
- A condition-based wait still has an upper bound, so a test of "something eventually happens"
  can still time out on a very slow machine; the bound is chosen to be generous.
- Simulating a slow remote endpoint is no longer done with a timed delay, so a test cannot assert
  that a specific wall-clock latency is tolerated. Such properties are pinned through the configured
  timeout values instead.

## Alternatives Considered

- **Keep `Thread.sleep` where it is "obviously enough".** Rejected — the margin is a guess, and it
  either flakes or wastes time.
- **Hand-rolled polling loops.** Rejected — Awaitility already provides bounded polling with a
  readable failure message.
- **Ban the call with a build-time check.** Rejected for now — the convention is enough while
  occurrences are rare; a check can be added if they reappear.
