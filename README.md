# Camunda Security Library (CSL)

The Camunda Security Library is a unified identity and authorization library for the [Camunda 8](https://camunda.com/) platform. It replaces two separate identity stacks — OC Identity (embedded in each Orchestration Cluster) and Management Identity (a standalone service for Web Modeler, Console, and Optimize) — with a single, shared implementation.

## Why

Camunda currently maintains two independent identity stacks that solve the same problem in different ways. This creates real costs:

- **Capability gaps** — identity features are implemented twice, or only in one stack, creating inconsistencies that confuse customers and generate avoidable support tickets.
- **Silent configuration drift** — configuration that works in one stack can silently fail or behave differently in the other, leading to long debugging cycles.
- **Double maintenance burden** — two codebases to test, maintain, and audit for compliance, with behavior diverging over time.
- **Integration friction** — Hub integration would require a third implementation path unless the underlying stacks are unified first.

The CSL solves this by implementing authentication, authorization, policy authoring, and policy propagation once. Hub and every Orchestration Cluster embed the same library, configured for their deployment context.

For customers: one set of concepts, one configuration surface, one place to look when something goes wrong.
For the platform team: one codebase to maintain, one security surface to audit, one upgrade path.

## Architecture

The CSL is a **hexagonal (ports and adapters) Spring Boot library** embedded into host applications (Hub, Orchestration Clusters). All persistence, IdP clients, engine commands, and outbox delivery sit behind port interfaces defined in the library core. Host applications provide adapter implementations.

No host-specific code leaks into the library domain. Swapping a database, replacing an IdP client, or adding a new deployment topology requires only a new adapter.

### Deployment Strategies

Active capabilities are selected via a **deployment strategy configuration property** (not Spring profiles):

| Strategy | Policy Authority | Authoring | Outbox Dispatch | Engine Projection |
|---|---|---|---|---|
| `oc-standalone` | OC (local source of truth) | Yes | No | Yes |
| `oc-managed` | Receives from Hub | No (read-only) | No | Yes |
| `hub` | Hub (central source of truth) | Yes | Yes | No |

Authentication and authorization enforcement is **always active** in every strategy.

### Unified Policy Model

A single policy model is shared across Hub and all Orchestration Clusters:

- **Organization** — top-level tenant boundary
- **Tenant** — logical isolation within an organization
- **Role** — a named set of permissions
- **Group** — a collection of principals
- **Mapping Rule** — maps external identity attributes to internal roles/groups
- **Principal** — a user or machine identity
- **Authorization** — a granted permission scoped to a resource

Authorizations can be scoped at four levels: `ALL`, `TENANT`, `ENGINE`, or `TENANT_ENGINE`.

## Getting Started

The library ships as a Spring Boot starter. Hosts include the artefact, set a few properties, and the central security filter chains plus their dependencies (JWT decoder, OAuth2 client beans, default failure handler) wire automatically.

```xml
<dependency>
  <groupId>io.camunda</groupId>
  <artifactId>camunda-security-library-spring-boot-starter</artifactId>
  <version>${camunda.security.library.version}</version>
</dependency>
```

```yaml
camunda:
  security:
    authentication:
      method: oidc                                            # or "basic"
      oidc:
        issuer-uri: https://login.example.com/realms/camunda
        client-id: camunda-app
        client-secret: ...
```

The only mandatory host-supplied bean is a `SecurityPathAdapter` that declares which paths are API, webapp, and unprotected. Everything else — JWT decoder, client registration, OAuth2 client manager, RFC 7807 problem-detail failure handler — is library-supplied with `@ConditionalOnMissingBean` so hosts override any layer by registering their own bean.

See [`docs/adopters/security-filter-chains.md`](docs/adopters/security-filter-chains.md) for the full configuration reference, extension hooks, and migration guide. Design rationale lives in [ADR-0006](docs/adr/0006-central-security-filter-chains.md).

## Related

- [Tracking issue — camunda/product-hub#3607](https://github.com/camunda/product-hub/issues/3607)
- [Architecture vision — camunda/camunda#49865](https://github.com/camunda/camunda/issues/49865)
- [Common Identity Stack — camunda/product-hub#3412](https://github.com/camunda/product-hub/issues/3412)

## License

This project is licensed under the [Camunda License](https://legal.camunda.com/).
