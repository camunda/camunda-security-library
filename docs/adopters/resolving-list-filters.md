# Resolving list filters over conditional memberships

When a host lists resources, it must show only the ones the caller may see. For a single resource
the host asks `AuthorizationCheckPort`/`ResourceAccessProvider` a yes/no question. For a list, asking
per row does not scale, so CSL resolves the access **once** into a `ResourceAccessFilter` that the
host turns into a query ([ADR-0041](../adr/0041-conditional-memberships.md)).

The filter can carry both plain grants (every resource, or specific resource IDs) and grants that are
gated by a condition on a resource attribute — for example *"editor, but only in workspace
Payments"*. A single result may mix the two.

## The flow

```
host resource  ─(ResourceAttributeExtractor)─►  attribute values  ─┐
                                                                    ├─►  ResourceAccessProvider
caller (CamundaAuthentication) + RequiredAuthorization  ───────────┘      .resolveResourceAccess(...)
                                                                                      │
                                                                                      ▼
                                                                            ResourceAccess.filter()
                                                                       (None / All / AnyOf of terms)
                                                                                      │
                                                            (ResourceAccessFilterTranslator)
                                                                                      ▼
                                                                          the host's own query
```

The filter has three shapes ([`ResourceAccessFilter`](../../core/src/main/java/io/camunda/security/core/authz/ResourceAccessFilter.java)):

- `None` — no access; the host returns an empty list without querying.
- `All` — every resource; the caller holds an unconditional grant on everything.
- `AnyOf` — a set of **terms**, each a resource-ID set and/or attribute conditions. A resource
  matches if it matches at least one term.

## What a host implements

Two SPIs and one call.

### 1. `ResourceAttributeExtractor` — read the attributes off a resource

CSL evaluates conditions only for a resource type that has an extractor, and only against the
attribute values the extractor returns. The attributes are a fixed CSL enum
([`ResourceAttribute`](../../api/src/main/java/io/camunda/security/api/model/authz/ResourceAttribute.java)):
`WORKSPACE_ID` and `PROJECT_ID`. Leave an attribute out when the resource has no value for it —
a condition on a missing attribute is not met ([ADR-0041](../adr/0041-conditional-memberships.md) D4).

### 2. `ResourceAccessFilterTranslator<R>` — turn the filter into a query

`R` is the host's query model (a JPA `Specification`, a jOOQ `Condition`, a SQL fragment, …). CSL
walks the filter and calls back:

| Callback | Meaning |
|---|---|
| `matchAll()` / `matchNone()` | every / no resource |
| `anyOf(List<R>)` / `allOf(List<R>)` | OR / AND of the parts |
| `resourceIds(Set<String>)` | the resource's ID is one of these |
| `attributeEquals(ResourceAttribute, String)` | the resource has this attribute value |

> **A translator that cannot express an attribute must throw, or return `matchNone()` — never
> `matchAll()`.** Widening to "match everything" would grant access the single check denies
> ([ADR-0041](../adr/0041-conditional-memberships.md) D4).

### 3. Resolve and translate at the list endpoint

```java
var caller   = authenticationProvider.getCamundaAuthentication();
var required = RequiredAuthorization.of(b -> b.resourceType(SOME_TYPE).permissionType(SOME_PERM));
var resolved = resourceAccessProvider.resolveResourceAccess(caller, required);

if (resolved.denied()) {
  return emptyPage();                         // None → nothing visible
}
R authzQuery = resolved.filter().translate(myTranslator);
return repository.find(existingFilters.and(authzQuery));  // AND with the host's own filters
```

## Worked example — Camunda Web Modeler (Hub)

Hub lists `File` entities (diagrams) with Spring Data JPA, so `R` is `Specification<File>`. A `File`
lives in a workspace and, usually, a process application. Note the vocabulary offset:

| CSL name | Hub entity | On a `File` |
|---|---|---|
| resource type `FILE` | `File` | the row being listed |
| attribute `WORKSPACE_ID` | `Project` | `File.project` (column `project_id`, always set) |
| attribute `PROJECT_ID` | `ProcessApplication` | `File.processApplication` (column `hub_project_id`, nullable) |

> The `FILE`, `WORKSPACE`, and `PROJECT` resource types are added separately — see
> [ADR-0049](../adr/0049-spring-free-client-for-csl-protected-services.md) and the Hub-types change.
> The code below is illustrative and uses Hub types that live in the Hub repository.

**Extractor:**

```java
@Component
final class FileResourceAttributeExtractor implements ResourceAttributeExtractor<File> {

  @Override public AuthorizationResourceType resourceType() { return AuthorizationResourceType.FILE; }
  @Override public Class<File> resourceClass() { return File.class; }

  @Override public Map<ResourceAttribute, Set<String>> attributesOf(File file) {
    var attrs = new EnumMap<ResourceAttribute, Set<String>>(ResourceAttribute.class);
    attrs.put(ResourceAttribute.WORKSPACE_ID, Set.of(file.getProject().getId())); // always present
    var app = file.getProcessApplication();                                       // nullable
    if (app != null) {
      attrs.put(ResourceAttribute.PROJECT_ID, Set.of(app.getId()));
    }
    return attrs;
  }
}
```

**Translator:**

```java
final class FileAccessFilterTranslator implements ResourceAccessFilterTranslator<Specification<File>> {

  @Override public Specification<File> matchAll()  { return (r, q, cb) -> cb.conjunction(); }
  @Override public Specification<File> matchNone() { return (r, q, cb) -> cb.disjunction(); }

  @Override public Specification<File> anyOf(List<Specification<File>> xs) {
    return xs.stream().reduce(matchNone(), Specification::or);
  }
  @Override public Specification<File> allOf(List<Specification<File>> xs) {
    return xs.stream().reduce(matchAll(), Specification::and);
  }
  @Override public Specification<File> resourceIds(Set<String> ids) {
    return (r, q, cb) -> r.get(File_.id).in(ids);
  }
  @Override public Specification<File> attributeEquals(ResourceAttribute attr, String value) {
    return switch (attr) { // exhaustive: a future attribute won't compile until mapped (fail-closed)
      case WORKSPACE_ID -> (r, q, cb) -> cb.equal(r.get(File_.project).get(Project_.id), value);
      case PROJECT_ID   -> (r, q, cb) -> cb.equal(r.get(File_.processApplication).get(ProcessApplication_.id), value);
    };
  }
}
```

**Call site** — the derived filter ANDs into the same place as Hub's existing visibility filter:

```java
var caller   = authenticationProvider.getCamundaAuthentication();
var required = RequiredAuthorization.of(
    b -> b.resourceType(AuthorizationResourceType.FILE).permissionType(PermissionType.READ));
var resolved = resourceAccessProvider.resolveResourceAccess(caller, required);

if (resolved.denied()) {
  return Page.empty(pageable);
}
Specification<File> authz = resolved.filter().translate(translator);
return fileRepository.findAll(Specification.allOf(existingFilters, authz), pageable);
```

For a caller who is globally in a `viewer` role (grant on file `f9`) and conditionally in `editor`
where `workspaceId = payments`, the filter resolves to:

```
AnyOf([ Term({f9}, []),  Term({}, [WORKSPACE_ID = payments]) ])
            ↓ translate
WHERE file.id = 'f9'  OR  file.project_id = 'payments'
```

## Wiring

- Register the extractor as a bean. CSL's starter then creates a
  [`ConditionalResourceAccessProvider`](../../core/src/main/java/io/camunda/security/core/authz/ConditionalResourceAccessProvider.java)
  automatically (`@ConditionalOnBean(ResourceAttributeExtractor.class)`), unless the host registers
  its own `ResourceAccessProvider` (`@ConditionalOnMissingBean`).
- `@Import` the starter's `AuthorizationConfiguration` (CSL registers no auto-configuration — see
  [ADR-0003](../adr/0003-no-spring-boot-auto-configuration.md)).
- Obtain the caller through the `CamundaAuthenticationProvider` the host already uses for
  authentication.

## Rules to keep correct

- **Fail closed.** A translator that cannot express a term throws or returns `matchNone()`; it never
  returns `matchAll()`.
- **Keep the filter and the single check in step.** The list filter agrees with the per-resource
  check only when the host's stored attributes equal what the extractor computes, for every
  resource. When the host reads both from one model — as in the Hub example, where the extractor
  reads `File.project`/`File.processApplication` and the translator queries the same relationships —
  they cannot drift. The single check also denies a resource with no ID, and a resource whose
  extractor throws gets no conditional role.
- **Property grants are not supported here.** A `RequiredAuthorization` that carries resource
  property names is rejected; those are evaluated by host `PropertyAuthorizationEvaluator` code that
  a filter cannot express.
