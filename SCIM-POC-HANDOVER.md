# SCIM POC Handover

Status: handover from a research/scoping session (2026-10-14). The user will give you further
instructions; this document is context, not a task list. Treat the recommendations below as the
user's starting position, not as a decided design. Nothing has been built or verified by running
code. No ADR has been written yet.

## Goal

Build a proof of concept of an **in-house SCIM 2.0 layer for the Camunda Security Library (CSL)**:
`/Users` and `/Groups` endpoints, plus discovery, with JSON marshalling, RFC-conformant validation,
and an outbound repository port the host implements. The Ping/UnboundID SCIM2 SDK is to be used
**as a reference** (read its code and tests for guidance), not as a runtime dependency, unless the
user says otherwise.

CSL's own docs already anticipate this: `docs/architecture/01-introduction.md` says "SCIM is planned
as another inbound port/adapter on top of the same library." No SCIM code or ADR exists yet.
The highest existing ADR is 0034, so the next is 0035.

## Read first (CSL rules that constrain the design)

Read `CLAUDE.md`, `AGENTS.md`, `.claude/docs/architecture.md`, `conventions.md`, `guardrails.md`,
`workflow.md`. The ones that matter most here:

- **`core` must have no Spring, Servlet or Jackson dependency**, not even `jackson-annotations`.
  Domain records stay serialization-free; JSON shape for core types is done by a mixin or a mapper
  in the host/starter (precedent: ADR-0014, OC's `MsgPackConverter.CamundaAuthenticationMixin`).
  Enforced by ArchUnit (`DomainArchTest`).
- Hexagonal naming: interfaces are always `*Port` (`port/in/`, `port/out/`); inbound
  implementations are `*Service`; outbound implementations are `*Adapter`; never `*Impl`.
- Models are records. Production classes are `final` unless they are deliberate extension points.
- **No auto-configuration** (ADR-0003). Configuration classes are plain `@Configuration`, activated
  by explicit `@Import`, every default bean has `@ConditionalOnMissingBean`, and a new
  configuration class must also be added to the umbrella `CamundaSecurityAutoConfiguration`'s
  `@Import` list and to `CamundaSecurityAutoConfigurationTest`.
- `core` has no notion of a physical tenant, only an opaque *scope* key (ADR-0013). Don't introduce
  tenant-flavored names in `core`.
- Domain exceptions propagate out of ports unchanged; transport translation (here: SCIM error JSON)
  is the caller's job. Outbound adapters must not leak infrastructure exceptions.
- Logging: SLF4J only, include entity IDs and the operation in WARN/ERROR, **never log PII or
  secrets**. SCIM payloads are full of PII (names, emails), so do not log request or response
  bodies.
- Every new class needs tests. Contract tests (Pact) for APIs. Run `mvn verify` before claiming
  completion. Spotless/Google Java Format runs in the pre-commit hook.
- Adding a port/adapter/dependency or a project-wide convention requires an ADR (use the `/adr`
  skill; `docs/workflows/adr.md`). User-visible changes need a camunda-docs note in the PR.
- Commit/branch conventions: Conventional Commits, `<type>/<short-description>` branches.

## Repo facts observed

- Modules: `api`, `core`, `spring-boot-starter` (plus `config`, `validation`; a non-Spring
  `adapters` module is planned).
- Existing ports in `core/.../port/in`: `AuthorizationCheckPort`, `CamundaUserPort`,
  `ClusterRegistrationPort`, `OidcProviderConfigurationPort`, `PolicyApplyPort`, `PolicyPort`,
  `TenantPort`. In `port/out`: `MembershipPort`, `PolicyRepositoryPort`, `IdpClientPort`,
  `SecurityPathPort`, `AuthorizationScopeRepositoryPort`, `BasicAuthUserDetailsPort`, among others.
  Read these before designing SCIM ports so you reuse existing concepts (Principal, Group,
  membership) instead of duplicating them. `api/model/user/` has only `CamundaUserDTO`.
- This is the first **write-side** identity surface. Existing user/group ports are read-oriented.
  Settle how SCIM relates to the existing policy/authoring model (see open questions).
- Stack: Java 21, Spring Boot **4.1.1** (BOM in root `pom.xml`), Maven.
- `spring-boot-starter/pom.xml` has `spring-web`, `jackson-core`/`jackson-databind` declared with
  the **Jackson 2 coordinates** (`com.fasterxml.jackson.core`), `jakarta.servlet-api`, the Spring
  Security OAuth2 resource server, and `spring-boot-starter-validation`. It does **not** have
  `spring-webmvc`.
- The Jackson version point is unresolved (see pitfalls).

## What the research found

### SCIM background

- SCIM 2.0 is RFC 7642 (concepts), 7643 (schema), 7644 (protocol), 2015, and is still the current
  major version. There is no SCIM 2.1 or 3.0. Additive extensions published since: RFC 9865
  (cursor-based pagination, Oct 2025), RFC 9967 (SCIM profile for Security Event Tokens, May 2026),
  RFC 9944 (device schema; the Ping SDK's CHANGELOG lists it for 6.1.0). A draft for agents
  exists. None break existing implementations. I did not read the RFC texts in this session; check
  the RFCs directly for exact requirements.
- SCIM is a provisioning protocol. It is **orthogonal to login auth** (basic vs OIDC). It only
  needs the SCIM endpoint itself secured, almost always with an OAuth2 bearer token. The only
  coupling to SSO is identifier matching: SCIM `userName`/`externalId` must line up with the SSO
  subject, NameID or email claim.
- Core mandatory attributes: User needs only `userName` (unique); Group needs only `displayName`;
  every resource has server-assigned `id` and `meta`; payloads carry a `schemas` array. Required
  sub-attributes apply only when the parent is present (for example `emails[].value`). Almost
  everything else is optional in the spec.
- De facto baseline that all major IdPs (Okta, Entra, OneLogin, Google, JumpCloud, Ping) send:
  `userName`, `externalId`, `active` (the soft-delete/deprovision mechanism), `name.givenName`,
  `name.familyName`, `displayName`, `emails[]` (with `primary`/`work`), plus Group `displayName`
  and `members[].value`. Beyond that (title, phoneNumbers, locale, Enterprise extension fields)
  is configurable per tenant. This baseline comes from general knowledge, not from vendor docs
  read this session. **Verify against current Okta and Entra docs.**

### Existing Java libraries (state as of 2026-10-14)

Sources were the GitHub API and Maven Central metadata. Nobody ran or compiled any of them, and
nobody verified RFC conformance of any filter or PATCH implementation.

| Library | Finding |
|---|---|
| Apache SCIMple | Active (about 236 commits in 12 months) but no GA release (newest tag `v1.0.0-M2`, Feb 2025; Maven Central lists only M1). Server is Jakarta RS/CDI. Its Spring Boot starter runs on Jersey (builds against Boot 3.5, tests on 4.1). Ties you to a JAX-RS server. Not a fit as a whole. |
| Ping/UnboundID scim2 | Most healthy. 6.0.0 released 2026-05-11, monthly commits. `scim2-sdk-common` (model, filter parser, PATCH) depends only on Jackson per its pom, with no JAX-RS. `scim2-sdk-server`/`-client` pull in Jersey. 6.x uses Jackson 3 (`tools.jackson`). Reference choice for this POC. |
| BetterCloud/scim2 | Fork of Ping with a Spring Boot starter. Dormant since 2024-06, no releases. Do not use. |
| Captain-P-Goldfish/SCIM-SDK | 1.35.0 (Aug 2026), BSD-3, embeddable (`-server`/`-common`/`-client`), has a `1.35.0-jackson3` build and a ResourceHandler SPI. Opinionated schema-driven framework. Candidate secondary reference. |
| WSO2 Charon | Java 21, active; `charon-core` has a generated filter parser and `PatchOperationUtil`. License unconfirmed. Secondary reference. |
| Apache Syncope scimv2 | Not embeddable. Contains `SCIMFilter.g4` (ANTLR4 filter grammar, Apache-2.0) with `SCIMFilterTest`. Useful as a grammar reference. |
| Keycloak extensions, Personify, SAP scimono, Gravitee | Extensions/clients, stale, archived, or nonexistent. Ruled out. |

Not found in any of them: support for RFC 9865 or RFC 9967 (the SCIMple search for "9865" had zero
hits; the others were not checked).

## Proposed architecture (starting position, to be confirmed with the user)

| Layer | Contents |
|---|---|
| `api` | Public SCIM-facing records if hosts need them; SCIM config record in `api/model/config`. |
| `core` (framework-free) | Inbound ports (`ScimUserPort`, `ScimGroupPort`), outbound ports (`ScimUserRepositoryPort`, `ScimGroupRepositoryPort`), domain types and exceptions (for example uniqueness, not-found, invalid-filter, invalid-path, mutability), the resource/schema model and attribute characteristics, validation, the **filter AST and parser**, and the **PATCH engine**. All pure Java. |
| `spring-boot-starter` | `ScimConfiguration` (explicit `@Import`, `@ConditionalOnMissingBean`), Spring MVC controllers, JSON mapping (mixins or a handwritten mapper), translation of domain exceptions to SCIM error JSON, security chain for `/scim/v2/**`. |

Work breakdown, in rough order:

1. Resource model and schema registry: User, Group, EnterpriseUser, `meta`, extension schemas;
   attribute characteristics (mutability, returned, uniqueness, multiValued, caseExact). Validation
   and PATCH are driven by this.
2. Validation per RFC 7643 (required attributes, `schemas`, read-only handling, types, single
   `primary` in multi-valued attributes, case-insensitive `userName` uniqueness).
3. Filter parser per RFC 7644 section 3.4.2.2: `eq ne co sw ew gt ge lt le pr`, `and or not`,
   grouping, value paths like `emails[type eq "work"]`. Produces an AST. Likely the largest piece.
4. PATCH engine: `add`/`remove`/`replace`, path grammar, omitted `path`, filtered paths, group
   membership patch semantics. Second largest and most error-prone.
5. Protocol semantics: POST/GET/PUT/PATCH/DELETE, search (GET and `POST /.search`), pagination
   (index-based; cursor per RFC 9865 is optional), sort, `attributes`/`excludedAttributes`,
   ETag and `If-Match`, `Location` header, status codes, SCIM error format with `scimType`.
6. Discovery: `/ServiceProviderConfig`, `/Schemas`, `/ResourceTypes`, generated from the registry
   and supported features. Advertise capabilities honestly (for example `bulk` unsupported).
7. Outbound repository ports: domain-typed, with exceptions propagating per CSL rules.
8. Security: separate Spring Security chain for `/scim/v2/**` with OAuth2 resource server bearer
   tokens; decide how provisioning clients are authorized (a dedicated scope/role, or new resource
   types through `AuthorizationCheckPort`); wire `SecurityPathPort`; scope via the opaque scope
   key.
9. Configuration properties and wiring (config record in `api`, binding in the starter, umbrella
   import and its test).
10. Cross-cutting: ADR(s), Pact contract tests, ArchUnit coverage, logging rules, docs note.
11. Conformance testing against real IdP behavior (Okta SCIM validator, Entra provisioning test).

Suggested v1 subset: Users and Groups only, no Bulk, no `/Me`, no custom resource types; search
with a filter subset (`eq`, `and`, `co`, `pr` cover most IdP traffic) with the full grammar
later; cursor pagination optional.

For a POC, a thin vertical slice is probably more valuable than breadth: for example
`POST /Users` and `GET /Users?filter=userName eq "x"` through the controller, the ports, and an
in-memory repository adapter, plus `PATCH` of `active`, so the layering and the JSON strategy are
proven before the rest is built. Confirm the slice with the user.

## Recommended use of the Ping SDK as a reference

- Read `scim2-sdk-common` (github.com/pingidentity/scim2) for the filter parser, the PATCH
  handling and the model, and for the test cases. Use its tests as a source of edge-case ideas
  and, license permitting, conformance vectors.
- Do **not** add it as a dependency of `core`: it requires Jackson, which `core` forbids. If the
  user later wants it as a dependency, it can only live in the starter or an adapter module, which
  forces a second mapping layer (AST and PATCH types converted between the SDK and `core`) and
  needs its own ADR.
- Use the Syncope grammar `SCIMFilter.g4` and the RFC 7644 ABNF as additional references for the
  filter parser. SCIM-SDK and Charon are further references.
- `scim2-sdk-common` licensing and attribution: see the first pitfall.

## Pitfalls and open questions from this session

1. **Ping licensing is unresolved.** One research agent said Apache-2.0 from 5.0.0 (earlier
   versions GPLv2/LGPLv2.1). The other described the repo as multi-licensed
   (Apache-2.0, GPLv2 or LGPLv2.1). GitHub reports NOASSERTION because the license file is custom.
   Nobody read the LICENSE file for 6.0.0. **Read it before copying any code or test data.**
   Reading for reference is fine. Copying is not, until this is settled. Same caution for
   Syncope's grammar (Apache-2.0, needs attribution) and the license of Charon (unconfirmed).
2. **Jackson version is unresolved.** The starter declares `com.fasterxml.jackson.core` (Jackson 2)
   artifacts, while Spring Boot 4 defaults to Jackson 3 (`tools.jackson`), as does Ping 6.x. I did
   not check which versions the Boot 4.1.1 BOM resolves, or how the starter's existing Jackson use
   behaves. Check `mvn dependency:tree` first. It affects the controller/JSON layer regardless of
   build-versus-adopt.
3. **`core` cannot hold JSON annotations.** SCIM extensions and custom schemas cannot be fully
   typed, so core likely needs a neutral representation (typed records plus a generic attribute
   map, or a small tree type). Decide this early; it shapes the repository port.
4. **Whether the repository port sees the SCIM tree or CSL domain records** is the central design
   question. The host could receive the neutral tree and map it, or the library could map to
   `Principal`/`Group` and hand typed records over. How SCIM relates to the existing
   policy/authoring ports (new write ports versus reusing existing ones) is also open.
5. **IdP quirks** that real clients exhibit (from general knowledge, not verified this session;
   confirm against vendor docs and the conformance tools): Entra uses non-standard PATCH
   behavior and path forms by default; some IdPs send `active` as the string `"False"`; group
   membership updates arrive as either full replacement or incremental add/remove; `emails[]`
   `type`/`primary` handling differs. Plan a tolerant mode for these, and make sure strictness
   is a deliberate choice.
6. **`userName` semantics.** It must be unique but its meaning is not fixed (email, UPN, login ID).
   Keep `userName`, `externalId`, the internal key and the SSO subject separate, and decide how
   they are matched.
7. **Do not log SCIM bodies.** Full of PII. Log IDs and operation names only.
8. **No RFC conformance claim holds for any surveyed library.** Do not assume the Ping parser is
   correct on nested value-path PATCH, `pr`, or complex filters. Write your own tests from the RFC
   examples.
9. **No `spring-webmvc` in the starter yet.** Adding controllers means adding a dependency (needs
   justification under the "no unused dependencies" rule and likely an ADR note). Consider whether
   controllers belong in the starter or in a new module.
10. **RFC 9865/9967 are out of scope for v1** unless the user says otherwise. None of the surveyed
    libraries support them, so there is no reference to copy.
11. **Unverified research.** The library survey used GitHub API and Maven Central metadata only; the
    agents did not compile samples or read filter/PATCH source. Treat statements about "usable
    standalone" as claims to verify (for example by a small spike) before relying on them.

## Suggested first steps (adjust to the user's instructions)

1. Read the CSL docs listed above and the existing ports and `api/model/user`.
2. Run `mvn dependency:tree -pl spring-boot-starter` and settle the Jackson question.
3. Read the Ping `scim2-sdk-common` LICENSE and note what may and may not be reused.
4. Propose the neutral-model and port design, and the POC slice, to the user before coding.
5. Draft ADR 0035 (SCIM layering, JSON strategy, build versus adopt) using `/adr`.
6. Build the POC slice with tests, and run `mvn verify`.
