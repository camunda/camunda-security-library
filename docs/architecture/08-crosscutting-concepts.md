## 8. Crosscutting concepts (target)

- IdP-agnostic: Any OIDC/SAML IdP integrating via standards (no IdP-specific code in the domain layer).
- RBAC + ABAC: Roles and authorizations with optional attribute-based policies (resource attributes, environment conditions).
- Multi-tenancy: Tenant-aware identity context propagated from tokens/headers; tenant-specific policy and IdP configuration; propagation filters by tenant.
- Lifecycle handling: Principal and tenant assignment are derived from IdP claims and mapping rules; clusters receive derived principals and policies from Hub.
- Observability: Identity flows emit metrics, logs, and traces (e.g. authn attempts, authz decisions, propagation delay, health indicators). For Spring Security instrumentation, align with the Spring Security observability integration guidance: https://docs.spring.io/spring-security/reference/reactive/integrations/observability.html

### 8.1 Scalability and operational considerations

The unified identity architecture must support SaaS deployments at significant scale:

**Current operational metrics (SaaS):**
- Approximately 47,000 organizations
- Approximately 24,000 users who have accepted invitations into SaaS
- Largest single organization successfully onboarded ~200 users
- Approximately 43,000 total clusters created across all organizations

**Implications for Hub and OC:**

1. **Policy propagation scale**: Hub must reliably propagate policy changes to 43k+ clusters without overwhelming either Hub or OC infrastructure.
2. **Visibility and monitoring**: At this scale, operators must be able to track policy rollout state across thousands of clusters in real time. Hub must surface which clusters are on which policy versions, and what delivery state each cluster is in (pending, delivered, failed, retrying).
3. **Rate limiting and backpressure**: Both push-based and pull-based propagation require careful handling of load spikes:
  - Push: Hub propagation dispatcher must respect OC capacity and not flood clusters with simultaneous policy updates.
  - Pull: OCs must not synchronize polling (thundering herd problem) to avoid overwhelming Hub with simultaneous policy version queries.
4. **Idempotency**: At this scale, retries are frequent and necessary. All policy applies must be idempotent per `policyVersionId` to ensure correctness despite network failures and replay scenarios.
5. **Observability requirements**: Logs, metrics, and traces must emit at a reasonable volume even with 43k+ clusters. Per-cluster granular logging is necessary for debugging but must be carefully sampled or aggregated for operational dashboards.

These constraints directly inform the choice and implementation details of ADR-0003 (Push vs Pull Policy Propagation); see section 9.1 for detailed analysis.

---

