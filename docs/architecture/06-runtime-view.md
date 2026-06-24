## 6. Runtime view (selected scenarios)

This section illustrates selected runtime flows as concrete user journeys, focusing on who performs which action at which point in time.

### 6.1 Admin configures cluster policies in full mode (Hub + OC)

1. Admin logs into the Hub UI.
2. Hub Camunda Security Library authenticates the user against the configured IdP for the Hub organization and derives roles/tenants via mapping rules.
3. Admin creates or updates tenants, roles, mapping rules, and authorizations for a specific Orchestration Cluster in the Hub UI.
4. Hub Camunda Security Library:
- Resolves the organization and target cluster context via `ClusterRegistryPort`.
- Validates and persists the changes in the Hub DB under that organization scope.
- Writes a new `PolicyVersion` and associated `EntityRevision` and `PolicyVersionChange` rows.
- Writes one or more `OutboxEvent`s in status `PENDING` for the affected OCs.
5. Outbox Dispatcher picks up the new events and delivers the full `POLICY_SNAPSHOT` for the target `PolicyVersion` to each affected OC via the configured transport (see `docs/hub-oc-data-propagation.md`).
6. OC Camunda Security Library:
- Applies the full policy snapshot to its local projection and updates `last_applied_version`.
- Propagates engine-scoped changes to engines via the engine command path / Security Engine Framework.

From the admin’s perspective, all policy changes are made centrally in Hub; the OC and engines converge asynchronously.

```mermaid
sequenceDiagram
  actor Admin
  box Hub
    participant HubUI as Hub UI (Console, Web Modeler, Admin)
    participant HubCSL as Hub Camunda Security Library
    participant Outbox as Outbox Dispatcher
  end
  participant IdP as Hub IdP
  participant HubDB as Hub DB
  box Orchestration Cluster
    participant OCSLF as OC Camunda Security Library
    participant Engine as Engine(s)
  end

  Admin->>HubUI: Log in and manage policies
  HubUI->>HubCSL: Authn/authz request
  HubCSL->>IdP: Validate identity and derive roles/tenants
  IdP-->>HubCSL: Token/claims
  HubUI->>HubCSL: Submit policy updates
  HubCSL->>HubDB: Persist policy + PolicyVersion + revisions + propagation events
  Outbox->>HubDB: Read pending events
  Outbox->>OCSLF: Deliver policy snapshot (transport-agnostic, see hub-oc-data-propagation.md)
  OCSLF->>OCSLF: Apply snapshot projection
  OCSLF->>Engine: Propagate engine-scoped changes
```

### 6.2 End user uses the OC UI in full mode

1. User opens the OC UI in the browser.
2. The OC UI delegates authentication to the OC's Camunda Security Library (for example via OAuth2 login flow or existing session cookie).
3. OC Camunda Security Library:
- Redirects or talks to the configured IdP for the user's logical Tenant.
- Validates the returned OIDC/SAML token and derives the principal's roles, groups, and logical-Tenant assignments from mapping rules and direct assignments.
4. For each incoming request from the OC UI:
- OC resolves the logical-Tenant context (from token claims and/or headers).
- Loads the logical-Tenant- and Physical-Tenant-scoped policy view from its local projection (which is synchronized from Hub).
- Evaluates whether the principal has the required permissions on the requested resource (for example reading process instances in a given logical Tenant).
5. If the check passes:
- OC forwards or executes the corresponding operation against the engine(s).
- Engines apply their own runtime-level checks (for example engine-level authorization filters) based on the OC-provided projections.
6. If the check fails:
- OC denies the request and returns an appropriate error to the OC UI.

The user never interacts directly with Hub; Hub’s role is to define the policy that OC enforces.

```mermaid
sequenceDiagram
  actor User
  participant IdP as Customer IdP
  box Orchestration Cluster
    participant OcUi as OC UI (Operate, Tasklist, Admin (view only))
    participant OCSLF as OC Camunda Security Library
    participant SecStore as Secondary Storage
    participant Engine as Engine(s)
  end

  User->>OcUi: Open OC UI
  OcUi->>OCSLF: Start login / present session
  OCSLF->>IdP: Redirect/validate token
  IdP-->>OCSLF: OIDC/SAML token claims
  OCSLF->>OCSLF: Derive roles/groups/tenant assignments

  OcUi->>OCSLF: API request
  OCSLF->>SecStore: Load tenant+engine scoped policy
  OCSLF->>OCSLF: Evaluate permission on requested resource
  alt Authorized
    OCSLF->>Engine: Forward/execute operation
    Engine-->>OcUi: Success response
  else Not authorized
    OCSLF-->>OcUi: Deny request (error)
  end
```

### 6.3 Worker authenticates against cluster APIs

1. A worker application gets a token from the customer’s IdP using the configured client credentials (machine principal).
2. The worker calls OC gRPC/REST APIs with the token.
3. OC Camunda Security Library:
- Validates the token against the IdP.
- Maps its claims to machine principal permissions via mapping rules and authorizations (for example which tenants and which process instances the worker can access).
4. If authorized, the worker’s request is executed against the engine(s); otherwise it is rejected.

The same policy model governs both human users and machine principals.

```mermaid
sequenceDiagram
  actor Worker
  participant IdP as Customer IdP
  box Orchestration Cluster
    participant OCSLF as OC Camunda Security Library
    participant Engine as Engine(s)
  end

  Worker->>IdP: Request token (client credentials)
  IdP-->>Worker: Access token
  Worker->>OCSLF: Call OC gRPC/REST APIs with token
  OCSLF->>IdP: Validate token
  IdP-->>OCSLF: Validation/claims
  OCSLF->>OCSLF: Map claims to machine principal permissions
  alt Authorized
    OCSLF->>Engine: Execute request
    Engine-->>Worker: Success response
  else Not authorized
    OCSLF-->>Worker: Reject request
  end
```

---

