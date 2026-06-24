## 11. Technical Debts, Risks, and Open Design Questions

### Open design questions

These are unresolved design questions that require a dedicated ADR before implementation can proceed:

- **SPI boundaries for OC/engine command creation** (`EngineCommandPort`): still open. Webapp, session, user, and scope provider SPI boundaries have been defined (ADRs 0009, 0010, 0017, 0021, 0025, 0027); the engine-command interface is the remaining open design question.
- **Migration path** from current Auth0-based SaaS setup to "Enterprise IdP as SoT" while keeping Auth0 as a private implementation detail — not yet addressed in an ADR.
- **Policy endpoint ownership:** If the endpoints to apply policy changes are public, Hub will not be aware of what a customer applies to OC and will run out of sync. The right ownership boundary is unresolved.
- **Snapshot idempotency:** How can we apply a snapshot multiple times? How could we reset the projections in primary and secondary storage?

### Open issues

- **Multiple Hub instances:** The architecture shows a single shared Hub instance in SaaS and a single Hub in Self-Managed full mode. Some customers require multiple Hub instances (e.g. to separate delivery stages). Each Hub instance is an independent CSL deployment; Hub-to-Hub coordination is out of scope. An OC is associated with exactly one Hub at a time; reassignment is an open design question (see above).
- **Satellite components (open scope):** Two satellite runtimes are not yet explicitly covered by CSL:
  - *App Integrations backend* — not yet decided whether it receives IdP configuration via Hub's CSL port model or manages its own auth independently.
  - *Connectors runtime* — same open question at the OC level.
  - The hexagonal port model accommodates both as future CSL consumers (adapter implementations only, no core change). Whether and when to do this is a scope decision outside this document.

### Known debts

- `EngineCommandPort` SPI boundary for OC → engine policy propagation is still undefined (see Open design questions above).
- The deployment strategy property values currently use an `oc-` prefix (`oc-standalone`, `oc-managed`); a rename to `standalone` / `managed` is planned (docs already use the shorter names).
- ADR numbering has duplicate entries for 0011, 0020, and 0023; a file rename to resolve the ambiguity is deferred.

---

