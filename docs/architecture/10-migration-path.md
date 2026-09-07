## 10. Migration path

Authentication has already migrated to CSL across Hub, OC, and Optimize — see
[rollout status](./02-current-state.md#21-rollout-status-at-a-glance). What is still migrating is
authorization: moving Hub and Optimize authorization off Management Identity, building the OC
authorization write path, and wiring Hub → OC/Optimize policy distribution.

The migration path from the current split identity systems (Auth0 in SaaS, Management Identity, and OC Identity in Self-Managed) to the unified Camunda Security Library — across Hub, OC, and Optimize — is documented in a dedicated file:

- **[Migration Path](../migration_path.md)**

---

