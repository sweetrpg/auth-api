---
id: ADR-0001
title: user_roles and service_deny_entries hard-delete (audit-fields carve-out)
status: accepted
date: 2026-09-03
scope: auth-api
supersedes:
superseded_by:
tags: [data, persistence, audit, security]
---

# ADR-0001: user_roles and service_deny_entries hard-delete

Records `auth-api`'s hard-delete carve-out under the platform audit-fields convention, as
`PADR-0027` requires each hard-deleting service to do in its own repo.

## Context

The platform convention (`sweetrpg/platform` `PADR-0001` / `docs/data-conventions.md`) is soft
delete by default: a delete sets `deleted_at` / `deleted_by` and every read filters
`{deleted_at: nil}`. `PADR-0027` carves out **security / authorization control records**, where a
soft-deleted row that a forgotten `{deleted_at: nil}` filter leaves visible is a
privilege-escalation path — a revoked role still returned by one unfiltered query means the user
keeps access.

`auth-api` persists exactly that class:

- `user_roles` — one row per role assignment beyond the default `user` role. `RemoveRole`
  revokes a role.
- `service_deny_entries` — an explicit deny of one subject's access to one service.
  `RemoveDenyEntry` lifts the deny.

Both are read on the authorization hot path (`GET /api/admin/roles/:subject`, and the
`/authz/check` role resolution). They also churn — grants and denies are added and lifted
routinely — so soft delete would accumulate tombstones faster than anywhere else in the
platform.

## Options

- **Option A — soft delete, matching the platform default.** Rejected: makes a missed
  `{deleted_at: nil}` filter on a revoked role grant a silent privilege-escalation bug. A
  security control's failure mode must be "access lost", never "access silently retained".
- **Option B — hard delete, no `deleted_*`, with the existing admin-action audit log as the
  retained deletion record (chosen).** See Decision.

## Decision

`RemoveRole` and `RemoveDenyEntry` remove the document (`DeleteMany` on the
`subject`+`role` / `subject`+`service` match). The models carry `created_at` / `created_by` /
`updated_at` / `updated_by` (required by `PADR-0001`; a row is only ever added or removed, so
`updated_*` equals `created_*`) but **no `deleted_at` / `deleted_by` pair**, and there is no
`{deleted_at: nil}` read filter.

`created_by` / `updated_by` are stamped from the verified acting subject (the admin performing
the grant) on `AddRole` / `AddDenyEntry`.

The "who revoked this access and when" record that hard delete gives up is retained by the
**`admin_action_audit_logs`** collection: every add and remove of a role or deny entry goes
through `performAudited` → `RecordAuditAttempt`, written *before* the mutation (the mutation is
refused if the audit write fails), capturing the acting user, the action (`remove_role` /
`remove_deny_entry`), the target subject, and the timestamp. `CompleteAudit` then transitions
that same row to `succeeded` / `failed` — a status transition by the audit protocol itself, not
a mutation of the who/what/when. No other application path updates or deletes an audit row.

## Consequences

- A revoked role or lifted deny is unrecoverable by design. Re-granting is the only path back.
- The platform-wide "always filter `{deleted_at: nil}`" review checkpoint does not apply to this
  service. A reviewer confirms the delete class from this ADR.
- The deletion record lives in a different collection (`admin_action_audit_logs`) from the
  domain record. An audit query joins on `targetSubject` + `action`, not a tombstone on the row.
- A future `auth-api` collection that is user-owned domain data (not a security control) would
  need soft delete and would not be covered by this ADR.

## Links

- Platform: `sweetrpg/platform` `PADR-0027` (delete strategy by data class), `PADR-0001` (audit
  fields), `openspec/changes/platform-audit-fields-convention` (tasks 9.6, 9.7).
