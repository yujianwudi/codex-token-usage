# Reservation lifecycle and CPA ABI limits

The plugin reserves a protected Codex account slot when `scheduler.pick`
selects it. A terminal `usage.handle` callback attempts to release at most one
active reservation for the same canonical Provider and strict credential/file
identity, regardless of success, failure, token count, or `Generate` value.

## Current compatibility mode

CLIProxyAPI v7.2.80 exposes neither a reservation/request token nor a dedicated
dispatch-failed, cancelled, or request-finalized callback. `UsageRecord` also
has no identifier that can distinguish two otherwise identical requests.

Consequently the current behavior is deliberately named
`legacy_uncorrelated_release`:

- one received terminal callback removes at most one matching reservation;
- strict auth-file identity wins over broader aliases;
- unmatched callbacks are non-fatal and are counted in low-sensitivity
  diagnostics;
- callbacks that never arrive are recovered only by the bounded reservation
  TTL and expiry cleanup;
- duplicate and out-of-order callbacks are **not** exactly-once in this mode.

In particular, a dispatch failure or cancellation that occurs after a
successful scheduler pick but before any usage callback cannot be released
precisely by this plugin alone. Documentation and diagnostics must not claim
otherwise.

## Proposed upstream capability

A minimal CPA extension could add either:

```text
SchedulerPickResponse.ReservationToken
UsageRecord.ReservationToken
```

or a callback such as:

```text
scheduler.release / request.finalize
state = completed | failed_before_dispatch | cancelled | host_shutdown
```

Requirements for token mode:

- the token is opaque and contains no raw credential, path, email, or API key;
- the Host returns it unchanged on every terminal path;
- the reservation table enforces `UNIQUE(provider, reservation_token)`;
- finalization deletes by Provider and token in the same transaction as the
  terminal usage write when applicable;
- repeated or out-of-order finalization is idempotent and can be described as
  exactly-once release;
- capability negotiation keeps older Hosts on the documented aliases+TTL
  compatibility path.

This proposal is an upstream integration requirement, not a private ABI hidden
inside the release plugin.
