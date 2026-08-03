# ADR-001: Shared vNext core with thin IDA runtime adapters

Status: accepted

## Context

The project must support an idalib supervisor and an in-IDA GUI plugin without
allowing their public schemas, safety behavior, persistence, or error handling
to drift. IDA APIs must run on the appropriate IDA thread, while transport,
policy, job, schema, and report code should remain testable without IDA.

## Decision

Keep contracts, policies, authentication, path validation, audit, jobs,
transactions, investigations, and report generation in `ida_pro_mcp.vnext`.
This package has no import-time IDA dependency. Runtime adapters provide
database identity, main-thread execution, checkpoints, capabilities, revisions,
debugger access, and events. Canonical tools are thin facades over this shared
core and the proven low-level IDA operations.

Use one process per idalib database. Every headless tool call is explicitly
scoped by supervisor session ID; the supervisor translates this to the worker's
database identity. Each worker receives an ephemeral credential through its
environment and is terminated with its owning supervisor.

## Consequences

- Pure security and lifecycle behavior can be unit-tested on Python 3.11-3.13.
- GUI and idalib use the same schemas and typed failures.
- Licensed or backend-specific behavior remains capability-gated.
- Some recovery is checkpoint/reopen based because IDA cannot guarantee native
  atomic undo for every operation.
- Legacy implementations remain internal dependencies during one compatibility
  release, reducing regression risk while the public API contracts stabilize.
