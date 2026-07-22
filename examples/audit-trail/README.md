# Audit trail walkthrough

This example composes the authoritative recorder locally, writes typed events,
creates an RFC 9162 checkpoint, and rebuilds a disposable timeline projection.
It uses ephemeral memory providers and therefore makes no durable assurance
claim.

```bash
npm run example:audit-trail
```

Replace `MemoryAuditJournal` and `MemoryAuditProjectionProvider` with adapters
that pass `@kya-os/mcp/audit/testing` before advertising AAP-2 or above.
