# Architecture

```text
CycloneDX SBOM / incident / vulnerability evidence
                     │
                     ▼
              Input validation
                     │
                     ▼
      Deterministic risk + scope policy
             ┌───────┴────────┐
             ▼                ▼
        CRA candidate     NIS2 DE candidate
             └───────┬────────┘
                     ▼
               Deadline engine
           24h / 72h / final report
                     │
                     ▼
              Evidence readiness
                     │
                     ▼
              Human approval route
                     │
                     ▼
        Draft report / evidence export
                     │
                     ▼
              Append-only audit event
```

## Authority boundary

| Concern | Authority |
|---|---|
| CRA/NIS2 screening | deterministic versioned policy |
| reporting clock | deterministic date arithmetic |
| evidence completeness | deterministic control mapping |
| AI summary | advisory only |
| legal classification | qualified human reviewer |
| external submission | human only |

The Python engine is the canonical reference backend. The Next.js public app mirrors the deterministic contract so it can run with zero keys and no database on a free portfolio deployment.
