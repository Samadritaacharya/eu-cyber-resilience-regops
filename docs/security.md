# Security posture

The public demo is intentionally **synthetic and non-production**.

## Controls
- reject unknown API fields
- reject malformed/primitive JSON
- bounded request sizes in Next.js route handler
- Pydantic validation in FastAPI
- no secrets required for public mode
- no external infrastructure mutation
- no autonomous regulatory submission
- no real vulnerability feed required
- SQLite only for local reference backend
- optional local model cannot change deterministic outputs

## Data rule
Do not upload confidential SBOMs, real incident reports, customer data, vulnerability embargo material, credentials or personal data to the public demo.

## Threat model highlights
- prompt injection cannot alter regulatory routing because policy is not model-controlled;
- malformed JSON and unknown fields fail closed;
- public web history remains in browser local storage;
- external reporting requires an explicit human-controlled step that is not implemented in the public demo.
