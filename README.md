# RegOps EU — Cyber Resilience Operations Platform

> **From vulnerability to regulatory evidence in minutes — with humans in control.**

RegOps EU is a portfolio-safe cyber-resilience operations platform that connects **CycloneDX SBOM evidence, vulnerability/incident triage, CRA + German NIS2 decision support, reporting clocks, evidence readiness, human approval and auditable report drafts**.

The central design rule is deliberate:

> **AI may organise and explain evidence. Deterministic policy owns screening and deadlines. Humans own legal classification and submission.**

## Why this exists

European security teams increasingly need to operationalise cyber-regulatory workflows under time pressure.

- CRA reporting obligations apply from **11 September 2026** for actively exploited vulnerabilities and severe incidents affecting products with digital elements.
- The CRA workflow includes an **early warning within 24 hours** and a **full notification within 72 hours**.
- Germany's NIS2 implementation act has applied since **6 December 2025**; BSIG §32 includes 24h / 72h incident reporting stages and a later final report.
- CycloneDX provides a standardised way to represent SBOM, vulnerability and VEX-style supply-chain evidence.

Official context is documented in [`docs/market-context.md`](docs/market-context.md).

**Important:** RegOps EU is decision-support software. It does not determine legal scope, perform conformity assessment, or submit regulatory notifications.

## Product surface

```text
CycloneDX SBOM / vulnerability / incident
                   ↓
            input validation
                   ↓
        deterministic risk + scope screen
             ↙               ↘
      CRA candidate        NIS2 DE candidate
             ↘               ↙
              deadline engine
           24h / 72h / final
                   ↓
            evidence readiness
                   ↓
            human approval route
                   ↓
        regulatory report draft
                   ↓
              audit history
```

## Interactive command center

`frontend/` is a **Next.js 16 + React 19** command center designed as a live portfolio product rather than a static dashboard.

It includes:

- cinematic scroll/reveal motion
- React Three Fiber cyber-resilience graph
- four synthetic operational scenarios
- editable product/incident context
- CVSS / impact controls
- CRA + NIS2 candidate signals
- CycloneDX JSON upload and client-side summary
- deterministic `/api/analyze` screening
- evidence coverage + missing-control matrix
- 24h / 72h reporting countdowns
- human approval route
- downloadable JSON evidence pack
- browser-local history
- reduced-motion and non-WebGL fallback
- no API key, login or database required for public mode

Run locally:

```bash
npm install
npm run build
npm start
```

## Reference backend

The Python implementation is the canonical reference backend:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

pytest -q
python scripts/evaluate.py
uvicorn api:app --reload
```

API:

```text
GET  /health
POST /v1/analyze
POST /v1/registry
GET  /v1/registry/{case_id}
```

The local backend adds:

- Pydantic validation
- CycloneDX summarisation
- SQLite case registry
- append-only audit events
- deterministic report drafting
- optional local/OpenAI-compatible advisory summarisation

## Verification

Current local verification before first GitHub publication:

| Check | Result |
|---|---:|
| Python unit/governance/API/SBOM/registry tests | **15/15 passed** |
| Synthetic policy regression set | **30/30 passed** |
| Python ↔ TypeScript policy snapshot parity | **30/30 matched** |
| Core TypeScript static check | **Passed** |
| FastAPI production smoke | **Passed** |
| Next.js production build | **Configured for GitHub CI; clean-network CI verification required** |

The 30-case result is a **checked-in synthetic regression result**, not a production detection-rate or legal-classification claim.

## Regulatory decision model

RegOps intentionally outputs cautious states:

```text
CRA
scope-review
no-trigger-detected
reporting-candidate

NIS2 Germany
not-assessed
no-trigger-detected
reporting-candidate

Overall control state
STANDARD_MONITORING
CONTROL_REVIEW
HUMAN_REVIEW_REQUIRED
```

It never outputs:

```text
"Your company is legally required to report."
```

Instead it routes candidate situations to qualified human review.

## CycloneDX

The demo accepts CycloneDX JSON and extracts:

- component count
- vulnerability count
- high/critical vulnerability count
- component names
- vulnerability identifiers

The included `data/demo-bom.cdx.json` is synthetic.

## Business architecture

RegOps EU is intentionally shaped like an open-core B2B product:

**Community / portfolio layer**

- rules engine
- API
- synthetic fixtures
- SBOM parser
- local SQLite registry
- audit trail
- interactive web app
- Docker
- tests + CI

**Commercial evolution**

- tenant isolation
- auth / RBAC
- persistent organisations and products
- GitHub/GitLab SBOM ingestion
- continuous vulnerability monitoring
- alerting
- collaboration
- regulator-specific exports
- managed onboarding / readiness assessments

See [`docs/business-case.md`](docs/business-case.md).

## Security and responsible-AI boundary

The hosted public demo must use synthetic data only. Do not upload confidential SBOMs, embargoed vulnerability details, production incident records, credentials, customer data or personal data.

The optional AI layer is **advisory only**. It cannot modify:

- CRA/NIS2 screening states
- risk score
- evidence requirements
- reporting deadlines
- approval route
- release/submission authority

See [`docs/security.md`](docs/security.md) and [`docs/threat-model.md`](docs/threat-model.md).

## Repository structure

```text
.
├── frontend/                    # Next.js interactive public app
│   ├── app/                     # page + route handlers
│   ├── components/              # motion + 3D command center
│   ├── lib/                     # deterministic TS policy + fixtures
│   └── tests/
├── src/regops/
│   ├── models.py
│   ├── policy.py
│   ├── sbom.py
│   ├── reports.py
│   ├── registry.py
│   └── ai.py
├── data/
│   ├── demo-bom.cdx.json
│   ├── evaluation_cases.json
│   └── python_policy_snapshot.json
├── docs/
├── scripts/evaluate.py
├── tests/
├── api.py
├── Dockerfile
├── docker-compose.yml
├── package.json
├── vercel.json
└── .github/workflows/
```

## Roadmap

1. CRA reporting operations
2. NIS2 Germany workflow depth
3. GitHub / GitLab integration
4. continuous SBOM monitoring
5. vulnerability-feed connectors
6. AI Act / AI-BOM module
7. multi-tenant commercial workspace

## License

MIT

---

**Public-project boundary:** all bundled products, incidents, vulnerabilities and organisations are synthetic. RegOps EU demonstrates product architecture, cyber-resilience workflow design, deterministic governance, testing and implementation quality; it does not claim real production deployment or legal compliance.
