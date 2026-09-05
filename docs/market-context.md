# Market context — RegOps EU

RegOps EU is built around a near-term European operational problem: security teams increasingly need to turn vulnerability and incident evidence into auditable, deadline-aware regulatory workflows.

## Cyber Resilience Act

The European Commission states that CRA reporting obligations apply from **11 September 2026**. Manufacturers must report actively exploited vulnerabilities and severe incidents affecting products with digital elements. The reporting workflow includes an early warning within **24 hours** and a full notification within **72 hours**. Final-report timing differs for exploited vulnerabilities and severe incidents.

Official sources:
- https://digital-strategy.ec.europa.eu/en/policies/cra-reporting
- https://digital-strategy.ec.europa.eu/en/policies/cra-summary

The public project therefore treats `reporting-candidate` as decision support only. It does not determine legal scope, submit notifications, or replace qualified counsel.

## Germany / NIS2

Germany's NIS2 implementation act has applied since **6 December 2025**. The BSI portal is the operational registration/reporting route described by the BSI.

German BSIG §32 includes:
- early warning within 24 hours after awareness of a significant security incident;
- incident notification within 72 hours;
- final report generally one month after the 72-hour notification.

Official sources:
- https://mip2.bsi.bund.de/de/info-nis2-registrierung/
- https://www.gesetze-im-internet.de/bsig_2025/__32.html

## SBOM

RegOps EU accepts CycloneDX JSON for the public demo. CycloneDX supports SBOM, VEX and vulnerability reporting use cases, and its official schemas are Apache-2.0 licensed.

Source:
- https://github.com/CycloneDX/specification
