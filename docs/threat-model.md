# Threat model

| Threat | Public-build response |
|---|---|
| Prompt injection changes legal decision | impossible by design; model is advisory only |
| Fake `admin_override` field | rejected by API schema |
| Malformed/oversized request | rejected |
| Sensitive SBOM upload | warned against; public UI processes summary client-side |
| Wrong scope assumption | output says `scope-review` / `reporting-candidate`, never legal certainty |
| Missed deadline arithmetic | unit-tested 24h/72h calculations |
| Automatic regulator submission | not implemented |
| Silent policy drift between Python/TypeScript | shared labeled fixture + CI |
