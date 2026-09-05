import type {IncidentInput} from './engine';
const strings=['product_name','manufacturer','product_type','purpose','customer_impact','awareness_at','corrective_measure_available_at','cra_notification_submitted_at','nis2_notification_submitted_at'] as const;
const bools=['cra_scope_candidate','actively_exploited_vulnerability','severe_security_incident','nis2_entity_candidate','significant_nis2_incident','internet_exposed','critical_service_dependency','supply_chain_exposure','affected_versions_known','sbom_available','exploit_evidence_available','incident_timeline_available','mitigation_documented','owner_assigned','csirt_contact_ready','legal_review_complete'] as const;
const allowed=new Set<string>([...strings,...bools,'cvss_score']);
export function validatePayload(v:unknown):IncidentInput{
 if(!v||Array.isArray(v)||typeof v!=='object')throw new Error('JSON object required');
 const x=v as Record<string,unknown>;const bad=Object.keys(x).filter(k=>!allowed.has(k));if(bad.length)throw new Error(`Unknown fields: ${bad.join(', ')}`);
 for(const k of strings)if(k in x&&typeof x[k]!=='string')throw new Error(`${k} must be a string`);
 for(const k of bools)if(k in x&&typeof x[k]!=='boolean')throw new Error(`${k} must be a boolean`);
 if(typeof x.product_name!=='string'||!x.product_name.trim())throw new Error('product_name is required');
 if(typeof x.purpose!=='string'||x.purpose.trim().length<20)throw new Error('purpose must be at least 20 characters');
 if('cvss_score'in x&&(typeof x.cvss_score!=='number'||!Number.isFinite(x.cvss_score)||x.cvss_score<0||x.cvss_score>10))throw new Error('cvss_score must be between 0 and 10');
 const impact=x.customer_impact;if(impact!==undefined&&!['none','low','medium','high','critical'].includes(String(impact)))throw new Error('invalid customer_impact');
 for(const k of ['awareness_at','corrective_measure_available_at','cra_notification_submitted_at','nis2_notification_submitted_at'] as const){if(typeof x[k]==='string'&&Number.isNaN(Date.parse(x[k] as string)))throw new Error(`${k} must be an ISO date-time`)}
 return x as IncidentInput;
}
