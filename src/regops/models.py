from __future__ import annotations
from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field, ConfigDict

CRAStatus = Literal['scope-review','no-trigger-detected','reporting-candidate']
NIS2Status = Literal['not-assessed','no-trigger-detected','reporting-candidate']
Decision = Literal['STANDARD_MONITORING','CONTROL_REVIEW','HUMAN_REVIEW_REQUIRED']

class IncidentInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    product_name: str = Field(min_length=1, max_length=200)
    manufacturer: str = Field(default='Demo Manufacturer', max_length=200)
    product_type: str = Field(default='software', max_length=100)
    purpose: str = Field(min_length=20, max_length=3000)
    cra_scope_candidate: bool = True
    actively_exploited_vulnerability: bool = False
    severe_security_incident: bool = False
    nis2_entity_candidate: bool = False
    significant_nis2_incident: bool = False
    internet_exposed: bool = True
    customer_impact: Literal['none','low','medium','high','critical'] = 'medium'
    critical_service_dependency: bool = False
    supply_chain_exposure: bool = False
    cvss_score: float = Field(default=7.5, ge=0, le=10)
    affected_versions_known: bool = False
    sbom_available: bool = False
    exploit_evidence_available: bool = False
    incident_timeline_available: bool = False
    mitigation_documented: bool = False
    owner_assigned: bool = False
    csirt_contact_ready: bool = False
    legal_review_complete: bool = False
    awareness_at: datetime | None = None
    corrective_measure_available_at: datetime | None = None
    cra_notification_submitted_at: datetime | None = None
    nis2_notification_submitted_at: datetime | None = None

class Deadline(BaseModel):
    label: str
    due_at: datetime
    hours_from_awareness: float | None = None
    legal_basis: str

class ScreeningResult(BaseModel):
    cra_status: CRAStatus
    nis2_status: NIS2Status
    decision: Decision
    risk_score: int
    reasons: list[str]
    required_evidence: list[str]
    missing_evidence: list[str]
    approval_route: list[str]
    deadlines: list[Deadline]
    report_sections: list[str]
    policy_version: str = '2026.09'
    legal_notice: str = 'Decision-support screening only; not a legal determination or regulatory submission.'

class SBOMSummary(BaseModel):
    format: str
    spec_version: str | None
    components: int
    vulnerabilities: int
    high_or_critical: int
    component_names: list[str]
    vulnerability_ids: list[str]
