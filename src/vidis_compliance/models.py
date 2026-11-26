from pydantic import BaseModel, Field
from typing import Any, Literal, Optional, List, Dict

Status = Literal["PASS", "FAIL", "MANUELL"]

class VidisCriterion(BaseModel):
    code: str
    name: str
    description: str
    area: Literal["RDS", "ITS"]
    must: bool = True  # SOLL=false

Reason = Literal["automated", "needs_review", "not_automated", "missing_input", "not_reachable"]


class CheckFinding(BaseModel):
    criterion: str
    status: Status
    note: str = ""
    # Why the status is what it is; for MANUELL it says what kind of manual work is needed.
    reason: Optional[Reason] = None
    # The check that produced the finding (catalog id), if any.
    check: Optional[str] = None
    # Machine-readable data behind the finding, for a human reviewer or a test suite.
    evidence: Dict[str, Any] = Field(default_factory=dict)
    review_hint: Optional[str] = None
    # Artifact names (API: download links) that hold the full evidence.
    artifacts: List[str] = Field(default_factory=list)

class JobConfig(BaseModel):
    job_id: str
    target_url: Optional[str] = None
    code_path: Optional[str] = None
    target_audience: Literal["SuS", "Lehrkraefte", "beide"] = "beide"
    pages: int = 8

class JobResult(BaseModel):
    job_id: str
    # Contract version that produced this result; None for results from before 1.0.0.
    api_version: Optional[str] = None
    findings: List[CheckFinding] = Field(default_factory=list)

class CriteriaIndex(BaseModel):
    items: Dict[str, VidisCriterion]
