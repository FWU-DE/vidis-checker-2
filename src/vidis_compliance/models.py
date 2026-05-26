from pydantic import BaseModel, Field
from typing import Literal, Optional, List, Dict

Status = Literal["PASS", "FAIL", "MANUELL"]

class VidisCriterion(BaseModel):
    code: str
    name: str
    description: str
    area: Literal["RDS", "ITS"]
    must: bool = True  # SOLL=false

class CheckFinding(BaseModel):
    criterion: str
    status: Status
    note: str = ""

class JobConfig(BaseModel):
    job_id: str
    target_url: Optional[str] = None
    code_path: Optional[str] = None
    target_audience: Literal["SuS", "Lehrkraefte", "beide"] = "beide"
    pages: int = 8

class JobResult(BaseModel):
    job_id: str
    findings: List[CheckFinding] = Field(default_factory=list)

class CriteriaIndex(BaseModel):
    items: Dict[str, VidisCriterion]
