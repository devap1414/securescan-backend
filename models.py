"""
SecureScan AI – Pydantic Models
"""

from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"


class RiskReason(BaseModel):
    source: str = Field(..., description="Which check produced this reason (virustotal, safebrowsing, heuristic)")
    title: str = Field(..., description="Short title, e.g. 'No HTTPS'")
    description: str = Field(..., description="Detailed explanation")
    severity: str = Field(..., description="low, medium, or high")
    score_contribution: float = Field(0, description="How many points this added to the risk score")


class AnalyzeRequest(BaseModel):
    url: str = Field(..., description="The URL to analyze", min_length=1)


class SandboxResult(BaseModel):
    available: bool = False
    is_malicious: bool = False
    malicious_score: int = 0
    screenshot_url: str = ""
    page_title: str = ""
    server_ip: str = ""
    server_country: str = ""
    domain: str = ""
    redirects: list[str] = []
    technologies: list[str] = []
    categories: list[str] = []
    brands: list[str] = []
    details: str = ""
    score: float = 0


class AnalyzeResponse(BaseModel):
    url: str
    risk_score: float = Field(..., ge=0, le=100)
    risk_level: RiskLevel
    risk_reasons: list[RiskReason] = []
    virustotal_positives: int = 0
    virustotal_total: int = 0
    safe_browsing_threats: list[str] = []
    heuristic_flags: list[str] = []
    sandbox_result: Optional[SandboxResult] = None
    domain_age_days: int = -1
    registration_date: str = ""
    registrar: str = ""
    is_new_domain: bool = False
    summary: str = ""

    class Config:
        json_schema_extra = {
            "example": {
                "url": "http://g00gle-login.tk/verify",
                "risk_score": 87.5,
                "risk_level": "dangerous",
                "risk_reasons": [
                    {
                        "source": "heuristic",
                        "title": "Typosquatting Detected",
                        "description": "Domain 'g00gle-login.tk' looks similar to 'google.com'",
                        "severity": "high",
                        "score_contribution": 25,
                    }
                ],
                "summary": "This URL is DANGEROUS. Multiple risk factors detected.",
            }
        }
