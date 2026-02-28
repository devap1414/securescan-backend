"""
SecureScan AI – FastAPI Backend
Main application entry point with /analyze endpoint.
Orchestrates VirusTotal, Google Safe Browsing, and Heuristic analysis.
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
import httpx as httpx_sync
from models import AnalyzeRequest, AnalyzeResponse, RiskLevel, RiskReason, SandboxResult
from config import (
    WEIGHT_VIRUSTOTAL,
    WEIGHT_SAFE_BROWSING,
    WEIGHT_HEURISTIC,
    SAFE_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
)
from services import virustotal_service, safe_browsing_service, heuristic_analyzer, sandbox_service, domain_age_service

import asyncio
import time as _time
import re

app = FastAPI(
    title="SecureScan AI",
    description="Phishing & Malware Link Detection API",
    version="1.0.0",
)

# Allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _is_valid_url(url: str) -> bool:
    """Basic URL validation."""
    pattern = re.compile(
        r"^(https?://)?"
        r"("
        r"([a-zA-Z0-9_-]+\.)+[a-zA-Z]{2,}"
        r"|"
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
        r")"
        r"(:\d+)?"
        r"(/.*)?$"
    )
    return bool(pattern.match(url))


@app.get("/")
async def root():
    return {
        "name": "SecureScan AI",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "/analyze": "POST - Analyze a URL for threats",
            "/health": "GET - Health check",
            "/docs": "GET - Interactive API documentation",
        },
    }


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_url(request: AnalyzeRequest):
    """
    Analyze a URL for phishing, malware, and other threats.
    Combines results from VirusTotal, Google Safe Browsing, and heuristic analysis.
    """
    url = request.url.strip()

    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    if not _is_valid_url(url):
        raise HTTPException(status_code=400, detail="Invalid URL format")

    # --- Run ALL checks concurrently for maximum speed ---
    _t0 = _time.perf_counter()

    # Sandbox runs in background – does NOT block the response
    sandbox_result = {
        "available": False,
        "is_malicious": False,
        "malicious_score": 0,
        "screenshot_url": "",
        "page_title": "",
        "server_ip": "",
        "server_country": "",
        "domain": "",
        "redirects": [],
        "technologies": [],
        "categories": [],
        "brands": [],
        "details": "Sandbox analysis runs in background. Scan again in ~30s for full results.",
        "score": 0,
    }

    # Heuristic runs synchronously (no I/O, instant)
    heuristic_result = heuristic_analyzer.analyze_url(url)

    # --- Wrap each service with timing ---
    async def _timed(name, coro):
        t = _time.perf_counter()
        result = await coro
        print(f"[PERF] {name}: {_time.perf_counter() - t:.2f}s")
        return result

    # Run VT, Safe Browsing, and Domain Age ALL concurrently
    vt_result, sb_result, domain_age_result = await asyncio.gather(
        _timed("VirusTotal", virustotal_service.analyze_url(url)),
        _timed("SafeBrowsing", safe_browsing_service.check_url(url)),
        _timed("DomainAge", domain_age_service.get_domain_age(url)),
    )
    print(f"[PERF] Total /analyze: {_time.perf_counter() - _t0:.2f}s")

    # --- Build risk reasons list ---
    risk_reasons: list[RiskReason] = []

    # VirusTotal reasons
    if vt_result["score"] > 0:
        risk_reasons.append(RiskReason(
            source="virustotal",
            title="Flagged by Security Vendors",
            description=vt_result["details"],
            severity="high" if vt_result["score"] >= 50 else "medium",
            score_contribution=vt_result["score"] * WEIGHT_VIRUSTOTAL,
        ))

    # Safe Browsing reasons
    if sb_result["is_threat"]:
        for threat in sb_result["threats"]:
            risk_reasons.append(RiskReason(
                source="safebrowsing",
                title=f"Google Safe Browsing: {threat}",
                description=sb_result["details"],
                severity="high",
                score_contribution=sb_result["score"] * WEIGHT_SAFE_BROWSING / max(len(sb_result["threats"]), 1),
            ))

    # Heuristic reasons
    for flag in heuristic_result["flags"]:
        risk_reasons.append(RiskReason(
            source="heuristic",
            title=flag["title"],
            description=flag["description"],
            severity=flag["severity"],
            score_contribution=flag["points"] * WEIGHT_HEURISTIC,
        ))

    # --- Sandbox reasons ---
    if sandbox_result.get("is_malicious", False):
        risk_reasons.append(RiskReason(
            source="sandbox",
            title="Sandbox: Malware Detected",
            description=sandbox_result.get("details", "Sandbox flagged this URL as malicious."),
            severity="high",
            score_contribution=sandbox_result.get("score", 30),
        ))

    # --- Domain age reasons ---
    if domain_age_result.get("is_new_domain", False):
        age_days = domain_age_result.get("domain_age_days", 0)
        risk_reasons.append(RiskReason(
            source="domain_age",
            title="Newly Registered Domain",
            description=f"This domain was registered only {age_days} days ago. Newly created domains are frequently used in phishing attacks.",
            severity="medium",
            score_contribution=10,
        ))

    # --- Calculate combined risk score ---
    sandbox_score = sandbox_result.get("score", 0) * 0.30  # Sandbox weight
    combined_score = (
        vt_result["score"] * WEIGHT_VIRUSTOTAL
        + sb_result["score"] * WEIGHT_SAFE_BROWSING
        + heuristic_result["score"] * WEIGHT_HEURISTIC
        + sandbox_score
    )
    combined_score = min(round(combined_score, 1), 100)

    # --- Determine risk level ---
    if combined_score <= SAFE_THRESHOLD:
        risk_level = RiskLevel.SAFE
    elif combined_score <= SUSPICIOUS_THRESHOLD:
        risk_level = RiskLevel.SUSPICIOUS
    else:
        risk_level = RiskLevel.DANGEROUS

    # --- Build summary ---
    level_labels = {
        RiskLevel.SAFE: "SAFE ✓",
        RiskLevel.SUSPICIOUS: "SUSPICIOUS ⚠",
        RiskLevel.DANGEROUS: "DANGEROUS ✗",
    }
    reason_count = len(risk_reasons)
    summary = (
        f"This URL is {level_labels[risk_level]}. "
        f"Risk score: {combined_score}/100. "
        f"{reason_count} risk factor{'s' if reason_count != 1 else ''} detected."
    )

    # --- Build sandbox result model ---
    sandbox_model = SandboxResult(
        available=sandbox_result.get("available", False),
        is_malicious=sandbox_result.get("is_malicious", False),
        malicious_score=sandbox_result.get("malicious_score", 0),
        screenshot_url=sandbox_result.get("screenshot_url", ""),
        page_title=sandbox_result.get("page_title", ""),
        server_ip=sandbox_result.get("server_ip", ""),
        server_country=sandbox_result.get("server_country", ""),
        domain=sandbox_result.get("domain", ""),
        redirects=sandbox_result.get("redirects", []),
        technologies=sandbox_result.get("technologies", []),
        categories=sandbox_result.get("categories", []),
        brands=sandbox_result.get("brands", []),
        details=sandbox_result.get("details", ""),
        score=sandbox_result.get("score", 0),
    )

    return AnalyzeResponse(
        url=url,
        risk_score=combined_score,
        risk_level=risk_level,
        risk_reasons=risk_reasons,
        virustotal_positives=vt_result["positives"],
        virustotal_total=vt_result["total"],
        safe_browsing_threats=sb_result["threats"],
        heuristic_flags=[f["title"] for f in heuristic_result["flags"]],
        sandbox_result=sandbox_model,
        domain_age_days=domain_age_result.get("domain_age_days", -1),
        registration_date=domain_age_result.get("registration_date", ""),
        registrar=domain_age_result.get("registrar", ""),
        is_new_domain=domain_age_result.get("is_new_domain", False),
        summary=summary,
    )


@app.post("/sandbox")
async def sandbox_scan(request: AnalyzeRequest):
    """Run sandbox analysis independently (takes 15-30s)."""
    url = request.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    result = await sandbox_service.scan_url(url)

    # Convert screenshot URL to base64 data URI to bypass CORS on Flutter Web
    raw_ss = result.get("screenshot_url", "")
    if raw_ss and raw_ss.startswith("https://"):
        try:
            import base64
            async with httpx_sync.AsyncClient(timeout=15, follow_redirects=True) as ss_client:
                ss_resp = await ss_client.get(raw_ss)
                if ss_resp.status_code == 200:
                    ct = ss_resp.headers.get("content-type", "image/png")
                    b64 = base64.b64encode(ss_resp.content).decode("utf-8")
                    result["screenshot_url"] = f"data:{ct};base64,{b64}"
        except Exception:
            pass  # Keep raw URL as fallback

    return SandboxResult(
        available=result.get("available", False),
        is_malicious=result.get("is_malicious", False),
        malicious_score=result.get("malicious_score", 0),
        screenshot_url=result.get("screenshot_url", ""),
        page_title=result.get("page_title", ""),
        server_ip=result.get("server_ip", ""),
        server_country=result.get("server_country", ""),
        domain=result.get("domain", ""),
        redirects=result.get("redirects", []),
        technologies=result.get("technologies", []),
        categories=result.get("categories", []),
        brands=result.get("brands", []),
        details=result.get("details", ""),
        score=result.get("score", 0),
    )



@app.get("/proxy/screenshot")
async def proxy_screenshot(url: str = Query(..., description="The screenshot URL to proxy")):
    """Proxy an external screenshot image to bypass CORS for Flutter Web."""
    if not url.startswith("https://urlscan.io/"):
        raise HTTPException(status_code=400, detail="Only urlscan.io URLs are allowed")
    try:
        async with httpx_sync.AsyncClient(timeout=15, follow_redirects=True) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                raise HTTPException(status_code=502, detail="Failed to fetch screenshot")
            content_type = resp.headers.get("content-type", "image/png")
            return Response(
                content=resp.content,
                media_type=content_type,
                headers={"Cache-Control": "public, max-age=3600"},
            )
    except httpx_sync.TimeoutException:
        raise HTTPException(status_code=504, detail="Screenshot fetch timed out")


if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False)


