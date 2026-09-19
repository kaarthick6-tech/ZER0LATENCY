from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import os
import re
from dotenv import load_dotenv

# Import our custom modules
from url_checker import URLChecker
from analyzer import ScamAnalyzer

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(
    title="ScamCheck API",
    description="AI-Powered Job/Internship Scam Detection System",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize checkers
url_checker = URLChecker()
scam_analyzer = ScamAnalyzer()

# Pydantic models for request/response
class JobOpportunity(BaseModel):
    company_name: str
    email: str
    phone: Optional[str] = ""
    website: Optional[str] = ""
    job_description: str
    salary: Optional[str] = ""

class Forensics(BaseModel):
    domain_age_days: Optional[int] = None
    ssl_valid: bool = False
    is_free_email: bool = False
    email_provider: str = "Unknown"

class AnalysisResponse(BaseModel):
    overall_risk_score: Optional[float]
    risk_level: str
    url_analysis: dict
    content_analysis: dict
    recommendations: List[str]
    verdict: str
    sos_message: Optional[str] = None
    confidence: int
    forensics: Forensics

@app.get("/")
async def root():
    return {
        "message": "ScamCheck API - AI-Powered Opportunity Verification",
        "version": "1.0.0",
        "status": "running"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "scamcheck-api"}

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_opportunity(job: JobOpportunity):
    """
    Comprehensive scam analysis endpoint
    """
    try:
        def calculate_confidence(content_analysis=None, url_analysis=None):
            confidence = 30
            if job.website.strip():
                confidence += 20
            if job.email.strip():
                confidence += 20

            description_words = len(re.findall(r"\b\w+\b", job.job_description or ""))
            if description_words > 40:
                confidence += 15

            has_signal = False
            if content_analysis:
                keyword_flags = content_analysis.get("keyword_analysis", {}).get("flag_count", 0)
                email_info = content_analysis.get("email_analysis", {})
                phone_score = content_analysis.get("phone_analysis", {}).get("risk_score", 0)
                salary_score = content_analysis.get("salary_analysis", {}).get("risk_score", 0)
                has_signal = (
                    keyword_flags > 0
                    or bool(email_info.get("reasons"))
                    or email_info.get("is_suspicious") is False
                    or phone_score > 0
                    or salary_score > 0
                )

            if url_analysis:
                if url_analysis.get("overall_risk_score") is not None or url_analysis.get("has_ssl") is not None:
                    has_signal = True

            if has_signal:
                confidence += 15

            return min(100, max(0, confidence))

        validity = scam_analyzer.validate_input(job.job_description)
        if not validity.get("valid", False):
            confidence = calculate_confidence()
            email_domain = job.email.rsplit("@", 1)[-1].lower() if "@" in job.email else ""
            free_email_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com"}
            return AnalysisResponse(
                overall_risk_score=None,
                risk_level="UNVERIFIABLE",
                url_analysis={},
                content_analysis={
                    "input_validity": validity,
                    "keyword_analysis": {"found_keywords": [], "flag_count": 0, "keyword_risk_score": 0},
                    "email_analysis": {"is_suspicious": False, "risk_score": 0, "reasons": []},
                    "phone_analysis": {"is_suspicious": False, "risk_score": 0},
                    "salary_analysis": {"risk_score": 0, "unrealistic": False},
                    "overall_risk_score": 0
                },
                recommendations=[],
                verdict=(
                    "This does not look like a valid job offer. We cannot certify it as safe. "
                    "Please paste the complete offer text, company email, and website for proper verification."
                ),
                sos_message=None,
                confidence=confidence,
                forensics=Forensics(
                    domain_age_days=None,
                    ssl_valid=False,
                    is_free_email=email_domain in free_email_domains,
                    email_provider=email_domain or "Unknown"
                )
            )

        # Step 1: Analyze URL/Website
        url_analysis = {}
        if job.website:
            url_analysis = url_checker.comprehensive_check(job.website)
        
        # Step 2: Analyze content and details
        job_data = {
            "company_name": job.company_name,
            "email": job.email,
            "phone": job.phone,
            "website": job.website,
            "job_description": job.job_description,
            "salary": job.salary
        }
        
        content_analysis = scam_analyzer.comprehensive_analysis(job_data)
        email_analysis = content_analysis.get("email_analysis", {})
        domain_age_data = url_analysis.get("domain_age", {})
        ssl_data = url_analysis.get("ssl_certificate", {})
        forensics = Forensics(
            domain_age_days=url_analysis.get("domain_age_days", domain_age_data.get("age_days")),
            ssl_valid=url_analysis.get("ssl_valid", ssl_data.get("has_ssl", False)),
            is_free_email=email_analysis.get("is_free_email", False),
            email_provider=email_analysis.get("email_provider", email_analysis.get("domain", "Unknown"))
        )
        
        # Step 3: Calculate final risk score (FIXED)
        url_risk = url_analysis.get("overall_risk_score", 0)
        content_risk = content_analysis.get("overall_risk_score", 0)
        
        # Ensure scores are numbers and between 0-100
        try:
            url_risk = float(url_risk) if url_risk else 0
            content_risk = float(content_risk) if content_risk else 0
        except (ValueError, TypeError):
            url_risk = 0
            content_risk = 0
        
        # Cap at 100
        url_risk = min(100, max(0, url_risk))
        content_risk = min(100, max(0, content_risk))
        
        # Weighted final score (URL 40%, Content 60%)
        final_risk_score = round((url_risk * 0.4) + (content_risk * 0.6), 2)

        keyword_analysis = content_analysis.get("keyword_analysis", {})
        keyword_flags = keyword_analysis.get("found_keywords", [])
        flag_count = keyword_analysis.get("flag_count", len(keyword_flags))
        if flag_count >= 5:
            minimum_score = 75
        elif flag_count >= 3:
            minimum_score = 50
        else:
            minimum_score = 0

        if keyword_analysis.get("critical_indicator_count", 0) >= 2:
            minimum_score = max(minimum_score, 70)

        final_risk_score = max(final_risk_score, minimum_score)
        
        # Ensure final score is between 0-100
        final_risk_score = min(100, max(0, final_risk_score))
        
        # Determine risk level
        sos_message = None
        if final_risk_score >= 70:
            risk_level = "HIGH"
            verdict = "LIKELY SCAM - AVOID THIS OPPORTUNITY"
            first_two_flags = [
                flag.get("keyword", "").strip()
                for flag in keyword_flags
                if flag.get("keyword", "").strip()
            ][:2]
            flags_text = ", ".join(first_two_flags) if first_two_flags else "multiple suspicious signals"
            sos_message = (
                f"⚠️ URGENT: Job offer from {job.company_name} is HIGH RISK "
                f"(Score: {int(round(final_risk_score))}). Red flags: {flags_text}. "
                "Verify before proceeding."
            )
        elif final_risk_score >= 40:
            risk_level = "MEDIUM"
            verdict = "SUSPICIOUS - VERIFY CAREFULLY BEFORE PROCEEDING"
        else:
            risk_level = "LOW"
            verdict = "APPEARS LEGITIMATE - STILL VERIFY BASIC DETAILS"
        
        # Generate recommendations
        recommendations = []
        
        if url_risk > 50:
            recommendations.append("Website shows suspicious characteristics - verify company legitimacy")
        
        if content_analysis.get("email_analysis", {}).get("is_suspicious", False):
            recommendations.append("Email domain appears suspicious - look for official company email")
        
        if flag_count > 3:
            recommendations.append("Multiple red flags detected in job description")
        
        salary_risk = content_analysis.get("salary_analysis", {}).get("risk_score", 0)
        if salary_risk > 20:
            recommendations.append("Salary claim seems unrealistic - research market rates")
        
        if not recommendations:
            recommendations.append("Always verify company through official channels")
            recommendations.append("Never pay upfront fees for jobs")
            recommendations.append("Check company reviews on LinkedIn and Glassdoor")

        confidence = calculate_confidence(content_analysis=content_analysis, url_analysis=url_analysis)
        
        return AnalysisResponse(
            overall_risk_score=final_risk_score,
            risk_level=risk_level,
            url_analysis=url_analysis,
            content_analysis=content_analysis,
            recommendations=recommendations,
            verdict=verdict,
            sos_message=sos_message,
            confidence=confidence,
            forensics=forensics
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)