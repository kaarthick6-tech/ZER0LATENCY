from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import os
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
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
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

class AnalysisResponse(BaseModel):
    overall_risk_score: float
    risk_level: str
    url_analysis: dict
    content_analysis: dict
    recommendations: List[str]
    verdict: str

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
        
        # Ensure final score is between 0-100
        final_risk_score = min(100, max(0, final_risk_score))
        
        # Determine risk level
        if final_risk_score >= 70:
            risk_level = "HIGH"
            verdict = "🚨 LIKELY SCAM - AVOID THIS OPPORTUNITY"
        elif final_risk_score >= 40:
            risk_level = "MEDIUM"
            verdict = "⚠️ SUSPICIOUS - VERIFY CAREFULLY BEFORE PROCEEDING"
        else:
            risk_level = "LOW"
            verdict = "✅ APPEARS LEGITIMATE - STILL VERIFY BASIC DETAILS"
        
        # Generate recommendations
        recommendations = []
        
        if url_risk > 50:
            recommendations.append("Website shows suspicious characteristics - verify company legitimacy")
        
        if content_analysis.get("email_analysis", {}).get("is_suspicious", False):
            recommendations.append("Email domain appears suspicious - look for official company email")
        
        keyword_flags = content_analysis.get("keyword_analysis", {}).get("flag_count", 0)
        if keyword_flags > 3:
            recommendations.append("Multiple red flags detected in job description")
        
        salary_risk = content_analysis.get("salary_analysis", {}).get("risk_score", 0)
        if salary_risk > 20:
            recommendations.append("Salary claim seems unrealistic - research market rates")
        
        if not recommendations:
            recommendations.append("Always verify company through official channels")
            recommendations.append("Never pay upfront fees for jobs")
            recommendations.append("Check company reviews on LinkedIn and Glassdoor")
        
        return AnalysisResponse(
            overall_risk_score=final_risk_score,
            risk_level=risk_level,
            url_analysis=url_analysis,
            content_analysis=content_analysis,
            recommendations=recommendations,
            verdict=verdict
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)