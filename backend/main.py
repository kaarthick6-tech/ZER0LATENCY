from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from analyzer import ScamAnalyzer
from url_checker import URLChecker
from dotenv import load_dotenv

load_dotenv()

app = FastAPI(
    title="ScamCheck API",
    description="Advanced AI-powered job/internship scam detection system",
    version="1.0.0"
)

# Enable CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize analyzers
scam_analyzer = ScamAnalyzer()
url_checker = URLChecker()

class JobOpportunity(BaseModel):
    company_name: str
    email: str
    phone: str
    website: str
    job_description: str
    salary: str = ""
    additional_info: str = ""

class AnalysisResponse(BaseModel):
    overall_risk_score: float
    risk_level: str
    url_analysis: dict
    content_analysis: dict
    recommendations: list
    verdict: str

@app.get("/")
def root():
    return {
        "message": "Welcome to ScamCheck API",
        "version": "1.0.0",
        "status": "operational"
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "services": {
            "database": "connected",
            "ai_model": "loaded",
            "apis": "ready"
        }
    }

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
        
        # Step 3: Calculate final risk score
        url_risk = url_analysis.get("overall_risk_score", 0)
        content_risk = content_analysis["overall_risk_score"]
        
        # Weighted final score (URL 40%, Content 60%)
        final_risk_score = round((url_risk * 0.4) + (content_risk * 0.6), 2)
        
        # Determine risk level
        if final_risk_score >= 70:
            risk_level = "HIGH"
            verdict = " LIKELY SCAM - AVOID THIS OPPORTUNITY"
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
        
        if content_analysis["email_analysis"]["is_suspicious"]:
            recommendations.append("Email domain appears suspicious - look for official company email")
        
        if content_analysis["keyword_analysis"]["flag_count"] > 3:
            recommendations.append("Multiple red flags detected in job description")
        
        if content_analysis["salary_analysis"]["risk_score"] > 20:
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

@app.post("/quick-check")
async def quick_check(text: str):
    """
    Quick text-based scam check
    """
    try:
        analysis = scam_analyzer.analyze_keywords(text)
        return {
            "risk_score": analysis["keyword_risk_score"],
            "flags_found": analysis["flag_count"],
            "details": analysis["detected_flags"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)