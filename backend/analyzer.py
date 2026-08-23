import re
import os
from dotenv import load_dotenv

# Try to import Google Gemini
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

# Load environment variables
load_dotenv()

class ScamAnalyzer:
    def __init__(self):
        # Initialize Gemini if available
        if GEMINI_AVAILABLE:
            api_key = os.getenv("GEMINI_API_KEY")
            if api_key:
                genai.configure(api_key=api_key)
                self.model = genai.GenerativeModel('gemini-pro')
            else:
                self.model = None
        else:
            self.model = None
        
        # Comprehensive scam keyword database with weights
        self.scam_keywords = {
            # Urgency indicators (high weight)
            "urgent": 8, "immediately": 7, "asap": 8, "limited time": 7,
            "act now": 8, "hurry": 6, "don't miss": 6, "expires today": 9,
            
            # Payment requests (very high weight)
            "registration fee": 10, "processing fee": 9, "training fee": 9,
            "security deposit": 10, "advance payment": 10, "upfront payment": 10,
            "pay to join": 10, "buy equipment": 8, "purchase materials": 8,
            
            # Unrealistic promises (high weight)
            "guaranteed salary": 7, "earn thousands": 7, "get rich": 9,
            "passive income": 6, "financial freedom": 7, "no experience needed": 5,
            "work from home": 4, "part time": 3, "extra income": 5,
            
            # Communication red flags
            "whatsapp only": 8, "telegram": 7, "personal email": 6,
            "gmail.com": 4, "yahoo.com": 4, "hotmail.com": 4,
            
            # Vague descriptions
            "data entry": 6, "simple tasks": 5, "easy money": 8,
            "no interview": 9, "instant hiring": 8, "no skills": 5,
            
            # Pressure tactics
            "confidential": 5, "exclusive opportunity": 6, "selected candidates": 4,
            "send documents": 6, "id verification": 5, "bank details": 7
        }
    
    def comprehensive_analysis(self, job_data):
        """Run complete analysis on job opportunity"""
        
        # Extract fields
        company_name = job_data.get("company_name", "")
        email = job_data.get("email", "")
        phone = job_data.get("phone", "")
        job_description = job_data.get("job_description", "")
        website = job_data.get("website", "")
        salary = job_data.get("salary", "")
        
        # Combine all text for keyword analysis
        all_text = f"{company_name} {email} {phone} {job_description} {website} {salary}"
        
        # Run all analyses
        keyword_analysis = self.analyze_keywords(all_text)
        email_analysis = self.analyze_email(email)
        phone_analysis = self.analyze_phone(phone)
        salary_analysis = self.analyze_salary_claim(job_description)
        ai_analysis = self.get_ai_analysis(all_text)
        
        # Calculate overall risk score (FIXED - proper averaging)
        keyword_score = min(100, keyword_analysis["keyword_risk_score"])
        email_score = min(100, email_analysis["risk_score"])
        phone_score = min(100, phone_analysis["risk_score"])
        salary_score = min(100, salary_analysis["risk_score"])
        
        # AI analysis contribution
        ai_score = 0
        if ai_analysis["status"] == "success":
            ai_text = ai_analysis["ai_analysis"].lower()
            if "scam" in ai_text or "fraud" in ai_text or "suspicious" in ai_text:
                ai_score = 40
            elif "legitimate" in ai_text or "safe" in ai_text:
                ai_score = 10
        
        # Weighted average (FIXED)
        overall_risk = (
            keyword_score * 0.35 +
            email_score * 0.20 +
            phone_score * 0.10 +
            salary_score * 0.20 +
            ai_score * 0.15
        )

        matched_keywords = {flag["keyword"] for flag in keyword_analysis["found_keywords"]}
        payment_keywords = {
            "registration fee", "processing fee", "training fee",
            "security deposit", "advance payment", "upfront payment",
            "pay to join"
        }
        urgency_keywords = {"urgent", "immediately", "asap", "act now", "hurry"}
        if matched_keywords & payment_keywords and matched_keywords & urgency_keywords:
            overall_risk = 100
        
        # Cap at 100
        overall_risk = min(100, max(0, overall_risk))
        
        return {
            "keyword_analysis": keyword_analysis,
            "email_analysis": email_analysis,
            "phone_analysis": phone_analysis,
            "salary_analysis": salary_analysis,
            "ai_analysis": ai_analysis,
            "overall_risk_score": round(overall_risk, 2),
            "risk_level": "HIGH" if overall_risk > 60 else "MEDIUM" if overall_risk > 30 else "LOW"
        }
    
    def analyze_keywords(self, text):
        """Analyze text for scam keywords with weighted scoring"""
        text_lower = text.lower()
        found_keywords = []
        total_score = 0
        
        for keyword, weight in self.scam_keywords.items():
            if keyword.lower() in text_lower:
                found_keywords.append({
                    "keyword": keyword,
                    "weight": weight,
                    "severity": "high" if weight >= 8 else "medium" if weight >= 5 else "low"
                })
                total_score += weight
        
        flag_count = len(found_keywords)
        multiple_flags_bonus = 40 if flag_count >= 5 else 20 if flag_count >= 3 else 0
        critical_keywords = {
            "registration fee",
            "upfront payment",
            "no interview",
            "whatsapp only",
            "pay to join",
        }
        matched_critical_count = sum(
            keyword in critical_keywords for keyword in (flag["keyword"] for flag in found_keywords)
        )
        critical_bonus = matched_critical_count * 15
        risk_score = min(100, max(0, total_score + multiple_flags_bonus + critical_bonus))
        
        return {
            "found_keywords": found_keywords,
            "flag_count": flag_count,
            "total_weight": total_score,
            "multiple_flags_bonus": multiple_flags_bonus,
            "critical_bonus": critical_bonus,
            "keyword_risk_score": risk_score
        }
    
    def analyze_email(self, email):
        """Analyze email for suspicious patterns"""
        if not email:
            return {"is_suspicious": False, "risk_score": 0, "reasons": []}
        
        reasons = []
        risk_score = 0
        
        # Check for free email providers
        free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com"]
        email_domain = email.split("@")[-1].lower() if "@" in email else ""
        
        if email_domain in free_providers:
            reasons.append(f"Using free email provider ({email_domain})")
            risk_score += 30
        
        # Check for suspicious patterns
        if re.search(r'\d{3,}', email):
            reasons.append("Email contains multiple numbers")
            risk_score += 20
        
        if len(email) < 10:
            reasons.append("Email address unusually short")
            risk_score += 15
        
        # Check for job-related keywords in email
        if not any(word in email_domain for word in ["company", "corp", "inc", "ltd", "hr", "careers"]):
            reasons.append("Domain doesn't match typical business naming")
            risk_score += 10
        
        return {
            "is_suspicious": risk_score > 25,
            "risk_score": min(100, risk_score),
            "reasons": reasons,
            "domain": email_domain
        }
    
    def analyze_phone(self, phone):
        """Analyze phone number for suspicious patterns"""
        if not phone:
            return {"is_suspicious": False, "risk_score": 0}
        
        risk_score = 0
        
        # Check if it's a mobile number (more suspicious for jobs)
        if re.search(r'^\+?1?\s*\(?[2-9]\d{2}\)?\s*\d{3}[-.]?\d{4}$', phone):
            risk_score += 20
        
        # Check for WhatsApp mention
        if "whatsapp" in phone.lower():
            risk_score += 30
        
        return {
            "is_suspicious": risk_score > 25,
            "risk_score": min(100, risk_score)
        }
    
    def analyze_salary_claim(self, job_description):
        """Analyze if salary claim is realistic"""
        if not job_description:
            return {"risk_score": 0, "unrealistic": False}
        
        risk_score = 0
        
        # Look for salary patterns
        salary_patterns = [
            (r'₹?\s*\d{1,3}(?:,\d{3})+\s*(per month|monthly)', 40),
            (r'₹?\s*\d{5,}\s*(per month|monthly)', 40),
            (r'₹?\s*\d{6,}\s*(per month|monthly)', 60),
            (r'earn.*\d{4,}\s*per\s*(day|week)', 50),    # High daily/weekly earnings
            (r'guaranteed.*\d{5,}', 40),                 # Guaranteed high income
        ]
        
        for pattern, score in salary_patterns:
            if re.search(pattern, job_description, re.IGNORECASE):
                risk_score += score
                break
        
        # Check for "no experience" + high salary combination
        if re.search(r'no experience', job_description, re.IGNORECASE):
            if re.search(r'₹?\s*\d{1,3}(?:,\d{3})+|₹?\s*\d{4,}', job_description):
                risk_score += 30
        
        return {
            "risk_score": min(100, risk_score),
            "unrealistic": risk_score > 30
        }
    
    def get_ai_analysis(self, text):
        """Use Google Gemini AI to analyze the job posting"""
        if not self.model:
            return {"status": "error", "message": "AI model not available", "ai_analysis": ""}
        
        try:
            prompt = f"""
            Analyze this job posting for potential scam indicators. 
            Look for: urgency tactics, payment requests, unrealistic promises, vague descriptions.
            
            Job posting: {text}
            
            Provide a brief analysis (2-3 sentences) indicating if this appears legitimate or suspicious.
            """
            
            response = self.model.generate_content(prompt)
            analysis = response.text.strip()
            
            return {
                "status": "success",
                "ai_analysis": analysis
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "ai_analysis": ""
            }