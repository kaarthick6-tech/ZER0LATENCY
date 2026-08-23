import re
import google.generativeai as genai
from dotenv import load_dotenv
import os

load_dotenv()

class ScamAnalyzer:
    def __init__(self):
        self.gemini_api_key = os.getenv("GEMINI_API_KEY")
        genai.configure(api_key=self.gemini_api_key)
        self.model = genai.GenerativeModel('gemini-pro')
        
        # Advanced keyword database with weights
        self.red_flags = {
            # Payment-related (HIGH RISK)
            "registration fee": 35,
            "processing fee": 35,
            "security deposit": 35,
            "advance payment": 30,
            "upfront payment": 30,
            "pay to join": 40,
            "joining fee": 30,
            "training fee": 25,
            "software cost": 25,
            "id card fee": 20,
            
            # Urgency tactics (MEDIUM-HIGH RISK)
            "urgent hiring": 20,
            "limited time": 15,
            "act now": 15,
            "offer expires": 15,
            "immediate joining": 10,
            "hiring immediately": 10,
            
            # Too good to be true (HIGH RISK)
            "guaranteed salary": 30,
            "no experience needed": 20,
            "work from home": 15,
            "earn 50000": 25,
            "high salary": 20,
            "passive income": 25,
            "instant money": 30,
            "easy money": 30,
            "unlimited earning": 25,
            
            # Suspicious requirements
            "send documents": 10,
            "aadhar card": 15,
            "pan card": 15,
            "bank details": 20,
            "otp verification": 15,
            
            # Unprofessional language
            "!!!": 10,
            "congratulations": 15,
            "selected": 15,
            "without interview": 30,
        }
        
        # Email pattern checks
        self.suspicious_email_patterns = [
            r"@(gmail\.com|yahoo\.com|hotmail\.com|outlook\.com)",  # Free email domains
            r"@(.*-jobs\.com|.*-careers\.com|.*-hr\.com)",  # Fake domains
            r"hr.*@(?!.*\.com$).*",  # Non-standard domains
        ]
        
        # Phone pattern checks
        self.suspicious_phone_patterns = [
            r"\+91-\d{10}",  # Indian numbers (common in scams)
            r"\+1-\d{10}",  # International numbers for local jobs
            r"whatsapp.*\d{10,}",  # WhatsApp contact
        ]
    
    def analyze_keywords(self, text):
        """Analyze text for suspicious keywords"""
        text_lower = text.lower()
        detected_flags = []
        total_score = 0
        
        for keyword, score in self.red_flags.items():
            if keyword.lower() in text_lower:
                detected_flags.append({
                    "keyword": keyword,
                    "score": score,
                    "severity": "high" if score >= 30 else "medium" if score >= 15 else "low"
                })
                total_score += score
        
        # Cap the score at 100
        return {
            "detected_flags": detected_flags,
            "keyword_risk_score": min(100, total_score),
            "flag_count": len(detected_flags)
        }
    
    def analyze_email(self, email):
        """Analyze email address for suspicious patterns"""
        risk_score = 0
        issues = []
        
        for pattern in self.suspicious_email_patterns:
            if re.search(pattern, email, re.IGNORECASE):
                risk_score += 25
                issues.append("Suspicious email domain detected")
                break
        
        # Check for multiple @ symbols
        if email.count('@') != 1:
            risk_score += 30
            issues.append("Invalid email format")
        
        # Check for numbers in email (often fake)
        if re.search(r'\d{3,}', email):
            risk_score += 15
            issues.append("Email contains numbers (suspicious)")
        
        return {
            "email": email,
            "risk_score": min(100, risk_score),
            "issues": issues,
            "is_suspicious": risk_score > 20
        }
    
    def analyze_phone(self, phone):
        """Analyze phone number for suspicious patterns"""
        risk_score = 0
        issues = []
        
        for pattern in self.suspicious_phone_patterns:
            if re.search(pattern, phone):
                risk_score += 20
                issues.append("Suspicious phone pattern detected")
        
        return {
            "phone": phone,
            "risk_score": min(100, risk_score),
            "issues": issues
        }
    
    def analyze_salary_claim(self, text):
        """Analyze if salary claims are realistic"""
        # Look for salary patterns
        salary_patterns = [
            r"(\d{2,3},?\d{3,5})\s*(?:per month|monthly|\/month)",
            r"earn\s*(\d{2,3},?\d{3,5})",
            r"salary\s*[:\-]?\s*(\d{2,3},?\d{3,5})"
        ]
        
        for pattern in salary_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                salary = int(match.group(1).replace(',', ''))
                
                # Check for unrealistic salary for freshers
                if salary > 40000:
                    return {
                        "detected_salary": salary,
                        "risk_score": 40,
                        "issue": "Unrealistically high salary for entry-level position"
                    }
                elif salary > 25000:
                    return {
                        "detected_salary": salary,
                        "risk_score": 20,
                        "issue": "Above average salary - verify carefully"
                    }
                else:
                    return {
                        "detected_salary": salary,
                        "risk_score": 5,
                        "issue": "Salary seems reasonable"
                    }
        
        return {"detected_salary": None, "risk_score": 0, "issue": "No salary mentioned"}
    
    def get_ai_analysis(self, job_details):
        """Use Google Gemini AI for advanced analysis"""
        try:
            prompt = f"""
            Analyze this job/internship opportunity for potential scam indicators.
            
            Job Details:
            {job_details}
            
            Provide analysis in JSON format with these fields:
            - overall_assessment: "legitimate" or "suspicious" or "likely_scam"
            - confidence_score: 0-100 (higher = more confident it's a scam)
            - red_flags: [list of specific concerns]
            - green_flags: [list of positive indicators]
            - recommendation: "proceed" or "verify_carefully" or "avoid"
            - explanation: "detailed explanation in 2-3 sentences"
            
            Be strict and cautious. If anything seems suspicious, flag it.
            """
            
            response = self.model.generate_content(prompt)
            
            # Parse the response (basic parsing - in production use proper JSON parsing)
            return {
                "ai_analysis": response.text,
                "status": "success"
            }
        except Exception as e:
            return {
                "ai_analysis": f"AI analysis unavailable: {str(e)}",
                "status": "error"
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
        
        # Calculate overall risk score
        overall_risk = (
            keyword_analysis["keyword_risk_score"] * 0.35 +
            email_analysis["risk_score"] * 0.20 +
            phone_analysis["risk_score"] * 0.10 +
            salary_analysis["risk_score"] * 0.20 +
            (40 if ai_analysis["status"] == "success" and "scam" in ai_analysis["ai_analysis"].lower() else 0) * 0.15
        )
        
        return {
            "keyword_analysis": keyword_analysis,
            "email_analysis": email_analysis,
            "phone_analysis": phone_analysis,
            "salary_analysis": salary_analysis,
            "ai_analysis": ai_analysis,
            "overall_risk_score": round(min(100, overall_risk), 2),
            "risk_level": "HIGH" if overall_risk > 60 else "MEDIUM" if overall_risk > 30 else "LOW"
        }