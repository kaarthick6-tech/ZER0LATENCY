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
        self.job_related_tokens = {
            "job", "hire", "hiring", "work", "salary", "position", "intern",
            "role", "company", "apply", "offer", "pay", "earn", "recruit",
            "candidate", "experience"
        }

    def validate_input(self, text):
        """Validate that the input resembles a real job posting."""
        text_lower = (text or "").lower()
        tokens = re.findall(r"[a-zA-Z]+", text_lower)
        critical_concepts = self.detect_critical_concepts(text_lower)

        non_dictionary_like = sum(
            not self._is_dictionary_like_word(token)
            for token in tokens
        )
        gibberish_ratio = non_dictionary_like / len(tokens) if tokens else 1.0
        if gibberish_ratio > 0.40:
            return {
                "valid": False,
                "reason": "Text appears too noisy or gibberish. Please provide the original offer wording."
            }

        word_count = len(tokens)
        has_job_tokens = any(token in self.job_related_tokens for token in tokens)
        has_critical = len(critical_concepts) > 0

        if word_count < 15 and not has_critical:
            return {
                "valid": False,
                "reason": f"Text is too short to analyze ({word_count} words)."
            }

        if not has_job_tokens and not has_critical:
            return {
                "valid": False,
                "reason": "No job-related content detected."
            }

        return {"valid": True, "reason": "Input appears valid for scam analysis."}

    def _is_dictionary_like_word(self, token):
        """Heuristic detector for dictionary-like words."""
        if len(token) <= 2:
            return True
        if re.search(r"(.)\1\1", token):
            return False
        if not re.search(r"[aeiou]", token) and len(token) >= 4:
            return False
        if re.search(r"[bcdfghjklmnpqrstvwxyz]{6,}", token):
            return False
        return True

    def detect_critical_concepts(self, text_lower):
        """Detect critical high-risk scam concepts used by the validity gate and scoring."""
        critical_concepts = []
        concept_patterns = [
            (
                r"\b(registration fee|processing fee|training fee|upfront payment|advance payment|deposit)\b",
                "upfront payment/deposit demand"
            ),
            (
                r"\b(aadhaar|aadhar|bank details|account number|ifsc|otp|cvv|upi pin)\b",
                "document or sensitive data harvesting"
            ),
            (
                r"\b(payment|deposit|send money|transfer)\b.{0,35}\b(whatsapp|telegram)\b|\b(whatsapp|telegram)\b.{0,35}\b(payment|deposit|send money|transfer)\b",
                "payment request via whatsapp/telegram"
            ),
        ]
        for pattern, label in concept_patterns:
            if re.search(pattern, text_lower):
                critical_concepts.append(label)
        return critical_concepts
    
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
        # Do not let averaging dilute a strong set of content red flags.
        overall_risk = max(overall_risk, keyword_score)

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
            "risk_level": "HIGH" if overall_risk >= 70 else "MEDIUM" if overall_risk >= 40 else "LOW"
        }
    
    def analyze_keywords(self, text):
        """Analyze text for scam keywords with weighted scoring"""
        text_lower = text.lower()
        found_keywords = []
        total_score = 0
        matched_labels = set()

        def add_flag(keyword, weight, reason):
            nonlocal total_score
            if keyword in matched_labels:
                return
            matched_labels.add(keyword)
            found_keywords.append({
                "keyword": keyword,
                "weight": weight,
                "severity": "high" if weight >= 8 else "medium" if weight >= 5 else "low",
                "reason": reason
            })
            total_score += weight
        
        for keyword, weight in self.scam_keywords.items():
            if keyword.lower() in text_lower:
                add_flag(keyword, weight, self._keyword_reason(keyword))

        # Concept-based fuzzy matching for self-phrased scam variants.
        concept_patterns = [
            (
                r"\b(deposit|registration amount|joining amount|security amount|advance)\b",
                "upfront deposit request",
                10,
                "Requests upfront money before employment confirmation."
            ),
            (
                r"\b(daily payout|instant payout|quick payout|same day payout)\b",
                "rapid payout promise",
                8,
                "Promises unusually fast payouts, often used in scam bait."
            ),
            (
                r"\b(message|dm|contact)\b.{0,25}\b(whatsapp|telegram)\b",
                "informal contact channel",
                8,
                "Directs candidates to informal messaging channels instead of official HR."
            ),
            (
                r"\b(without experience|no prior experience|freshers?\s+(welcome|allowed)|anyone can do)\b",
                "no-experience sales pitch",
                6,
                "Overly broad eligibility claims are common in scam postings."
            ),
            (
                r"\b(part[\s-]?time)\b.{0,30}\b(earn|income|salary|payout)\b",
                "easy part-time earning claim",
                7,
                "Combines part-time framing with earning claims that need verification."
            ),
        ]
        for pattern, label, weight, reason in concept_patterns:
            if re.search(pattern, text_lower):
                add_flag(label, weight, reason)

        critical_concepts = self.detect_critical_concepts(text_lower)
        for concept in critical_concepts:
            if concept == "upfront payment/deposit demand":
                add_flag(
                    "critical: upfront payment/deposit",
                    10,
                    "Asks for money before hiring confirmation, a major scam indicator."
                )
            elif concept == "document or sensitive data harvesting":
                add_flag(
                    "critical: document/data harvesting",
                    10,
                    "Requests sensitive identity or financial details that scammers commonly misuse."
                )
            elif concept == "payment request via whatsapp/telegram":
                add_flag(
                    "critical: payment via whatsapp/telegram",
                    10,
                    "Combines money request with informal messaging channels, which is highly suspicious."
                )
        
        flag_count = len(found_keywords)
        amplified_score = total_score * 1.5
        critical_indicators = list(critical_concepts)
        if re.search(r"\b(registration fee|payment|fee)\b", text_lower):
            critical_indicators.append("payment or fee requested")
        if re.search(r"\b(urgent|act now|expires)\b", text_lower):
            critical_indicators.append("urgent pressure language")
        if (
            re.search(r"\bno experience\b", text_lower)
            and re.search(r"(?:₹|\$|£|€)?\s*\d[\d,]{3,}", text_lower)
            and re.search(r"\b(?:salary|month|monthly|per month|guaranteed|earn)\b", text_lower)
        ):
            critical_indicators.append("no experience paired with a high-salary promise")
        if re.search(r"\b(whatsapp|telegram)\b", text_lower):
            critical_indicators.append("informal messaging app used for job communication")
        # Remove duplicates while preserving order.
        critical_indicators = list(dict.fromkeys(critical_indicators))

        critical_bonus = len(critical_indicators) * 20
        risk_score = amplified_score + critical_bonus
        if len(critical_concepts) >= 1:
            risk_score = max(risk_score, 75)
        if flag_count >= 5:
            risk_score = max(risk_score, 75)
        elif flag_count >= 3:
            risk_score = max(risk_score, 50)
        if len(critical_indicators) >= 2:
            risk_score = max(risk_score, 70)
        risk_score = min(100, max(0, risk_score))
        
        return {
            "found_keywords": found_keywords,
            "flag_count": flag_count,
            "total_weight": total_score,
            "amplified_score": round(amplified_score, 2),
            "multiple_flags_bonus": 0,
            "critical_indicators": critical_indicators,
            "critical_indicator_count": len(critical_indicators),
            "critical_bonus": critical_bonus,
            "keyword_risk_score": risk_score
        }

    def _keyword_reason(self, keyword):
        """Return a user-facing explanation for a matched red flag."""
        if keyword in {"registration fee", "processing fee", "training fee",
                       "security deposit", "advance payment", "upfront payment",
                       "pay to join"}:
            return "Requests money before employment, which is a common job-scam tactic."
        if keyword in {"urgent", "immediately", "asap", "act now", "hurry",
                       "don't miss", "expires today"}:
            return "Uses pressure or urgency to discourage careful verification."
        if keyword in {"guaranteed salary", "earn thousands", "get rich",
                       "passive income", "financial freedom"}:
            return "Promises unusually easy or guaranteed income."
        if keyword in {"whatsapp only", "telegram", "personal email"}:
            return "Uses informal or unverifiable communication instead of official channels."
        if keyword in {"no experience needed", "no skills", "work from home",
                       "part time", "extra income"}:
            return "Makes the opportunity sound unusually easy or accessible."
        return "Matches a pattern commonly associated with fraudulent job postings."
    
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
            risk_score += 25
        
        # Check for suspicious patterns
        if re.search(r'\d{3,}', email):
            reasons.append("Email contains multiple numbers")
            risk_score += 20
        
        if len(email) < 10:
            reasons.append("Email address unusually short")
            risk_score += 15
        
        if (
            re.search(r"\d", email_domain)
            or "-" in email_domain
            or email_domain.endswith((".xyz", ".top", ".click", ".work"))
        ):
            reasons.append("Email domain has a suspicious pattern")
            risk_score += 15
        
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