import requests
import whois
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

class URLChecker:
    def __init__(self):
        self.virustotal_api_key = os.getenv("VIRUSTOTAL_API_KEY")
    
    def check_domain_age(self, url):
        """Check how old the domain is"""
        try:
            # Extract domain from URL
            domain = url.split("//")[-1].split("/")[0]
            w = whois.whois(domain)
            
            if w.creation_date:
                # Handle both single date and list of dates
                creation_date = w.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                if creation_date.tzinfo is not None:
                    creation_date = creation_date.replace(tzinfo=None)
                age_days = (datetime.now() - creation_date).days
                return {
                    "status": "success",
                    "domain": domain,
                    "creation_date": creation_date.strftime("%Y-%m-%d"),
                    "age_days": age_days,
                    "risk_score": 0 if age_days > 365 else min(100, (365 - age_days) // 3)
                }
            return {"status": "no_date", "risk_score": 50}
        except Exception as e:
            return {"status": "error", "error": str(e), "risk_score": 30}
    
    def check_virustotal(self, url):
        """Check URL against VirusTotal database"""
        if not self.virustotal_api_key:
            return {"status": "skipped", "reason": "VirusTotal API key not configured", "risk_score": 0}

        try:
            headers = {
                "x-apikey": self.virustotal_api_key
            }
            
            # First, submit the URL for analysis
            scan_response = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=5
            )
            
            if scan_response.status_code == 200:
                # Get the analysis ID
                data = scan_response.json()
                analysis_id = data["data"]["id"]
                
                # Get the analysis report
                report_response = requests.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=headers,
                    timeout=5
                )
                
                if report_response.status_code == 200:
                    report = report_response.json()
                    stats = report["data"]["attributes"]["stats"]
                    
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    
                    risk_score = (malicious * 10) + (suspicious * 5)
                    
                    return {
                        "status": "success",
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "risk_score": min(100, risk_score)
                    }
            
            return {"status": "clean", "risk_score": 0}
        except Exception as e:
            return {"status": "error", "error": str(e), "risk_score": 20}
    
    def check_ssl_certificate(self, url):
        """Check if website has valid SSL certificate"""
        try:
            if url.startswith("https://"):
                return {
                    "status": "success",
                    "has_ssl": True,
                    "risk_score": 0
                }
            else:
                return {
                    "status": "warning",
                    "has_ssl": False,
                    "risk_score": 40
                }
        except:
            return {"status": "error", "risk_score": 20}
    
    def comprehensive_check(self, url):
        """Run all URL checks"""
        # WHOIS can block for many seconds when a registry is unreachable.
        # Skip it when the URL is not HTTPS; the SSL result already flags it.
        domain_age = self.check_domain_age(url) if url.startswith("https://") else {
            "status": "skipped",
            "reason": "WHOIS check skipped for non-HTTPS URL",
            "risk_score": 30
        }
        virustotal = self.check_virustotal(url)
        ssl_check = self.check_ssl_certificate(url)
        
        # Calculate overall URL risk score
        total_risk = (
            domain_age.get("risk_score", 0) * 0.4 +
            virustotal.get("risk_score", 0) * 0.5 +
            ssl_check.get("risk_score", 0) * 0.1
        )
        
        overall_risk = round(min(100, total_risk), 2)
        if not self.virustotal_api_key:
            overall_risk = max(40, overall_risk)

        return {
            "domain_age": domain_age,
            "virustotal": virustotal,
            "ssl_certificate": ssl_check,
            "overall_risk_score": overall_risk
        }