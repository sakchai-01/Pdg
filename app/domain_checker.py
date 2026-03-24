import socket
import time
from app.whois_utils import whois_features

SUSPICIOUS_TLDS = [".tk",".ml",".ga",".cf",".gq"]

# Simple in-memory cache
ANALYSIS_CACHE = {}
CACHE_TTL = 3600  # 1 hour

def analyze_domain(domain):
    current_time = time.time()
    
    if domain in ANALYSIS_CACHE:
        cached = ANALYSIS_CACHE[domain]
        if current_time < cached["expiry"]:
            return cached["result"]

    score = 0
    details = []

    whois_data = whois_features(domain)

    if whois_data["domain_age_days"] < 180:
        score += 40
        details.append("โดเมนอายุสั้น ⚠️")

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 30
            details.append("TLD เสี่ยง")

    if "-" in domain:
        score += 10
        details.append("มีเครื่องหมาย -")

    risk = "ปลอดภัย"
    if score >= 70:
        risk = "อันตรายมาก 🔥"
    elif score >= 40:
        risk = "เสี่ยง ⚠️"

    result = {
        "domain": domain,
        "score": score,
        "risk": risk,
        "details": details,
        "whois": whois_data
    }
    
    ANALYSIS_CACHE[domain] = {
        "result": result,
        "expiry": current_time + CACHE_TTL
    }
    
    return result