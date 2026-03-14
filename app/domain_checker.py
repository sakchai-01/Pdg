import socket
from app.whois_utils import whois_features

SUSPICIOUS_TLDS = [".tk",".ml",".ga",".cf",".gq"]

def analyze_domain(domain):
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

    return {
        "domain": domain,
        "score": score,
        "risk": risk,
        "details": details,
        "whois": whois_data
    }