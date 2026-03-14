import whois
from datetime import datetime

def whois_features(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        age_days = (datetime.utcnow() - creation).days if creation else 0
        return {
            "domain_age_days": age_days,
            "registrar": w.registrar or "Unknown"
        }
    except:
        return {"domain_age_days":0,"registrar":"Unknown"}