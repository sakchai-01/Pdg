# web_scraper.py
import threading
import time
import logging
import requests
import random
from bs4 import BeautifulSoup
from crawler import save_to_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)

# List of targets to monitor (Mocking a threat feed)
TARGET_FEEDS = [
    "http://example.com",
    "http://test-phishing.com",
    "http://secure-login-bank.com",
    "http://account-update-required.net"
]

KEYWORDS = ["login", "password", "bank", "update", "verify", "secure"]

def run_scraper_background():
    """
    Run phishing scraper in background thread
    """
    def scraper_job():
        cycle = 1
        while True:
            logger.info(f"🕷️ Scraper cycle {cycle} running...")
            
            # 1. Fetch from feed (Simulated)
            target = random.choice(TARGET_FEEDS)
            
            # 2. Analyze
            try:
                # In a real scenario, we would request(target)
                # resp = requests.get(target, timeout=5)
                # soup = BeautifulSoup(resp.text, 'html.parser')
                
                # Simulating analysis for demo reliability
                risk_score = random.randint(10, 95)
                is_phishing = risk_score > 70
                
                if is_phishing:
                    reason = f"Detected suspicious keywords: {random.choice(KEYWORDS)}"
                    logger.warning(f"⚠️ DETECTED THREAT: {target} (Score: {risk_score})")
                    
                    # 3. Save to DB
                    save_to_db(
                        url=target,
                        domain=target.split('//')[-1],
                        risk_score=risk_score,
                        reason=reason
                    )
                else:
                    logger.info(f"✅ Clean: {target}")

            except Exception as e:
                logger.error(f"Scraper error: {e}")
            
            cycle += 1
            # Run every 60 seconds for demo purposes
            time.sleep(60)

    thread = threading.Thread(target=scraper_job, daemon=True)
    thread.start()
