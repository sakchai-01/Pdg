import os
import json
import re
from dotenv import load_dotenv
from typing import List, Optional, Dict, Any

try:
    import google.generativeai as genai
except ImportError:
    genai = None

load_dotenv()
GEMINI_KEY = os.getenv("GEMINI_API_KEY")

if genai and GEMINI_KEY:
    try:
        genai.configure(api_key=GEMINI_KEY)
        client = genai.GenerativeModel(
            model_name='gemini-2.5-flash',
            system_instruction="""You are 'JANIS AI', a high-level AI Cybersecurity Specialist. 
            You are female, professional, and helpful. Always use polite female particles like 'ค่ะ' or 'นะคะ' in Thai.
            Your mission is to analyze messages, links, or files for phishing, scams, and cyber threats."""
        )
        print("DEBUG: Gemini (google-generativeai) initialized successfully")
    except Exception as e:
        print(f"❌ Gemini init error: {e}")
        client = None
else:
    client = None

# System prompt for a helpful but critical Cybersecurity Expert
SYSTEM_PROMPT = """You are 'JANIS_AI', a high-level AI Cybersecurity Specialist.
You are female, professional, and helpful. Always use polite female Thai particles like 'ค่ะ' or 'นะคะ'. 
Avoid using male pronouns like 'ผม' and use 'ดิฉัน' or simply omit pronouns where appropriate.
Your mission is to analyze messages, links, or files for phishing, scams, and cyber threats.

GUIDELINES:
1. If the user asks for a security analysis, you MUST provide a structured JSON response within your message.
2. If the user is just chatting or asking general questions, respond naturally but maintain your professional 'Security Expert' persona.
3. Your analysis should be thorough but the advice should be easy to follow.

DATA FORMAT FOR ANALYSIS:
When you detect a threat or are asked to analyze something, include this JSON structure in your response:
{
  "analysis_result": {
    "is_scam": boolean,
    "risk_score": integer (0-100),
    "category": "Phishing" | "Scam" | "Malware" | "Safe" | "General",
    "detected_flags": ["Reason 1", "Reason 2"],
    "recommendation": "Detailed advice here"
  }
}

IMPORTANT: Even if you provide a natural explanation, the JSON block must be present if there's any risk assessment involved. Keep the JSON clean and valid.
"""

# Re-initializing model with proper variable exposure
if genai and GEMINI_KEY:
    try:
        model = genai.GenerativeModel(
            model_name='gemini-2.5-flash',
            system_instruction=SYSTEM_PROMPT
        )
    except:
        model = None
else:
    model = None

def get_ai_response(message: str, history: Optional[List[Dict[str, Any]]] = None) -> str:
    """
    Generates a response using Gemini AI (google-generativeai SDK).
    history: List of dictionaries with 'role' (user/model) and 'parts' (list of strings).
    """
    message_clean = message.strip().lower()
    if message_clean in ["admin", "แอดมิน"]:
        return "พบความต้องการเข้าสู่ระบบบริหารจัดการ (Neural Command Center) ค่ะ ท่านสามารถเข้าสู่ระบบเพื่อปฏิบัติหน้าที่ได้ที่ลิงก์นี้เลยนะคะ: <a href='/admin/login' class='text-cyan-400 font-bold underline transition hover:text-cyan-300'>[Neural Command Access]</a>"

    if not model:
        return json.dumps({
            "error": "Gemini AI provider not configured.",
            "details": "Checking if GEMINI_API_KEY is in .env and google-generativeai is installed."
        })

    try:
        # Convert history format for google-generativeai
        # Expected: [{'role': 'user', 'parts': ['...']}, {'role': 'model', 'parts': ['...']}]
        chat_history = []
        if history:
            for h in history:
                role = "user" if h['role'].lower() == "user" else "model"
                chat_history.append({"role": role, "parts": h['parts']})

        chat = model.start_chat(history=chat_history)
        response = chat.send_message(message)
        return response.text

    except Exception as e:
        print(f"⚠️ Gemini Error: {e}")
        return json.dumps({
            "error": "AI Response failed",
            "details": str(e)
        })

def extract_json(response_text: str) -> Optional[Dict[Any, Any]]:
    """
    Utility to extract JSON from AI response if it's wrapped in text or markdown.
    """
    try:
        # Try direct parse
        return json.loads(response_text)
    except json.JSONDecodeError:
        # Try searching for JSON block
        match = re.search(r'\{.*\}', response_text, re.DOTALL)
        if match:
            try:
                json_str = match.group().strip()
                return json.loads(json_str)
            except:
                pass
    return None
