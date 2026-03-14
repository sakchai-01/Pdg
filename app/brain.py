import os
import json
import re
from dotenv import load_dotenv

try:
    from google import genai
except ImportError:
    genai = None

load_dotenv()
GEMINI_KEY = os.getenv("GEMINI_API_KEY")

if genai and GEMINI_KEY:
    try:
        client = genai.Client(api_key=GEMINI_KEY)
    except Exception as e:
        print(f"❌ Gemini init error: {e}")
        client = None
else:
    client = None

# System prompt for a helpful but critical Cybersecurity Expert
SYSTEM_PROMPT = """You are 'SECURITY_EXPERT', a high-level AI Cybersecurity Specialist.
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

def get_ai_response(message: str, history: list = None) -> str:
    """
    Generates a response using Gemini AI, considering conversation history.
    history: List of dictionaries with 'role' and 'parts' keys.
    """
    if not client:
        return json.dumps({
            "error": "Gemini AI provider not configured.",
            "details": "Check GEMINI_API_KEY in .env or pip install google-genai"
        })

    try:
        # Use a more capable/stable model name
        
        # We prepend the system prompt if history is empty to set the persona
        # The new SDK doesn't natively expose 'start_chat' exactly like the old one without explicit history parsing
        # For simplicity, we implement a naive history concatenation.
        
        contents = []
        if history:
            for msg in history:
                contents.append(f"{msg['role'].capitalize()}: {msg['parts'][0]}")
        else:
            contents.append(f"System: {SYSTEM_PROMPT}")

        contents.append(f"User: {message}")
        prompt = "\n\n".join(contents)
                
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
        )
        return response.text

    except Exception as e:
        print(f"⚠️ Gemini Error: {e}")
        return json.dumps({
            "error": "AI Response failed",
            "details": str(e)
        })

def extract_json(response_text: str) -> dict:
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
                return json.loads(match.group())
            except:
                pass
    return None
