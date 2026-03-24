import os
import asyncio
from fastapi import APIRouter, Request, Form, Response, Depends, status
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from urllib.parse import urlparse

from app.core.database import get_db_connection
from app.domain_checker import analyze_domain
from app.brain import get_ai_response, extract_json

router = APIRouter()
_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates = Jinja2Templates(directory=os.path.join(_BASE, "templates"))

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

# ==== STATIC PAGES (NEWS / INFO) ====
@router.get("/news", response_class=HTMLResponse)
async def news(request: Request): return templates.TemplateResponse(request=request, name="news.html")

@router.get("/about", response_class=HTMLResponse)
async def about(request: Request): return templates.TemplateResponse(request=request, name="about.html")

@router.get("/news/{category}", response_class=HTMLResponse)
async def news_category(request: Request, category: str): 
    return templates.TemplateResponse(request=request, name=f"news_{category}.html")

@router.get("/tools/{tool_name}", response_class=HTMLResponse)
async def tools_page(request: Request, tool_name: str):
    return templates.TemplateResponse(request=request, name=f"{tool_name}.html")

@router.get("/contact", response_class=HTMLResponse)
async def contact(request: Request): return templates.TemplateResponse(request=request, name="contact.html")

@router.get("/contact/{sub_page}", response_class=HTMLResponse)
async def contact_sub(request: Request, sub_page: str): 
    return templates.TemplateResponse(request=request, name=f"contact_{sub_page}.html")

@router.get("/report", response_class=HTMLResponse)
async def report_get(request: Request):
    return templates.TemplateResponse(request=request, name="report.html", context={
        "google_client_id": os.getenv("GOOGLE_CLIENT_ID")
    })

@router.post("/report", response_class=HTMLResponse)
async def report_post(request: Request, email: str = Form(...), url: str = Form(None), description: str = Form(None), type: str = Form(None)):
    print(f"REPORT RECEIVED: Email={email}, Type={type}, URL={url}")
    return templates.TemplateResponse(request=request, name="report.html", context={
        "success": f"ขอบคุณสำหรับการแจ้งเบาะแสคุณ {email}! เราจะตรวจสอบโดยเร็วที่สุด",
        "google_client_id": os.getenv("GOOGLE_CLIENT_ID")
    })

@router.get("/detect/fb", response_class=HTMLResponse)
async def detect_fb(request: Request):
    return templates.TemplateResponse(request=request, name="detect_fb.html", context={
        "google_client_id": os.getenv("GOOGLE_CLIENT_ID")
    })


# ==== API ENDPOINTS (ASYNC) ====
@router.post("/check")
async def check_url(request: Request):
    data = await request.json()
    url = data.get('url') if data else None

    if not url:
        return JSONResponse({'error': 'No URL provided'}, status_code=400)

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path

    # Run blocking analyze_domain in a thread to keep FastAPI non-blocking
    result = await asyncio.to_thread(analyze_domain, domain)
    
    return result

@router.post("/scan")
async def scan_url(request: Request):
    data = await request.json()
    url = data.get('url')
    
    if not url:
        return JSONResponse({'error': 'No URL provided'}, status_code=400)

    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    
    analysis = await asyncio.to_thread(analyze_domain, domain)
    score = analysis.get('score', 0)
    
    is_safe = score < 50
    
    response = {
        'status': 'safe' if is_safe else 'danger',
        'site_name': domain,
        'message': 'ตรวจสอบเรียบร้อย' if is_safe else 'ตรวจพบสัญญาณอันตราย',
        'risk_score': score,
        'details': {
            'threat_level': analysis.get('risk', 'Unknown'),
            'category': 'Phishing / Scam' if not is_safe else 'Safe',
            'target_brand': 'Unknown',
            'official_url': None,
            'reasons': analysis.get('details', [])
        }
    }
    return response

# ==== CHATBOT ENDPOINTS ====
@router.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request):
    return templates.TemplateResponse(request=request, name='chat.html')

@router.post("/chat")
async def chat_post(request: Request):
    message = None
    if request.headers.get("Content-Type") == "application/json":
        data = await request.json()
        message = data.get("message")
    else:
        form = await request.form()
        message = form.get("message")

    if not message:
        return JSONResponse({'error': 'No message provided'}, status_code=400)

    # Simplified chat: no session-based history for now
    ai_response_raw = await asyncio.to_thread(get_ai_response, message, [])
    
    # Check if the raw response is an error JSON generated by brain.py
    import json
    try:
        parsed_raw = json.loads(ai_response_raw)
        if "error" in parsed_raw:
            return parsed_raw
    except:
        pass
        
    analysis = extract_json(ai_response_raw)
    
    if analysis and "analysis_result" in analysis:
        return {
            "response": ai_response_raw,
            "analysis_result": analysis["analysis_result"]
        }
    else:
        return {
            "response": ai_response_raw,
            "analysis_result": None
        }
