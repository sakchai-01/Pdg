import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from app.routes import router as api_router
from app.core.database import init_db

# Only apply Windows patches when running locally on Windows
if os.name == 'nt':
    try:
        from app.core.compat import apply_windows_patches
        apply_windows_patches()
    except Exception:
        pass

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Database init: skip gracefully if filesystem is read-only (e.g., Vercel)
    try:
        await init_db()
    except Exception as e:
        print(f"⚠️ DB init skipped: {e}")
    yield

app = FastAPI(
    title="Jerb Cyber Phishing Internship",
    description="ASync FastAPI Backend for Phishing Detection",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Support - Tightened for Security (Add production domains here)
# For extension development, we allow all origins or specifically chrome-extension://*
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # For extension development, use * or specific extension IDs
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self' https://accounts.google.com https://fonts.googleapis.com https://fonts.gstatic.com; script-src 'self' 'unsafe-inline' https://accounts.google.com https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; frame-src https://accounts.google.com"
    return response

if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(api_router)

if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", 5000))
    uvicorn.run("main:app", host=host, port=port, reload=True)
