import os
import platform
import threading
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from dotenv import load_dotenv

# We will import these later when they are ready
from app.routes import router as api_router
from app.database import init_db

# Windows monkeypatch for platform.uname() to avoid WMI query hangs
if os.name == 'nt':
    try:
        import collections
        _original_uname = platform.uname
        def mocked_uname():
            UNameResult = collections.namedtuple('uname_result', ['system', 'node', 'release', 'version', 'machine', 'processor'])
            return UNameResult('Windows', 'LOCAL_MACHINE', '10', '10.0.19045', 'AMD64', 'Intel64 Family')
        platform.uname = mocked_uname
    except Exception:
        pass

load_dotenv()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite database (Async)
    await init_db()
    yield

app = FastAPI(
    title="Jerb Cyber Phishing Internship",
    description="ASync FastAPI Backend for Phishing Detection",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Support
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount Static Files
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# Include the endpoints
app.include_router(api_router)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=5000, reload=True)
