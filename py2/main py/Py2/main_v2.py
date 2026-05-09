"""
SpiderAI - Hybrid Digital Forensics & Threat Intelligence Platform
Main Application Entry Point
"""
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.utils import get_openapi
import os
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import routes
from routes import auth, investigations, entities, relationships, graph, threats, timeline, enrichment, websocket, integrations, reconnaissance, osint, ml, agents, global_graph, graph_rag

# Import database
from core.database import init_db, get_db
from core.graph_db import graph_db

# Import models
from models.models import Base

# Create app
app = FastAPI(
    title="SpiderAI Intelligence Platform",
    description="Hybrid Digital Forensics, Threat Hunting, and OSINT Correlation Engine",
    version="1.0.0"
)

# CORS Configuration
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "['http://localhost:3000', 'http://localhost:8000']").strip("'\"[]").split(",")
CORS_ORIGINS = [origin.strip() for origin in CORS_ORIGINS]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change to specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    print("🔧 Initializing database...")
    try:
        init_db()
        print("✅ Database initialized successfully")
        graph_db.connect()
        print("✅ Neo4j Graph Database connected successfully")
    except Exception as e:
        print(f"❌ Error initializing database: {e}")

# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "1.0.0"
    }

# Include routers
app.include_router(auth.router)
app.include_router(investigations.router)
app.include_router(entities.router)
app.include_router(relationships.router)
app.include_router(threats.router)
app.include_router(timeline.router)
app.include_router(enrichment.router)
app.include_router(websocket.router)
app.include_router(integrations.router)
app.include_router(reconnaissance.router)
app.include_router(osint.router)
app.include_router(ml.router)
app.include_router(graph.router)
app.include_router(global_graph.router)
app.include_router(graph_rag.router)
app.include_router(agents.router)

# Custom OpenAPI schema
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="SpiderAI API",
        version="1.0.0",
        description="Enterprise-grade Intelligence Platform API",
        routes=app.routes,
    )
    openapi_schema["info"]["x-logo"] = {
        "url": "https://fastapi.tiangolo.com/img/logo-margin/logo-teal.png"
    }
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": "SpiderAI Intelligence Platform",
        "version": "1.0.0",
        "description": "Hybrid Digital Forensics, Threat Hunting, and OSINT Correlation Engine",
        "docs_url": "/docs",
        "health_url": "/health"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main_v2:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 8000)),
        reload=os.getenv("ENVIRONMENT", "development") == "development"
    )
