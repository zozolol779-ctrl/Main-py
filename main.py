
import os
import logging
from fastapi import FastAPI, Request, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from scapy.all import rdpcap, IP, TCP, UDP
import shutil

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("RedKing_Core")

app = FastAPI(title="Red King C2", version="2.1.0-Intel")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

static_path = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_path): os.makedirs(static_path)
app.mount("/static", StaticFiles(directory=static_path), name="static")

@app.get("/api/health")
async def health_check():
    return {"status": "OPERATIONAL", "module": "PCAP_ANALYZER_ACTIVE"}

# --- PCAP ANALYSIS ENGINE ---
@app.post("/api/analyze-pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    temp_file = f"/tmp/{file.filename}"
    try:
        # حفظ الملف مؤقتاً
        with open(temp_file, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        # تحليل الحزم
        packets = rdpcap(temp_file)
        analysis_report = []
        unique_ips = set()
        detected_os = "Unknown"
        
        # تحليل أول 50 حزمة فقط للسرعة
        for pkt in packets[:50]:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = pkt[IP].proto
                unique_ips.add(src)
                
                # Simple OS Fingerprinting based on TTL
                ttl = pkt[IP].ttl
                if ttl == 64: os_guess = "Linux/Mac/Android"
                elif ttl == 128: os_guess = "Windows"
                elif ttl == 255: os_guess = "Cisco/Network Gear"
                else: os_guess = "Unknown"
                
                summary = {
                    "src": src,
                    "dst": dst,
                    "ttl": ttl,
                    "os_fingerprint": os_guess,
                    "protocol": proto
                }
                analysis_report.append(summary)
        
        return {
            "status": "ANALYSIS_COMPLETE",
            "total_packets": len(packets),
            "unique_targets": list(unique_ips),
            "fingerprints": analysis_report[:10] # إرسال عينة
        }
    except Exception as e:
        return {"error": str(e)}
    finally:
        if os.path.exists(temp_file): os.remove(temp_file)

@app.get("/{full_path:path}")
async def serve_spa(full_path: str):
    if full_path == "" or full_path == "index.html":
        return FileResponse(os.path.join(static_path, "index.html"))
    return FileResponse(os.path.join(static_path, "index.html"))
