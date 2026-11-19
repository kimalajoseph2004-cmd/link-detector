import sqlite3
import json
import os
from datetime import datetime, timezone
from typing import List
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from detector import analyze_url

load_dotenv()
APP_API_KEY = os.getenv("APP_API_KEY", "my-secret-auditor-key-2026")

app = FastAPI(title="Enterprise Link & Website Auditor")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "audit_logs.db"


def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                input_url TEXT,
                domain TEXT,
                risk_score INTEGER,
                verdict TEXT,
                reasons TEXT
            )
            """
        )


init_db()


def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != APP_API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: Invalid or missing API key")


@app.get("/")
def health_check():
    return {"status": "online", "service": "Enterprise Link Auditor"}


class ScanRequest(BaseModel):
    url: str


@app.post("/scan", dependencies=[Depends(verify_api_key)])
def scan_link(request: ScanRequest):
    result = analyze_url(request.url)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO scans (timestamp, input_url, domain, risk_score, verdict, reasons) VALUES (?, ?, ?, ?, ?, ?)",
            (now, result["input_url"], result["domain"], result["risk_score"], result["verdict"], json.dumps(result["reasons"])),
        )
    return result


class BulkScanRequest(BaseModel):
    urls: List[str]


@app.post("/scan-bulk", dependencies=[Depends(verify_api_key)])
def scan_bulk_links(request: BulkScanRequest):
    results = []
    for raw_url in request.urls:
        clean_url = raw_url.strip()
        if not clean_url:
            continue
        result = analyze_url(clean_url)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO scans (timestamp, input_url, domain, risk_score, verdict, reasons) VALUES (?, ?, ?, ?, ?, ?)",
                (now, result["input_url"], result["domain"], result["risk_score"], result["verdict"], json.dumps(result["reasons"])),
            )
        results.append(result)
    return results


@app.get("/audit-logs", dependencies=[Depends(verify_api_key)])
def get_audit_logs():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 50").fetchall()
        return [
            {
                "id": r["id"],
                "timestamp": r["timestamp"],
                "input_url": r["input_url"],
                "domain": r["domain"],
                "risk_score": r["risk_score"],
                "verdict": r["verdict"],
                "reasons": json.loads(r["reasons"]),
            }
            for r in rows
        ]
