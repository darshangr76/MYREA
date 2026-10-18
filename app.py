from __future__ import annotations
import os
import tempfile
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse

from myrea.analyzer import analyze
from myrea.report import render_markdown

app = FastAPI(title="MyREA", description="Static PE analyzer")


@app.get("/")
def root():
    return {"service": "MyREA", "status": "ok", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/analyze")
async def analyze_pe(file: UploadFile = File(...)):
    """Upload a PE file, get back structured analysis + Markdown report."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    # Save upload to a temp file (LIEF needs a real path)
    suffix = os.path.splitext(file.filename)[1] or ".bin"
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp_path = tmp.name
            content = await file.read()
            tmp.write(content)

        result = analyze(tmp_path, no_disasm=False)
        return JSONResponse({
            "sha256": result.sha256,
            "arch": result.arch,
            "entrypoint_va": hex(result.entrypoint_va),
            "file_size": result.file_size,
            "compile_timestamp": result.compile_timestamp,
            "timestamp_anomaly": result.timestamp_anomaly,
            "has_signature": result.has_signature,
            "has_overlay": result.has_overlay,
            "overlay_size": result.overlay_size,
            "sections": [
                {
                    "name": s.name,
                    "rva": hex(s.rva),
                    "virtual_size": s.virtual_size,
                    "raw_size": s.raw_size,
                    "entropy": s.entropy,
                    "is_executable": s.is_executable,
                    "is_writable": s.is_writable,
                }
                for s in result.sections
            ],
            "findings": result.findings,
            "yara_matches": result.yara_matches,
            "strings": {
                k: v[:20] for k, v in result.strings.items()
            },
            "report_markdown": render_markdown(result),
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
