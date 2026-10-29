#!/usr/bin/env python3
"""ZeroTrace-OS local web dashboard."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import uuid
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from queue import Queue, Empty

from flask import Flask, Response, jsonify, render_template, request, send_file

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "app" / "engine.py"
AUDIT = ROOT / "audit_output" / "last_sanitization.json"
CERT_DIR = ROOT / "certificates"

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

jobs: dict[str, dict] = {}
lock = threading.Lock()


def run_engine_json() -> list[dict]:
    p = subprocess.run([sys.executable, str(ENGINE), "json"], cwd=ROOT,
                       text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or "Engine failed")
    return json.loads(p.stdout)


def enrich_devices(items: list[dict]) -> list[dict]:
    return items


def start_job(command: list[str], kind: str) -> str:
    job_id = uuid.uuid4().hex
    q: Queue[str | None] = Queue()
    with lock:
        jobs[job_id] = {"queue": q, "status": "RUNNING", "kind": kind, "return_code": None,
                        "started_at": datetime.now(timezone.utc).isoformat()}

    def worker():
        try:
            proc = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, bufsize=1)
            assert proc.stdout is not None
            for line in proc.stdout:
                q.put(line.rstrip("\n"))
            rc = proc.wait()
            with lock:
                jobs[job_id]["return_code"] = rc
                jobs[job_id]["status"] = "SUCCESS" if rc == 0 else "FAILED"
                jobs[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        except Exception as exc:
            q.put(f"ERROR: {exc}")
            with lock:
                jobs[job_id]["return_code"] = -1
                jobs[job_id]["status"] = "FAILED"
                jobs[job_id]["completed_at"] = datetime.now(timezone.utc).isoformat()
        finally:
            q.put(None)

    threading.Thread(target=worker, daemon=True).start()
    return job_id


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/devices")
def devices():
    try:
        return jsonify({"devices": enrich_devices(run_engine_json())})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.get("/api/device/<path:device_path>")
def device_detail(device_path: str):
    target = "/" + device_path if not device_path.startswith("/") else device_path
    try:
        items = run_engine_json()
        for item in items:
            if item["device"]["path"] == target:
                return jsonify(item)
        return jsonify({"error": "Device not found"}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.post("/api/demo")
def demo():
    data = request.get_json(force=True)
    device = data.get("device")
    if not device:
        return jsonify({"error": "device is required"}), 400
    return jsonify({"job_id": start_job([sys.executable, str(ENGINE), "demo", device], "demo")})


@app.post("/api/sanitize")
def sanitize():
    data = request.get_json(force=True)
    required = ["device", "model", "serial", "size", "confirm_path"]
    missing = [k for k in required if not str(data.get(k, "")).strip()]
    if missing or not data.get("acknowledge"):
        return jsonify({"error": "All identity confirmations and destructive acknowledgement are required."}), 400
    try:
        size = int(data["size"])
    except ValueError:
        return jsonify({"error": "Invalid device size."}), 400
    cmd = [sys.executable, str(ENGINE), "execute", data["device"],
           "--confirm-device", data["device"], "--confirm-model", data["model"],
           "--confirm-serial", data["serial"], "--confirm-size", str(size),
           "--i-understand-this-is-destructive", "--confirm-path", data["confirm_path"]]
    return jsonify({"job_id": start_job(cmd, "sanitize")})


@app.get("/api/jobs/<job_id>/events")
def job_events(job_id: str):
    with lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Unknown job"}), 404
    q: Queue = job["queue"]

    def stream():
        while True:
            try:
                item = q.get(timeout=20)
            except Empty:
                yield ": keepalive\n\n"
                continue
            if item is None:
                with lock:
                    state = {k: v for k, v in jobs[job_id].items() if k != "queue"}
                yield f"event: done\ndata: {json.dumps(state)}\n\n"
                break
            yield f"data: {json.dumps({'line': item})}\n\n"

    return Response(stream(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/jobs/<job_id>")
def job_status(job_id: str):
    with lock:
        job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Unknown job"}), 404
    return jsonify({k: v for k, v in job.items() if k != "queue"})


@app.post("/api/verify-wipe")
def verify_wipe():
    data = request.get_json(force=True)
    device = data.get("device")
    if not device:
        return jsonify({"error": "device is required"}), 400
    audit = data.get("audit") or str(AUDIT)
    return jsonify({"job_id": start_job([sys.executable, str(ENGINE), "verify-wipe", device, audit], "verify")})


@app.post("/api/certificate")
def certificate():
    audit = request.get_json(force=True).get("audit") or str(AUDIT)
    return jsonify({"job_id": start_job([sys.executable, str(ENGINE), "certificate", audit], "certificate")})


@app.post("/api/verify-certificate")
def verify_certificate():
    data = request.get_json(force=True)
    path = data.get("path") or str(CERT_DIR / "sanitization_certificate.json")
    try:
        p = subprocess.run([sys.executable, str(ENGINE), "verify-certificate", path], cwd=ROOT,
                           text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
        return jsonify({"verified": p.returncode == 0, "message": p.stdout.strip(), "return_code": p.returncode})
    except Exception as exc:
        return jsonify({"verified": False, "message": str(exc)}), 500


@app.post("/api/verify-certificate-upload")
def verify_certificate_upload():
    uploaded = request.files.get("certificate")
    if uploaded is None or not uploaded.filename:
        return jsonify({"verified": False, "message": "Please choose a signed certificate JSON file."}), 400

    filename = uploaded.filename.lower()
    if not filename.endswith(".json"):
        return jsonify({
            "verified": False,
            "message": "Cryptographic verification requires the signed certificate JSON. The PDF is a presentation copy; upload the matching .json certificate.",
        }), 400

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(prefix="zerotrace_cert_", suffix=".json", delete=False) as tmp:
            temp_path = Path(tmp.name)
            uploaded.save(tmp)

        p = subprocess.run(
            [sys.executable, str(ENGINE), "verify-certificate", str(temp_path)],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20,
        )
        message = p.stdout.strip() or "Certificate verification failed."
        return jsonify({
            "verified": p.returncode == 0,
            "message": message,
            "return_code": p.returncode,
            "filename": uploaded.filename,
        })
    except json.JSONDecodeError:
        return jsonify({"verified": False, "message": "The uploaded file is not valid JSON."}), 400
    except Exception as exc:
        return jsonify({"verified": False, "message": str(exc)}), 500
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass


@app.get("/api/history")
def history():
    records = []
    if AUDIT.exists():
        try:
            records.append({"type": "sanitization", "data": json.loads(AUDIT.read_text())})
        except Exception:
            pass
    demo_dir = ROOT / "demo_output"
    for p in sorted(demo_dir.glob("*.json"), reverse=True) if demo_dir.exists() else []:
        try:
            records.append({"type": "demo", "data": json.loads(p.read_text())})
        except Exception:
            pass
    return jsonify({"records": records})


@app.get("/api/certificate/pdf")
def certificate_pdf():
    p = CERT_DIR / "sanitization_certificate.pdf"
    if not p.exists():
        return jsonify({"error": "Certificate PDF not found."}), 404
    return send_file(p, as_attachment=True, download_name=p.name)


@app.get("/api/certificate/json")
def certificate_json():
    p = CERT_DIR / "sanitization_certificate.json"
    if not p.exists():
        return jsonify({"error": "Certificate JSON not found."}), 404
    return send_file(p, as_attachment=True, download_name=p.name)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
