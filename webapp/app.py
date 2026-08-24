"""Flask web front-end for APK Sentinel.

Flow: a user uploads an APK on ``/`` -> it is analysed -> the report is
persisted under an instance results directory -> the user is redirected to
``/report/<id>`` where they can view and download the HTML / Markdown / JSON.

The engine (``apk_sentinel``) is dependency-free; Flask is only the transport.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import uuid
from datetime import datetime, timezone

# Make the sibling engine package importable when run from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import (  # noqa: E402
    Flask, abort, redirect, render_template, request, send_file, url_for,
)
from werkzeug.utils import secure_filename  # noqa: E402

from apk_sentinel import __version__  # noqa: E402
from apk_sentinel.analyzer import analyze_apk  # noqa: E402
from apk_sentinel.report import render_html, render_json, render_markdown  # noqa: E402

MAX_UPLOAD_MB = int(os.environ.get("APK_SENTINEL_MAX_MB", "350"))
ALLOWED_EXT = {".apk"}


def _instance_dir() -> str:
    base = os.environ.get("APK_SENTINEL_DATA") or os.path.join(
        tempfile.gettempdir(), "apk_sentinel_web"
    )
    os.makedirs(base, exist_ok=True)
    return base


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
    results_root = os.path.join(_instance_dir(), "results")
    os.makedirs(results_root, exist_ok=True)

    # -- helpers --------------------------------------------------------
    def result_dir(rid: str) -> str:
        # rid is a uuid4 hex; reject anything else to prevent path traversal.
        if not rid or len(rid) != 32 or not all(ch in "0123456789abcdef" for ch in rid):
            abort(404)
        d = os.path.join(results_root, rid)
        if not os.path.isdir(d):
            abort(404)
        return d

    def load_meta(rid: str) -> dict:
        # A present-but-corrupt meta.json must not 500 a view; degrade to {}.
        try:
            with open(os.path.join(result_dir(rid), "meta.json"), encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    # -- routes ---------------------------------------------------------
    @app.get("/")
    def index():
        return render_template("index.html", max_mb=MAX_UPLOAD_MB, version=__version__,
                               recent=_recent_scans(results_root))

    @app.post("/analyze")
    def analyze():
        file = request.files.get("apk")
        if not file or not file.filename:
            return render_template("error.html", message="No file was uploaded."), 400
        _, ext = os.path.splitext(file.filename.lower())
        if ext not in ALLOWED_EXT:
            return render_template(
                "error.html",
                message=f"Unsupported file type '{ext or '?'}'. Please upload a .apk file.",
            ), 400

        rid = uuid.uuid4().hex
        rdir = os.path.join(results_root, rid)
        os.makedirs(rdir, exist_ok=True)
        tmp_apk = os.path.join(rdir, secure_filename(file.filename) or "upload.apk")
        file.save(tmp_apk)

        try:
            result = analyze_apk(tmp_apk)
        except Exception as exc:
            shutil.rmtree(rdir, ignore_errors=True)
            return render_template(
                "error.html",
                message=f"Could not analyse this file: {exc}",
            ), 400
        finally:
            # keep reports, drop the (potentially large) APK once analysed
            try:
                os.remove(tmp_apk)
            except OSError:
                pass

        try:
            nav = _report_nav(rid)
            with open(os.path.join(rdir, "report.html"), "w", encoding="utf-8") as fh:
                fh.write(render_html(result, nav_html=nav))
            with open(os.path.join(rdir, "report.md"), "w", encoding="utf-8") as fh:
                fh.write(render_markdown(result))
            with open(os.path.join(rdir, "report.json"), "w", encoding="utf-8") as fh:
                fh.write(render_json(result))
            meta = {
                "id": rid,
                "file_name": result.file_name,
                "package": result.manifest.package,
                "grade": result.grade,
                "risk_score": result.risk_score,
                "severity_counts": result.severity_counts,
                "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
            # Write meta.json atomically (temp + replace) so a crash mid-write
            # can never leave a truncated file that breaks the home page.
            tmp_meta = os.path.join(rdir, "meta.json.tmp")
            with open(tmp_meta, "w", encoding="utf-8") as fh:
                json.dump(meta, fh)
            os.replace(tmp_meta, os.path.join(rdir, "meta.json"))
        except Exception as exc:
            shutil.rmtree(rdir, ignore_errors=True)
            return render_template(
                "error.html",
                message=f"The report could not be written: {exc}",
            ), 500

        return redirect(url_for("report", rid=rid))

    @app.get("/report/<rid>")
    def report(rid):
        d = result_dir(rid)
        with open(os.path.join(d, "report.html"), encoding="utf-8") as fh:
            return fh.read()

    @app.get("/report/<rid>/download/<fmt>")
    def download(rid, fmt):
        d = result_dir(rid)
        mapping = {
            "html": ("report.html", "text/html"),
            "md": ("report.md", "text/markdown"),
            "json": ("report.json", "application/json"),
        }
        if fmt not in mapping:
            abort(404)
        fname, mime = mapping[fmt]
        path = os.path.join(d, fname)
        if not os.path.isfile(path):
            abort(404)
        meta = load_meta(rid)
        stem = (meta.get("package") or "apk-sentinel").replace(".", "_")
        return send_file(path, mimetype=mime, as_attachment=(fmt != "html"),
                         download_name=f"{stem}.report.{fmt}")

    @app.get("/health")
    def health():
        return {"status": "ok", "engine": __version__}

    @app.errorhandler(413)
    def too_large(_e):
        return render_template(
            "error.html",
            message=f"That file is larger than the {MAX_UPLOAD_MB} MB limit.",
        ), 413

    return app


def _report_nav(rid: str) -> str:
    return (
        "<div style='position:sticky;top:0;z-index:50;display:flex;gap:10px;align-items:center;"
        "justify-content:space-between;background:#0b1220;color:#fff;padding:10px 18px;font:14px system-ui'>"
        "<a href='/' style='color:#9fc0ff;text-decoration:none;font-weight:600'>&larr; Analyze another APK</a>"
        "<span style='display:flex;gap:8px'>"
        f"<a href='/report/{rid}/download/html' style='color:#fff;background:#1f2b45;padding:6px 12px;border-radius:8px;text-decoration:none'>Download HTML</a>"
        f"<a href='/report/{rid}/download/md' style='color:#fff;background:#1f2b45;padding:6px 12px;border-radius:8px;text-decoration:none'>Markdown</a>"
        f"<a href='/report/{rid}/download/json' style='color:#fff;background:#1f2b45;padding:6px 12px;border-radius:8px;text-decoration:none'>JSON</a>"
        "</span></div>"
    )


def _recent_scans(results_root: str, limit: int = 8):
    out = []
    try:
        entries = [os.path.join(results_root, d) for d in os.listdir(results_root)]
    except OSError:
        return out
    entries = [d for d in entries if os.path.isdir(d)]
    entries.sort(key=lambda d: os.path.getmtime(d), reverse=True)
    for d in entries[:limit]:
        try:
            with open(os.path.join(d, "meta.json"), encoding="utf-8") as fh:
                out.append(json.load(fh))
        except (OSError, ValueError):
            # OSError = missing/unreadable; ValueError = corrupt/truncated JSON.
            # Either way, skip this entry rather than 500 the whole home page.
            continue
    return out


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=False)
