#!/usr/bin/env python3
"""
PhantomLog — Log File Analyzer
Tabs: Analyze Log | Detection Reference
"""

import os
import secrets
from flask import Flask, render_template, request, jsonify

from modules import parsers, detectors, report, sample_logs

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

MAX_WEB_LINES = 50_000  # cap for browser-uploaded logs; CLI has no cap


@app.route("/")
def index():
    return render_template("index.html", active="analyze")


@app.route("/reference")
def reference_page():
    return render_template("reference.html", active="reference")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    if "file" in request.files and request.files["file"].filename:
        text = request.files["file"].read().decode("utf-8", errors="replace")
    else:
        data = request.get_json(silent=True) or {}
        text = data.get("log_text", "")

    if not text.strip():
        return jsonify({"error": "No log content provided."}), 400

    log_type = request.form.get("log_type") or (request.get_json(silent=True) or {}).get("log_type", "auto")

    parsed = parsers.parse_log_text(text, log_type=log_type, max_lines=MAX_WEB_LINES)
    findings = detectors.run_all_detectors(parsed["events"])
    full_report = report.build_full_report(parsed["events"], parsed["stats"], findings)

    # Strip raw_line from bulk event list to keep payload size reasonable;
    # findings already carry their own relevant detail/line_number.
    return jsonify(full_report)


@app.route("/api/sample/<kind>")
def api_sample(kind):
    if kind == "access":
        sample = sample_logs.generate_sample_access_log()
    elif kind == "auth":
        sample = sample_logs.generate_sample_auth_log()
    else:
        return jsonify({"error": "Unknown sample kind. Use 'access' or 'auth'."}), 400
    return jsonify({"text": sample["text"], "log_type": kind})


@app.route("/api/status")
def api_status():
    return jsonify({"ok": True})


if __name__ == "__main__":
    print(r"""
   ██████╗██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
   ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
   ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
   ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
   ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
        L O G  —  Apache/Nginx/Auth Log Analyzer
        http://127.0.0.1:5054
    """)
    app.run(debug=True, host="127.0.0.1", port=5054)
