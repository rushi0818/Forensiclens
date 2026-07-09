import sys  
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, jsonify
from forensics.memory_analyzer    import run_full_memory_analysis
from forensics.artifact_collector import run_full_artifact_collection
from forensics.timeline_builder   import build_timeline
from forensics.hash_verifier      import compute_file_hashes, verify_hash, create_evidence_log

app           = Flask(__name__)
UPLOAD_FOLDER = "uploads"
REPORTS_FOLDER= "reports"
os.makedirs(UPLOAD_FOLDER,  exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan/memory", methods=["POST"])
def scan_memory():
    """Memory dump analysis."""
    if "file" not in request.files:
        return render_template("index.html", error="No file uploaded", tab="memory")
    file = request.files["file"]
    if file.filename == "":
        return render_template("index.html", error="No file selected", tab="memory")
    save_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(save_path)
    result = run_full_memory_analysis(save_path)
    result['filename'] = file.filename
    return render_template("index.html", result=result, tab="memory", module="memory")


@app.route("/scan/artifacts", methods=["POST"])
def scan_artifacts():
    """Live system artifact collection."""
    result = run_full_artifact_collection()
    return render_template("index.html", result=result, tab="artifacts", module="artifacts")


@app.route("/scan/timeline", methods=["POST"])
def scan_timeline():
    """Timeline analysis."""
    log_file = None
    if "file" in request.files and request.files["file"].filename:
        file      = request.files["file"]
        log_file  = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(log_file)
    result = build_timeline(log_file=log_file)
    return render_template("index.html", result=result, tab="timeline", module="timeline")


@app.route("/scan/hash", methods=["POST"])
def scan_hash():
    """Hash verification and evidence logging."""
    if "file" not in request.files:
        return render_template("index.html", error="No file uploaded", tab="hash")
    file          = request.files["file"]
    expected_hash = request.form.get("expected_hash", "").strip()
    case_number   = request.form.get("case_number", "CASE-001").strip()
    save_path     = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(save_path)

    hashes       = compute_file_hashes(save_path)
    evidence_log = create_evidence_log(save_path, case_number)

    result = {
        'scan_type'    : 'Hash Verification & Evidence Log',
        'filename'     : file.filename,
        'hashes'       : hashes,
        'evidence_log' : evidence_log,
        'verdict'      : 'VERIFIED',
        'is_phishing'  : False,
        'confidence'   : 100,
        'threat_score' : 0,
        'reasons'      : [],
    }

    if expected_hash:
        verification   = verify_hash(save_path, expected_hash)
        result['verification'] = verification
        if not verification.get('verified'):
            result['verdict']     = 'TAMPERED'
            result['is_phishing'] = True
            result['confidence']  = 99
            result['reasons']     = ['Hash mismatch detected — evidence may be tampered!']

    if evidence_log.get('vt_result', {}).get('malicious', 0) > 3:
        result['verdict']     = 'MALICIOUS'
        result['is_phishing'] = True

    return render_template("index.html", result=result, tab="hash",
                           module="hash", hashes=hashes, evidence_log=evidence_log)


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  ForensicLens — Digital Forensics Toolkit")
    print("  By: Ritesh Vijay Bavaskar")
    print("  Open: http://127.0.0.1:5002")
    print("="*55 + "\n")
    app.run(debug=True, port=5002)
