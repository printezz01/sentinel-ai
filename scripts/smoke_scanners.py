"""Exercise installed scanners against generated local data and loopback only."""
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
# Keep the application integration check offline and in-memory.
for key in ("SUPABASE_URL", "SUPABASE_SERVICE_KEY", "GROQ_API_KEY", "GOOGLE_API_KEY",
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "VOYAGE_API_KEY", "SMTP_USER", "SMTP_PASS"):
    os.environ[key] = ""
from app.scanner_runtime import scanner_command


def run(name, args, codes=(0,)):
    result = subprocess.run([*scanner_command(name), *args], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90)
    if result.returncode not in codes:
        raise RuntimeError(f"{name}: exit {result.returncode}: {result.stderr[-2000:]}")
    return result.stdout


with tempfile.TemporaryDirectory(prefix="fusionx-smoke-") as directory:
    root = Path(directory)
    sample = root / "sample.py"
    sample.write_text("import pickle\npickle.loads(b'example')\n", encoding="utf-8")
    output = json.loads(run("bandit", ["-r", directory, "-f", "json", "-ll"], (0, 1)))
    assert output["results"], "Bandit did not detect the test pattern"
    print(f"Bandit: detected {len(output['results'])} test findings")
    rules = root / "rules.yaml"
    rules.write_text("rules:\n  - id: smoke-pickle\n    pattern: pickle.loads(...)\n    message: Test unsafe deserialization\n    languages: [python]\n    severity: WARNING\n", encoding="utf-8")
    output = json.loads(run("semgrep", ["scan", "--config", str(rules), "--metrics=off", "--disable-version-check", "--json", str(sample)]))
    assert output["results"], "Semgrep did not detect the test pattern"
    print(f"Semgrep: detected {len(output['results'])} test findings")
    clean = root / "clean"
    clean.mkdir()
    (clean / "README.txt").write_text("A local test with no credentials.", encoding="utf-8")
    output = run("trufflehog", ["filesystem", str(clean), "--no-verification", "--no-update", "--json"])
    assert not output.strip(), "Unexpected secret findings in clean sample"
    print("TruffleHog: clean sample correctly returned zero findings")

    class Handler(BaseHTTPRequestHandler):
        def handle(self):
            try:
                super().handle()
            except ConnectionResetError:
                pass
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"FUSIONX local scanner test")
        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        port = server.server_address[1]
        output = run("nmap", ["-sT", "-Pn", "-p", str(port), "-oX", "-", "127.0.0.1"])
        assert 'state="open"' in output, "Nmap did not detect the local test server"
        print(f"Nmap: detected local test server on port {port}")
        from app.tools import scan_web
        from app.db import create_scan_session, get_findings, new_uuid
        scan_id = new_uuid()
        target = f"http://127.0.0.1:{port}"
        create_scan_session(scan_id, target, "url")
        findings = scan_web(target, scan_id, plugins="headers")
        assert findings and len(get_findings(scan_id)) == len(findings)
        print(f"Nikto: FUSIONX ingested {len(findings)} real findings from localhost")
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
