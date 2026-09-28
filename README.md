# 🛡️ Sentinel AI — Autonomous Security Intelligence Platform

> **Hackathon Demo** | Multi-layer vulnerability scanning, attack chain analysis, and AI-powered remediation.

---

## 🏗️ Architecture

Sentinel AI uses a **LangChain ReAct agent** powered by **Groq Cloud (Llama 3.3 70B)** to autonomously scan targets across four layers:

| Layer      | Tool          | What it Scans                    |
| ---------- | ------------- | -------------------------------- |
| 🌐 Network | python-nmap   | Open ports, services, versions   |
| 🔒 Web     | nikto         | SQL injection, XSS, misconfig   |
| 💻 Code    | bandit+semgrep| Hardcoded secrets, bad patterns  |
| 📹 IoT     | HTTP fingerprint | Camera CVEs (Hikvision/Dahua) |

The agent chains findings together using **NetworkX** to discover multi-step attack paths.

---

## 📋 Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Git
- API Keys: **Groq (free)** — get yours at [console.groq.com](https://console.groq.com)
- Optional: Google Gemini (free), Anthropic (paid), Supabase, NVD (free), Voyage AI or OpenAI

---

## 🚀 Setup

### 1. Install System Dependencies

```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env and fill in your API keys
```

### 3. Start Docker Targets

```bash
docker-compose up -d
```

### 4. Run Database Migrations

Run the SQL in `migrations/001_create_tables.sql` against your Supabase project via the SQL Editor.

### 5. Start the Server

```bash
uvicorn app.main:app --reload
```

Server runs at `http://localhost:8000`

---

## 🎯 Demo Walkthrough

### Scan DVWA (Web)
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "http://localhost:4280", "target_type": "url"}'
```

### Scan OWASP PyGoat (Code)
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://github.com/OWASP/PyGoat", "target_type": "github"}'
```

### Scan Metasploitable (Network)
```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "target_type": "ip"}'
```

### Check Status (poll every 1-2s)
```bash
curl http://localhost:8000/scan/{scan_id}/status
```

### View Dashboard
```bash
curl http://localhost:8000/scan/{scan_id}/dashboard
```

### View Attack Chain
```bash
curl http://localhost:8000/scan/{scan_id}/chain
```

### Chat with Findings
```bash
curl -X POST http://localhost:8000/scan/{scan_id}/chat \
  -H "Content-Type: application/json" \
  -d '{"question": "What is the most critical vulnerability?"}'
```

### Download PDF Report
```bash
curl -o report.pdf http://localhost:8000/scan/{scan_id}/report
```

---

## 📁 Project Structure

```
FUSIONX/
├── app/
│   ├── __init__.py        # Package init
│   ├── main.py            # FastAPI endpoints
│   ├── agent.py           # LangChain ReAct agent
│   ├── tools.py           # Scanner tool implementations
│   ├── engine.py          # Attack chain, risk score, OWASP
│   ├── reporting.py       # PDF report generator
│   ├── config.py          # Configuration & whitelist
│   └── db.py              # Supabase database layer
├── fixtures/              # Sample data for development only
├── migrations/            # Supabase SQL migrations
├── scripts/               # Setup automation
├── docker-compose.yml     # Demo target containers
├── requirements.txt       # Pinned Python dependencies
├── .env.example           # Environment variable template
└── README.md
```

---

## 🔐 Safety Constraints

Target validation allows loopback/private networks and explicitly listed GitHub repositories:
- ✅ DVWA (Docker, localhost)
- ✅ Metasploitable (Docker, localhost)
- ✅ Whitelisted OWASP GitHub repos
- ✅ Private ranges configured in `app/config.py`
- ❌ Other targets → HTTP 400 at the API and scanner boundary

---

## 📊 API Endpoints

| Method | Path                      | Description              |
| ------ | ------------------------- | ------------------------ |
| GET    | `/health`                 | Health check             |
| POST   | `/scan`                   | Start new scan           |
| GET    | `/scan/{id}/status`       | Live scan status         |
| GET    | `/scan/{id}/dashboard`    | Full dashboard data      |
| GET    | `/scan/{id}/chain`        | Attack chain graph       |
| POST   | `/scan/{id}/chat`         | RAG-powered Q&A          |
| GET    | `/scan/{id}/report`       | Download PDF report      |

---

## 🧠 LLM Modes

| Mode | API Key | Cost | Agent |
| ---- | ------- | ---- | ----- |
| 🟢 Groq | `GROQ_API_KEY` | **FREE** | Llama 3.3 70B (fastest) |
| 🟢 Gemini | `GOOGLE_API_KEY` | **FREE** | Gemini 2.0 Flash |
| 🔵 Claude | `ANTHROPIC_API_KEY` | Paid | Claude Sonnet |
| ⚪ Deterministic | None needed | Free | Real scanners in a fixed sequence |

Priority: **Groq → Gemini → Claude → deterministic scanners**. Just add your Groq API key to `.env` to enable AI-powered scanning!

---

**Built for hackathon demo purposes only. Not a production security tool.**

## Local verification and runtime behavior

Install backend dependencies in an activated Python 3.11+ virtual environment with
`python -m pip install -r requirements.txt`. Then run:

```bash
python -m pip check
python -m unittest discover -s tests -v
cd frontend
npm ci
npm run build
npm run lint
```

Run the API with `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`
and the frontend with `npm run dev` in `frontend`.

Real scans require the corresponding executable on PATH: nmap for networks,
Nikto for web scans, Bandit and Semgrep for code, and the TruffleHog v3 binary
for secrets. Missing tools, invalid output, and scanner failures now fail the scan;
a successful scan with no findings stays empty. Backend scans never load fixtures.
Without an LLM key, the same real tools run in a deterministic sequence.
Frontend-only sample data remains available with `VITE_USE_MOCKS=true`.

The regression suite isolates external providers, SMTP, and scanner processes.
It does not verify your external API credentials or installed scanner binaries.
Scheduled email uses each subscription's recipient and only sends completed scans.
Reports for failed or unfinished scans return HTTP 409. Metasploitable HTTP uses
port 4281; DVWA uses port 4280. The API remains intended for local development.

The Groq model can be selected with `GROQ_MODEL`; the default is
`llama-3.3-70b-versatile`, listed in the
[Groq model documentation](https://console.groq.com/docs/model/llama-3.3-70b-versatile).

## Windows scanner installation on this machine

Project-local tools are discovered automatically by `app/scanner_runtime.py`;
activating a global PATH is unnecessary. The isolated `.scanner-venv` contains
Bandit 1.9.4 and Semgrep 1.178.0, pinned in `requirements-scanners.txt`.
`.tools` contains TruffleHog 3.97.9 and Nmap 7.991. Nmap uses TCP connect scans
on Windows, without requiring Npcap. These local installations are git-ignored.

```powershell
.\venv\Scripts\python.exe scripts/check_scanners.py
.\venv\Scripts\python.exe scripts/smoke_scanners.py
```

The smoke test uses temporary local code and a loopback server. It neither scans
external targets nor uses provider credentials. Nikto's official source was
downloaded, but Windows Defender quarantined `program/nikto.pl`. Web scanning
remains unavailable unless that specific detection is reviewed and allowed.
No antivirus exclusions or protection settings were changed during setup.
