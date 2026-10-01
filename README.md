# SENTINEL AI

**Autonomous Multi-Layer Security Intelligence Platform**  
**Team Triumph · ASYNC'26 · Cybersecurity & Defense**


SENTINEL AI is a defensive security platform that brings findings from different security tools into one place, correlates related weaknesses, and shows how they could combine into a possible attack path.

Most security tools are good at finding individual issues. The harder problem is understanding whether those issues are connected, what they could lead to, and which fix could break the path first.

> **The scanners find the pieces. SENTINEL connects the attack path.**

---

## Problem

Security teams often use separate tools for network scanning, web testing, code analysis, secret detection, and CVE lookup. Each tool reports findings independently.

A scanner may detect an exposed service. Another may find a weak web configuration. A code scanner may identify insecure code, while a secret scanner may discover an exposed credential.

When these findings are reviewed one by one, they may not look capable of causing a major compromise. The real risk can appear when one weakness gives an attacker the access or capability needed to use the next weakness.

SENTINEL therefore asks a different question:

**Can these separate weaknesses be combined into a possible attacker route through the system?**

---

## What SENTINEL Does

SENTINEL accepts an authorized target, selects the relevant security scanners, converts their outputs into a common finding format, and correlates the findings using relationships such as reachability, asset relationships, access prerequisites, and capabilities gained.

The platform provides:

- unified findings across multiple security layers,
- interactive attack-path graphs,
- contextual risk and remediation guidance,
- an AI assistant grounded in the actual scan data,
- downloadable PDF security reports,
- scan history showing what is new, resolved, or unchanged across rescans.

If the evidence does not support a relationship, SENTINEL leaves the findings disconnected. It does not force every vulnerability into an attack chain.

---

## System Architecture


SENTINEL combines specialized security tools instead of trying to replace them.

**Execution flow:**

`Target → Agent / Tool Orchestration → Security Scanners → Normalized Findings → Vulnerability Enrichment → Correlation Engine → NetworkX Attack Graph → Risk / Remediation → Dashboard / AI / PDF / Scan History`

The AI layer does not blindly invent attack paths. Scanner evidence is normalized first. Correlation logic establishes supported relationships, and graph logic constructs and analyzes possible paths. The AI is then used for orchestration, explanation, question answering, and remediation guidance.

---

## How Vulnerabilities Are Discovered

SENTINEL does not use one scanner for every target. It routes the target to the relevant tools.

- **Nmap** identifies exposed ports, services, and service versions for network targets.
- **Nikto** checks web servers for security weaknesses and misconfigurations.
- **Semgrep** performs static analysis for insecure coding patterns.
- **Bandit** performs Python-focused security analysis.
- **TruffleHog** searches repositories for exposed secrets and credentials.
- **NVD API** enriches relevant findings with known CVE information.

The outputs from these tools are converted into a common internal finding format so findings from different layers can be compared and correlated.

---

## Attack-Path Intelligence

The main value of SENTINEL appears when separate findings can support one another.

A simplified example is:

```text
Web weakness
    ↓
Application access
    ↓
Exposed credential
    ↓
Reachable database
    ↓
Sensitive data access
```

Individually, these findings may look like separate security issues. Together, they may reveal how an attacker could move through the system.

SENTINEL checks whether one finding creates the access, condition, or capability needed for another finding to become useful. Supported relationships become edges in the graph. Unsupported findings remain isolated.

In the attack graph:

- **node** = a real finding from the scan,
- **edge** = a supported security relationship between findings,
- **isolated node** = a finding for which SENTINEL has not established a supported connection to the current path.

This lets analysts focus on **connected risk**, not only individual severity scores.

---

## AI Security Assistant

Each completed scan can be queried through SENTINEL's AI assistant.

The assistant is grounded in the scan findings and stored security context, allowing analysts to ask questions such as:

```text
Explain this scan in simple terms.
```

```text
Explain this attack path and tell me where I should break the chain.
```

```text
What should I fix first and why?
```

The assistant is intended to simplify technical evidence, explain attack-path context, and provide remediation guidance rather than act as a generic chatbot.

---

## Scan History

SENTINEL compares repeated scans of the same target so analysts can see whether remediation actually changed the security posture.

It can show:

- **New findings** — detected now but not in the previous scan,
- **Resolved findings** — previously detected but no longer present,
- **Unchanged findings** — present in both scans,
- changes in critical findings and contextual risk,
- whether an attack path appeared, remained, or disappeared.

This creates a simple remediation loop:

`Scan → Fix → Rescan → Verify`

---

## Core Technology

### Frontend

- **React**
- **Tailwind CSS**
- **Cytoscape.js** for attack-graph visualization

### Backend and orchestration

- **Python 3.11+**
- **FastAPI**
- **LangChain / LangGraph**

### Security and intelligence

- **Nmap**
- **Nikto**
- **Semgrep**
- **Bandit**
- **TruffleHog**
- **NVD API**
- **NetworkX** for attack-graph construction and analysis

### Data

- **Supabase / PostgreSQL** for scan sessions, findings, attack paths, risk data, and scan history
- **LLM APIs** for grounded explanation, remediation, and natural-language interaction

---

## Supported Targets and Safety

SENTINEL is intended only for defensive and authorized security testing.

Supported targets include:

- HTTP/HTTPS web applications,
- public GitHub repositories,
- localhost,
- private IP ranges and controlled lab networks.

Current safety boundaries:

- public IP and public subnet scanning is blocked,
- malformed targets are rejected,
- private GitHub repositories are not supported without authenticated GitHub access,
- scans should only be run against systems you own or are explicitly authorized to test.

---

## Demo and Deployment

**Demo video:** https://youtu.be/aXEQfGe7hQw

**Frontend (Vercel):** https://sentinel-ai-psi-seven.vercel.app/  
**Backend (Render):**  https://dashboard.render.com/web/srv-dat7r3d9fdbs7381s7dg/deploys
**Supabase project:** https://maqwujyaosetzwqasmbq.supabase.co

Recommended demo flow:

`Authorized scan → Findings → Attack Paths → AI explanation → PDF report → Scan History → Chained repository → Correlated attack path → Remediation`

---

## Setup

### Prerequisites

- Python **3.11+**
- Node.js **20+**
- Git
- Docker / Docker Compose for local vulnerable targets
- required scanner binaries for the scan types you want to run

**Hardware:** No GPU is required. SENTINEL is designed to run on a normal development machine capable of running the Python backend, Node.js frontend, scanner binaries, and Docker when local lab targets are used.

### 1. Clone the repository

```bash
git clone <repo-url>
cd <repository-folder>
```

### 2. Create the Python environment

```bash
python -m venv venv
```

Activate the environment and install backend dependencies:

```bash
python -m pip install -r requirements.txt
```

### 3. Configure environment variables

```bash
cp .env.example .env
```

Fill in only the services used by your deployment.

### 4. Run database migrations

Apply the SQL migrations in the `migrations/` directory to the Supabase project if Supabase persistence is enabled.

### 5. Start the backend

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 6. Start the frontend

```bash
cd frontend
npm ci
npm run dev
```

---

## Environment Variables

| Variable | Type | Default | Required | Purpose |
|---|---|---|---|---|
| `GROQ_API_KEY` | string | empty | Conditional | Groq LLM access |
| `GOOGLE_API_KEY` | string | empty | No | Gemini fallback |
| `ANTHROPIC_API_KEY` | string | empty | No | Claude paid fallback |
| `VOYAGE_API_KEY` | string | empty | Conditional | Primary embedding provider |
| `OPENAI_API_KEY` | string | empty | No | Fallback embedding provider |
| `NVD_API_KEY` | string | empty | No | NVD CVE enrichment |
| `SUPABASE_URL` | string | empty | No | Supabase project URL; app can use its fallback when Supabase is not configured |
| `SUPABASE_SERVICE_KEY` | string | empty | No | Backend Supabase service key |
| `SMTP_USER` | string | empty | No | Gmail address used for report email functionality |
| `SMTP_PASS` | string | empty | No | Gmail App Password for report email functionality |
| `REPORT_EMAIL` | string | `printezz01@gmail.com` | No | Default report recipient configured by the current backend |
| `GROQ_MODEL` | string | `openai/gpt-oss-120b` | No | Groq model override |
| `CORS_ORIGINS` | string | empty | No | Comma-separated additional frontend origins |

`Conditional` means the variable is required only when that provider or feature is being used.

Never commit real API keys, service keys, SMTP passwords, or other secrets to GitHub.

---

## API and Documentation

When the backend is running locally:

- **Swagger UI:** `http://localhost:8000/docs`
- **OpenAPI schema:** `http://localhost:8000/openapi.json`
- **Health check:** `GET /health`

### Basic usage

Start a scan:

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"https://github.com/OWASP/PyGoat","target_type":"github"}'
```

Check scan status:

```bash
curl http://localhost:8000/scan/<scan_id>/status
```

Get dashboard data:

```bash
curl http://localhost:8000/scan/<scan_id>/dashboard
```

Get the attack graph:

```bash
curl http://localhost:8000/scan/<scan_id>/chain
```

Ask the AI assistant:

```bash
curl -X POST http://localhost:8000/scan/<scan_id>/chat \
  -H "Content-Type: application/json" \
  -d '{"question":"Explain the most important attack path and how to break it."}'
```

Download the PDF report:

```bash
curl -o report.pdf http://localhost:8000/scan/<scan_id>/report
```

---

## Testing and Quality Control

GitHub Actions is used for CI. Replace the generic CI badge at the top of this README with the repository's live workflow badge once the final repository URL and workflow filename are fixed.

Backend checks:

```bash
python -m pip check
python -m unittest discover -s tests -v
```

Frontend checks:

```bash
cd frontend
npm ci
npm run build
npm run lint
```

Scanner checks:

```bash
python scripts/check_scanners.py
python scripts/smoke_scanners.py
```

**Test coverage:** Formal percentage coverage is not currently measured, so no coverage percentage is claimed.

---

## Reliability and Current Maturity

**Maturity:** Hackathon MVP / Alpha

SENTINEL is a working demonstration platform, not a production SOC replacement.

No formal production benchmark has been established yet. Scan duration depends on the target, selected scanners, network conditions, and external APIs.

Current backend scanner timeouts include:

- Nmap: **60 seconds**
- Nikto: **90 seconds**

These are execution limits, not performance benchmarks.

---

## Known Limitations

- some scanners must be installed separately on the host machine,
- private GitHub repositories require authenticated GitHub access, which is not part of the current MVP,
- a valid scan may produce findings without producing a supported attack path,
- AI explanation depends on the configured LLM provider, while scanner findings and graph logic remain separate,
- scan time can vary significantly by target and scanner,
- production-scale performance and throughput have not yet been benchmarked.

---

## Troubleshooting

**Scanner unavailable**  
Verify that the required scanner executable is installed and available to the backend.

**GitHub repository cannot be scanned**  
Check that the URL is valid and the repository is public. Private repositories are not currently supported without authentication.

**No attack path appears**  
This does not necessarily mean the scan failed. The discovered findings may simply not form a supported chain.

**AI assistant unavailable**  
Check the configured LLM API keys. Scanner results and graph logic are independent of the AI explanation layer.

**Public IP or public subnet rejected**  
This is an intentional safety restriction.

**Supabase unavailable**  
Check `SUPABASE_URL` and `SUPABASE_SERVICE_KEY`. The current project configuration supports a fallback path when Supabase is not configured.

---

## Security Reporting

If you discover a security issue in SENTINEL itself, **do not publish exploit details in a public issue**. Report the issue privately to the repository maintainers using the private contact method associated with the final repository.

`<security-contact-or-private-reporting-link>`

---

## Team Triumph

### Prince Singh — Team Lead / Backend, Architecture & Demo Presentation

- overall system architecture
- FastAPI/backend development
- LangChain/LangGraph orchestration
- attack-path and correlation logic
- Supabase integration and deployment
- final demo flow and presentation

### Shreya Verma — Frontend & UI/UX

- React/Tailwind frontend development
- dashboard and scan-result interfaces
- attack-path visualization UI
- scan-history interface
- overall UI/UX design

### Sidhartha Kashyap — Cybersecurity, AI & Systems Integration

- Nmap / Nikto / Semgrep / Bandit / TruffleHog integration
- attack-path and correlation logic
- AI assistant and LLM workflows
- backend–frontend integration
- system architecture and technical integration

### Vishal Raj — Database, DevOps & Deployment

- Supabase/PostgreSQL database handling
- scan/session persistence
- Render/Vercel deployment support
- GitHub Actions / CI support
- deployment coordination

---

## Contributions and Code Quality

External contributions are **not being accepted during the hackathon review period**.

For team development:

- keep backend changes consistent with the existing Python/FastAPI structure,
- keep frontend changes consistent with the existing React/Tailwind structure,
- do not commit API keys or secrets,
- run backend tests and frontend build/lint checks before merging changes,
- keep security-scanner and attack-path changes traceable to real scanner evidence.

---

## License

No open-source license is currently granted for this repository. A `LICENSE` file should be added before distributing the project as open-source software.
