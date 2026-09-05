# IAM Remediation Assistant

> **Capstone Project** — AI-powered AWS IAM vulnerability detection, remediation, and visualization tool. Built on top of Bishop Fox's `iam-vulnerable` for realistic privilege escalation scenarios.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Anthropic](https://img.shields.io/badge/Claude-Haiku-CC785C?logo=anthropic&logoColor=white)](https://anthropic.com)
[![D3.js](https://img.shields.io/badge/D3.js-7.0-F9A03C?logo=d3.js&logoColor=white)](https://d3js.org)

---

## 🎯 Overview

The **IAM Remediation Assistant** is a full-stack security tool that:

1. **Analyzes** AWS IAM configurations (Terraform plans, JSON policies, `iam-vulnerable` output)
2. **Detects** 31+ privilege escalation patterns mapped to MITRE ATT&CK techniques
3. **Remediates** using Anthropic Claude AI for specific, actionable fixes with hardened policy examples
4. **Visualizes** attack graphs, escalation chains, MITRE heatmaps, and resource risk maps

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        User Browser                              │
│  HTML + CSS + Vanilla JS + D3.js + Chart.js                     │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTPS
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AWS EC2 (Flask + Gunicorn)                   │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│  │ iam_analyzer │ │  remediator  │ │  visualizer  │            │
│  │  (parser)    │ │  (Claude AI) │ │  (D3 data)   │            │
│  └──────────────┘ └──────────────┘ └──────────────┘            │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Anthropic Claude API                          │
│              (claude-3-haiku-20240307)                          │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- (Optional) Anthropic API key ([get one here](https://console.anthropic.com/)) for AI-assisted detection and remediation
- (Optional) AWS account for `iam-vulnerable` integration

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/iam-remediation-assistant.git
cd iam-remediation-assistant

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r backend/requirements.txt

# Configure environment (optional - the app runs without an API key)
cp backend/.env.example backend/.env
# Edit backend/.env and add your ANTHROPIC_API_KEY to enable the AI pass

# Run the application
cd backend
python app.py
```

Open http://localhost:5000 in your browser.

### Using Demo Data

Click **"Load Demo Data"** in the UI to instantly see the tool in action with realistic vulnerable IAM configurations.

---

## 📁 Project Structure

```
iam-remediation-assistant/
├── backend/
│   ├── app.py              # Flask app: routing, security headers, orchestration
│   ├── iam_analyzer.py     # Parse IAM configs, detect escalation patterns
│   ├── ai_detector.py      # Optional AI second pass for missed findings
│   ├── remediator.py       # Remediation engine (rule-based + optional Claude)
│   ├── visualizer.py       # Generate D3.js / Chart.js visualization data
│   ├── tests/              # Unit + integration tests
│   ├── requirements.txt    # Python dependencies
│   └── .env.example        # Environment template
├── frontend/
│   ├── index.html          # Single-page dashboard
│   ├── style.css           # Dark/light theme, responsive design
│   └── script.js           # API calls, D3 force graph, Chart.js
├── assets/                 # Screenshots, diagrams
├── README.md
└── .gitignore
```

---

## 🏛️ Design Notes

**Analyzer ↔ remediator contract.** Every finding carries a stable
`pattern_id` (e.g. `iam:PassRole`, `full_admin`, `service_wildcard`).
The remediator maps those IDs to strategies, so display titles can be
reworded without breaking remediation. A test enforces that every analyzer
pattern has a corresponding strategy.

**Stateless analysis.** Finding IDs are assigned per request, so the same
input always produces the same IDs across processes and Gunicorn workers.

**Bounded AI usage.** The AI remediation pass is capped
(`MAX_AI_REMEDIATIONS`, default 5 uncached calls per analysis) and cached by
finding content, so a 200-finding config cannot trigger 200 API calls. Any
API failure or unparseable response degrades cleanly to the rule engine.

**Untrusted input.** IAM configs, and any text the model returns, are treated
as untrusted: all values are HTML-escaped for text *and* attribute contexts,
class names are allowlisted, and a Content-Security-Policy is sent with every
response.

---

## 🔍 Supported Vulnerability Patterns

| Pattern | Severity | MITRE | Description |
|---------|----------|-------|-------------|
| `iam:AttachUserPolicy` | CRITICAL | T1098.001 | Attach any managed policy (including AdministratorAccess) |
| `iam:PutUserPolicy` | CRITICAL | T1098.001 | Create inline policies with arbitrary permissions |
| `iam:CreateAccessKey` | HIGH | T1098.004 | Create access keys for other users |
| `iam:UpdateLoginProfile` | HIGH | T1098.005 | Change passwords for any user |
| `sts:AssumeRole` | HIGH | T1550.001 | Assume roles with elevated permissions |
| `iam:PassRole` | HIGH | T1098.003 | Pass privileged roles to EC2, Lambda, Glue |
| `iam:CreateRole` | MEDIUM | T1098.003 | Create roles with arbitrary trust policies |
| `iam:PutRolePolicy` | HIGH | T1098.003 | Attach inline policies to any role |
| `iam:AttachRolePolicy` | HIGH | T1098.003 | Attach managed policies to any role |
| `iam:UpdateAssumeRolePolicy` | HIGH | T1550.001 | Modify trust policy for self-assumption |
| `organizations:AttachPolicy` | CRITICAL | T1484.002 | Attach Service Control Policies |
| `organizations:MoveAccount` | HIGH | T1484.002 | Move accounts between OUs to bypass SCPs |
| `ec2:RunInstances` | MEDIUM | T1611 | Launch EC2 with instance profile |
| `lambda:CreateFunction` | MEDIUM | T1611 | Create Lambda with privileged role |
| `lambda:UpdateFunctionCode` | MEDIUM | T1611 | Modify Lambda code for code execution |
| `<service>:*` | HIGH/CRITICAL | varies | Service-wide wildcard, reported once with covered escalation actions |
| `*` (all actions) | CRITICAL | T1098.001 | Full administrative access |
| ...and 15+ more | | | |

---

## 🎨 Visualizations

| Tab | Description |
|-----|-------------|
| **Attack Graph** | Force-directed D3 graph showing identities → vulnerabilities → MITRE techniques |
| **Vulnerabilities** | Sortable, filterable table with all detected issues |
| **Remediation** | AI-generated fixes with before/after policy JSON, priority, compliance notes |
| **Visualizer** | Escalation chains, MITRE heatmap, resource risk bars, remediation timeline |
| **Charts** | Severity doughnut, resource risk radar, remediation progress |

---

## 🔧 Configuration

### Environment Variables

```bash
# Required for AI features (optional - the tool works fully without it,
# falling back to the deterministic rule engine)
ANTHROPIC_API_KEY=sk-ant-...

# Server
PORT=5000
HOST=127.0.0.1          # use 0.0.0.0 only in containers
FLASK_DEBUG=0           # never set to 1 on a public host (RCE via debugger)

# AI cost/latency controls
MAX_AI_REMEDIATIONS=5           # max uncached Claude calls per analysis
ANTHROPIC_TIMEOUT_SECONDS=30
REMEDIATOR_MODEL=claude-3-haiku-20240307

# Limits
MAX_CONFIG_BYTES=1048576        # max request body (1 MB)

# Only if the frontend is served from a different origin
# CORS_ORIGINS=https://dashboard.example.com

# AWS Configuration (optional - for iam-vulnerable integration)
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1
IAM_VULNERABLE_ACCOUNT_ID=123456789012
```

> **Note:** Without `ANTHROPIC_API_KEY` the app runs entirely on the built-in
> rule engine. Findings and remediations are still produced; only the
> "AI Suggested" second-pass detection is skipped.

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/analyze` | Analyze an IAM config; returns findings, remediations, visualization data |
| `POST` | `/api/generate-dummy` | Return a realistic vulnerable demo config |
| `GET`  | `/health` | Liveness probe |

### Running Tests

```bash
cd backend
python -m unittest discover -s tests -t .
```

### Input Formats

The analyzer accepts:

1. **Terraform Plan JSON** — Output from `terraform show -json`
2. **IAM Policy JSON** — Raw policy documents with `Policy` key
3. **iam-vulnerable Output** — Resources from Bishop Fox tool
4. **Generic JSON** — Any structure with policy statements

---

## 🌐 Deployment

### AWS

The frontend calls the API at a same-origin `/api` path, so Flask serves both
the UI and the API from one origin. (Splitting the frontend onto S3 would
require setting `CORS_ORIGINS` and making the API base URL configurable.)

```bash
# Backend on EC2
ssh ec2-user@<ec2-ip>
git clone ...
cd iam-remediation-assistant/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # Add API key if you want the AI pass
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

Never run with `FLASK_DEBUG=1` on a reachable host: the Werkzeug debugger
allows remote code execution.

### Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY backend/requirements.txt .
RUN pip install -r requirements.txt
COPY backend/ .
EXPOSE 5000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

---

## 📚 Related Work

- **iam-policy-explainer** — This project's predecessor: web tool that explains and hardens single IAM policies
- **iam-vulnerable** (Bishop Fox) — Terraform module deploying 250+ vulnerable IAM resources for testing
- **CloudFox** — AWS enumeration tool
- **PMapper** — Principal mapping for IAM privilege escalation

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

## 👨‍💻 Author

**Adnan Nazir Ahmed** — Cloud Engineer & Security Researcher

- GitHub: [@adnannazirahmed](https://github.com/adnannazirahmed)
- Built as capstone project for MSIT program

---

## 🙏 Acknowledgments

- **Bishop Fox** — For `iam-vulnerable` and privilege escalation research
- **Seth Art** — Lead researcher on IAM Vulnerable
- **Anthropic** — For Claude API powering the remediation engine
- **AWS** — For IAM service (and its complexities 😅)