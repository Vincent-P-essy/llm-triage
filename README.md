# llm-triage

![Python](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/domain-cybersecurity-red)

**LLM-assisted security incident triage for financial institutions.**

`llm-triage` ingests open security incidents from an incident-tracker API, uses a large language model (Anthropic Claude or OpenAI GPT-4o-mini) to classify their severity and generate concrete investigation steps, then writes the enriched results back to the tracker — all in a single automated pipeline.

---

## Why this project?

Security Operations Centres (SOCs) at banks and financial institutions face a high volume of daily alerts.  Triaging each alert manually is slow, error-prone, and burns analyst capacity.  `llm-triage` acts as a first-responder layer:

- **Consistent severity scoring** calibrated to banking risks (PCI-DSS, DORA, credential theft, data exfiltration).
- **Actionable investigation steps** generated in seconds rather than minutes.
- **Auto-escalation hints** (SOC L1 → SOC L2 → CISO) to route incidents to the right team immediately.
- **Dry-run mode** so you can test prompts safely before touching production data.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                         main.py                              │
│  (argparse, .env loading, pipeline orchestration, logging)   │
└────────┬─────────────────────────┬────────────────────┬──────┘
         │                         │                    │
         ▼                         ▼                    ▼
┌────────────────┐    ┌──────────────────────┐  ┌─────────────────┐
│  app/ingest.py │    │   app/analyzer.py    │  │ app/reporter.py │
│                │    │                      │  │                 │
│ IncidentClient │    │  LLMAnalyzer         │  │IncidentReporter │
│  GET /incidents│    │  ├─ _AnthropicBackend│  │  enrich_and_    │
│  GET /incidents│    │  └─ _OpenAIBackend   │  │  update()       │
│     /{id}      │    │                      │  │  PATCH /api/    │
└────────────────┘    │  Uses:               │  │  incidents/{id} │
         │            │  app/prompt.py       │  └─────────────────┘
         │            │  PromptBuilder       │
         │            │  ├─ classify.txt     │
         │            │  └─ suggest.txt      │
         │            └──────────────────────┘
         │
         ▼
┌──────────────────────────────┐
│   incident-tracker-api       │
│   (external service)         │
│   http://localhost:5000      │
└──────────────────────────────┘
```

### Data flow

```
incident-tracker-api
       │
       │  GET /api/incidents?status=open
       ▼
  IncidentClient.get_open_incidents()
       │
       │  [{id, title, description, source_ip, severity, status, created_at}, ...]
       ▼
  LLMAnalyzer.analyze(incident)          ← classify.txt template
       │  → {severity, confidence, reasoning, tags}
       ▼
  LLMAnalyzer.suggest(incident, cls)     ← suggest.txt template
       │  → {priority_score, immediate_actions, investigation_steps,
       │     escalate_to, estimated_resolution_hours}
       ▼
  IncidentReporter.enrich_and_update()
       │
       │  PATCH /api/incidents/{id}
       ▼
  incident-tracker-api  ✔
```

---

## Installation

### Prerequisites

- Python 3.11+
- An incident-tracker-api reachable at `http://localhost:5000` (or configured via `INCIDENT_TRACKER_URL`)
- An Anthropic API key **or** an OpenAI API key

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/vplessy/llm-triage.git
cd llm-triage

# 2. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate      # macOS / Linux
# .\.venv\Scripts\activate     # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy and edit the environment file
cp .env.example .env
$EDITOR .env
```

---

## Configuration

Edit `.env` (never commit this file):

```dotenv
# LLM provider: "anthropic" or "openai"
LLM_PROVIDER=anthropic

# Anthropic credentials (required when LLM_PROVIDER=anthropic)
ANTHROPIC_API_KEY=sk-ant-...

# OpenAI credentials (required when LLM_PROVIDER=openai)
OPENAI_API_KEY=sk-...

# Incident tracker base URL
INCIDENT_TRACKER_URL=http://localhost:5000

# Logging verbosity: DEBUG, INFO, WARNING, ERROR
LOG_LEVEL=INFO
```

| Variable | Default | Description |
|---|---|---|
| `LLM_PROVIDER` | `anthropic` | Which LLM backend to use |
| `ANTHROPIC_API_KEY` | — | Your Anthropic API key |
| `OPENAI_API_KEY` | — | Your OpenAI API key |
| `INCIDENT_TRACKER_URL` | `http://localhost:5000` | Incident tracker base URL |
| `LOG_LEVEL` | `INFO` | Python logging level |

---

## Usage

### Process all open incidents

```bash
python main.py
```

### Dry-run (no API writes)

```bash
python main.py --dry-run
```

### Process a single incident by ID

```bash
python main.py --incident-id INC-001
```

### Combine flags

```bash
python main.py --dry-run --incident-id INC-042
```

### Example output

```
2024-06-01T08:30:00  INFO      __main__  Found 3 incident(s) to process.
2024-06-01T08:30:00  INFO      __main__  ── Processing incident INC-001: Suspicious login from unusual location
2024-06-01T08:30:00  INFO      __main__    [1/3] Classifying severity …
2024-06-01T08:30:02  INFO      app.analyzer  Incident INC-001 classified as HIGH (confidence=0.92)
2024-06-01T08:30:02  INFO      __main__    → severity=HIGH  confidence=0.92  tags=['credential-theft', 'tor']
2024-06-01T08:30:02  INFO      __main__    [2/3] Generating investigation steps …
2024-06-01T08:30:04  INFO      app.analyzer  Suggestion for incident INC-001: priority=8, escalate_to=SOC L2
2024-06-01T08:30:04  INFO      __main__    [3/3] Enriching and updating incident …
2024-06-01T08:30:04  INFO      app.reporter  Patched incident INC-001 — HTTP 200
2024-06-01T08:30:04  INFO      __main__    ✔ Incident INC-001 processed.
```

---

## Integration with incident-tracker-api

`llm-triage` expects the following API contract:

### `GET /api/incidents?status=open`

Returns a JSON array of incident objects:

```json
[
  {
    "id": "INC-001",
    "title": "Suspicious login from unusual location",
    "description": "Multiple failed logins then success from TOR exit node 198.51.100.42",
    "source_ip": "198.51.100.42",
    "severity": "MEDIUM",
    "status": "open",
    "created_at": "2024-06-01T08:23:45Z"
  }
]
```

### `GET /api/incidents/{id}`

Returns a single incident object (same shape).

### `PATCH /api/incidents/{id}`

Accepts a JSON body with enrichment fields:

```json
{
  "llm_severity": "HIGH",
  "llm_priority_score": 8,
  "llm_escalate_to": "SOC L2",
  "llm_classification": { "severity": "HIGH", "confidence": 0.92, ... },
  "llm_suggestion": { "priority_score": 8, "immediate_actions": [...], ... },
  "llm_processed_at": "2024-06-01T08:30:04Z"
}
```

---

## How LLM prompts are structured

Prompts live in `prompts/` as Jinja2 templates and are loaded at runtime by `PromptBuilder`.

### `prompts/classify.txt` — Severity classification

The template instructs the model to output structured JSON with:

- `severity` — `CRITICAL | HIGH | MEDIUM | LOW`
- `confidence` — float 0–1
- `reasoning` — brief human-readable explanation
- `tags` — list of relevant security tags

The system prompt anchors the model as a **financial institution cybersecurity analyst** and explicitly asks it to weight banking-specific risks (PCI-DSS compliance, DORA regulation, credential theft, data exfiltration, lateral movement).

### `prompts/suggest.txt` — Investigation steps

Uses the incident details **and** the severity from the classification call.  Output JSON includes:

- `priority_score` — 1–10
- `immediate_actions` — first-response actions (isolate host, reset credentials, etc.)
- `investigation_steps` — deeper forensic steps
- `escalate_to` — routing hint
- `estimated_resolution_hours` — effort estimate

---

## Testing

```bash
# Install dev dependencies (included in requirements.txt)
pip install -r requirements.txt

# Run all tests
pytest -v

# Run a specific test file
pytest tests/test_prompt.py -v

# Run with coverage
pip install pytest-cov
pytest --cov=app --cov-report=term-missing
```

### Test strategy

| Test file | What is tested | Mocking strategy |
|---|---|---|
| `test_prompt.py` | `PromptBuilder` — template rendering, error cases | Temp directories with minimal templates |
| `test_analyzer.py` | `LLMAnalyzer` — JSON parsing, retries, fallback | `unittest.mock.MagicMock` on the backend `.complete()` method |
| `test_reporter.py` | `IncidentReporter` — HTTP PATCH, enrichment, reporting | `responses` library intercepts HTTP calls |

---

## Project structure

```
llm-triage/
├── app/
│   ├── __init__.py        Package metadata
│   ├── ingest.py          IncidentClient — reads incidents from tracker API
│   ├── prompt.py          PromptBuilder — Jinja2 template rendering
│   ├── analyzer.py        LLMAnalyzer — Anthropic / OpenAI integration
│   └── reporter.py        IncidentReporter — enrichment + PATCH API
├── prompts/
│   ├── classify.txt       Severity classification prompt template
│   └── suggest.txt        Investigation steps prompt template
├── tests/
│   ├── __init__.py
│   ├── test_prompt.py
│   ├── test_analyzer.py
│   └── test_reporter.py
├── .env.example           Environment variable template
├── .gitignore
├── requirements.txt
├── setup.py
├── README.md
└── main.py                CLI entry point
```

---

## Future roadmap

- [ ] **Slack / Teams notifications** — post enriched incidents to a SOC channel automatically.
- [ ] **Prometheus metrics** — expose `incidents_processed_total`, `severity_counts`, `avg_priority_score`.
- [ ] **Streaming LLM responses** — reduce time-to-first-token for large incident descriptions.
- [ ] **Multi-incident batching** — send multiple incidents in one API call using Claude's context window.
- [ ] **Confidence thresholds** — only auto-update the tracker when confidence ≥ configurable threshold.
- [ ] **Feedback loop** — allow analysts to rate LLM suggestions, feed corrections back as few-shot examples.
- [ ] **Docker image** — containerised deployment with a health endpoint.
- [ ] **GitHub Actions workflow** — scheduled triage run every 15 minutes.

---

## Contributing

Contributions are welcome.  Please:

1. Fork the repository and create a feature branch (`git checkout -b feat/my-feature`).
2. Write tests for new functionality.
3. Ensure all tests pass (`pytest -v`).
4. Open a pull request describing what you changed and why.

---

## License

MIT © 2024 Vincent Plessy — [vincent.plessy12@gmail.com](mailto:vincent.plessy12@gmail.com)
