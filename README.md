# HackerBoyz — Quantum Security Audit Platform

HackerBoyz is a Python-based security auditing tool focused on **quantum-era risk**. It performs multi‑stage scans (TLS analysis, dependency and crypto code scanning), generates a **CBOM**, calculates a **quantum risk score**, and produces audit reports. A FastAPI service exposes scan results and a simple dashboard.

## Features

- **TLS Analyzer** for target domains  
- **Crypto Dependency Scan** for repositories  
- **Crypto Code Scan** to detect cryptographic usage  
- **CBOM (Crypto Bill of Materials)** generation  
- **PQC Recommendation Engine** (post‑quantum crypto guidance)  
- **Quantum Risk Score** calculation  
- **Report generation** + full audit logging  
- **FastAPI dashboard** with endpoints to view scans and trigger new scans  

## Repository Structure

- `main.py` — CLI entrypoint for full audit workflow  
- `dashboard_api.py` — FastAPI service for scan results + dashboard  
- `dashboard.html` — UI for viewing audit results  
- `engine/` — scanning, risk scoring, reporting  
- `pqc_engine/` — PQC recommendation engine  
- `cbom/` — CBOM artifacts  
- `logs/` — audit logs (JSON)  
- `tools/` — helper utilities  

## Requirements

Python 3.9+ recommended.

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run the CLI Audit

```bash
python main.py
```

You will be prompted for:

- Domain to audit (TLS scan)
- Repository path or GitHub URL
- Optional API endpoint to scan

## Run the API + Dashboard

```bash
uvicorn dashboard_api:app --reload
```

Endpoints:

- `GET /scans` — list all scans
- `GET /latest` — latest scan result
- `POST /run-scan` — trigger a scan
- `GET /` — serves dashboard (if local HTML path exists)

> **Note:** `dashboard_api.py` currently points to a local path for `dashboard.html`.  
> You may want to update this to a repo-relative path (e.g. `./dashboard.html`) for portability.

## Logs

Audit results are stored in:

```
logs/audit_log.json
```

Each scan is appended as a JSON object.

## Example Workflow

1. Run a CLI scan for a domain + repo  
2. Review output report and CBOM  
3. Use the dashboard to visualize latest scan  

## License

Add a license if you intend to open-source the project.
