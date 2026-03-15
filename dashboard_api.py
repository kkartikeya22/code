from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import json
import os
import subprocess
from pydantic import BaseModel, Field
from typing import Optional

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

LOG_FILE = "logs/audit_log.json"


def load_logs():
    """Load all scan logs from file."""
    if not os.path.exists(LOG_FILE):
        return []
    
    try:
        with open(LOG_FILE) as f:
            content = f.read().strip()
        
        if not content:
            return []

        # Split JSON objects
        objects = content.split("\n\n")

        data = []
        for obj in objects:
            try:
                data.append(json.loads(obj))
            except json.JSONDecodeError:
                pass

        return data
    except Exception as e:
        print(f"Error loading logs: {e}")
        return []


from pydantic import BaseModel, Field
from typing import Optional


class ScanRequest(BaseModel):
    """Request model for running a scan."""
    domain: str = Field(default="", description="Domain to scan")
    repo_path: str = Field(default="", description="Repository path to scan")
    api_endpoint: Optional[str] = Field(default=None, description="API endpoint to scan")


@app.get("/")
async def root():
    """Serve dashboard HTML."""
    dashboard_path = "/Users/rohit/Downloads/code/dashboard.html"
    if os.path.exists(dashboard_path):
        return FileResponse(dashboard_path, media_type="text/html")
    return HTMLResponse("<h1>Dashboard not found</h1>")


@app.get("/scans")
def get_scans():
    """Get all scan results."""
    return load_logs()


@app.get("/latest")
def latest_scan():
    """Get the latest scan result."""
    logs = load_logs()
    return logs[-1] if logs else {}


@app.post("/run-scan")
async def run_scan(request: ScanRequest):
    """
    Run a new security scan with provided parameters.
    This spawns a subprocess to run the main scanner.
    """
    try:
        # Prepare input for the scanner
        domain = request.domain.strip() if request.domain else ""
        repo_path = request.repo_path.strip() if request.repo_path else ""
        api_endpoint = request.api_endpoint.strip() if request.api_endpoint else ""
        
        # At least one input must be provided
        if not domain and not repo_path and not api_endpoint:
            raise HTTPException(status_code=400, detail="Please provide at least one input: domain, repository path, or API endpoint")
        
        # Use smart defaults for missing values
        if not domain:
            domain = "localhost"
        if not repo_path:
            repo_path = "/Users/rohit/Downloads/code"  # Default to current project
        
        # Create a Python script to run the scan
        
        # Create a Python script to run the scan
        scan_script = f"""
import sys
sys.path.insert(0, '/Users/rohit/Downloads/code')

from engine.scanner import run_tls_scan, run_dependency_scan, run_crypto_scan
from engine.risk_engine import calculate_risk
from engine.report_generator import generate_report, log_full_audit
from engine.cbom_generator import generate_cbom
from engine.api_scanner import scan_api
from main import run_pqc_recommendation, prepare_repo, cleanup_repo

# Parameters
domain = "{domain}"
repo_input = "{repo_path}"
api_url = "{api_endpoint if api_endpoint else ''}"

# Scan API if provided
if api_url:
    print("[API] Scanning API endpoint...")
    api_output = scan_api(api_url)
else:
    api_output = None

# Prepare repo (clone if needed)
repo_path, cloned = prepare_repo(repo_input)

# Run TLS scan
print("[1] Running TLS Analyzer...")
tls_output = run_tls_scan(domain)

# Run dependency scan
print("[2] Running Crypto Dependency Scan...")
dep_output = run_dependency_scan(repo_path)

# Run crypto code scan
print("[3] Running Crypto Code Scan...")
crypto_output = run_crypto_scan(repo_path)

# Generate CBOM
print("[4] Generating CBOM Inventory...")
generate_cbom(
    domain=domain,
    tls_info=tls_output,
    repo_path=repo_path,
    api_info=api_output
)

# Run PQC Recommendation
print("[5] Running PQC Recommendation Engine...")
pqc_output = run_pqc_recommendation()

# Calculate risk
print("[6] Calculating Quantum Risk Score...")
risk_score = calculate_risk(tls_output, crypto_output, dep_output)

# Generate report
print("[7] Generating Final Report...")
generate_report(
    domain,
    repo_path,
    risk_score,
    tls_output,
    dep_output,
    crypto_output,
    pqc_output,
    api_info=api_output
)

# Log full audit report
log_full_audit(
    domain,
    repo_path,
    risk_score,
    tls_output,
    dep_output,
    crypto_output,
    pqc_output,
    api_info=api_output
)

# Cleanup cloned repo
cleanup_repo(repo_path, cloned)

print("Scan completed successfully!")
"""
        
        # Run the scan in a subprocess
        try:
            result = subprocess.run(
                ["python", "-c", scan_script],
                capture_output=True,
                text=True,
                timeout=180  # Increased to 3 minutes
            )
            
            if result.returncode != 0:
                error_msg = result.stderr[:500] if result.stderr else "Unknown error"
                print(f"Scan subprocess error: {result.stderr}")
                return {
                    "status": "error",
                    "message": f"Scan failed: {error_msg}",
                    "detail": "Check the scan parameters and try again"
                }
            
            # Return the latest scan result
            logs = load_logs()
            latest = logs[-1] if logs else {}
            
            return {
                "status": "success",
                "message": "Scan completed successfully",
                "data": latest
            }
            
        except subprocess.TimeoutExpired as e:
            error_detail = "Scan timed out after 3 minutes. Try with a simpler repository or domain."
            print(f"Timeout error: {error_detail}")
            raise HTTPException(status_code=408, detail=error_detail)
        except Exception as e:
            error_detail = f"Scan execution error: {str(e)}"
            print(f"Error running scan: {error_detail}")
            raise HTTPException(status_code=500, detail=error_detail)
    
    except HTTPException:
        raise  # Re-raise HTTP exceptions
    except Exception as e:
        print(f"Unexpected error in run_scan: {e}")
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")