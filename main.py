import subprocess
import os
import shutil
import stat

from engine.scanner import run_tls_scan, run_dependency_scan, run_crypto_scan
from engine.risk_engine import calculate_risk
from engine.report_generator import generate_report, log_full_audit   # <-- NEW IMPORT
from engine.cbom_generator import generate_cbom
from engine.api_scanner import scan_api


def run_pqc_recommendation():
    """
    Runs the PQC recommendation engine via subprocess.
    """
    print("\nRunning PQC Recommendation Engine...\n")
    try:
        result = subprocess.run(
            ["python", "-m", "pqc_engine.pqc_bench.cli", "recommend", "rsa tls jwt"],
            capture_output=True,
            text=True
        )
        return result.stdout
    except Exception as e:
        print("Error running PQC recommendation:", e)
        return ""


def prepare_repo(repo_input):
    """
    If the user provides a GitHub URL, clone it locally.
    Otherwise assume it's already a local folder.
    """
    if repo_input.startswith("http"):
        repo_name = repo_input.split("/")[-1]
        print(f"\nCloning repository: {repo_input}\n")
        subprocess.run(["git", "clone", repo_input])
        return repo_name, True
    return repo_input, False


def remove_readonly(func, path, _):
    """
    Clears the readonly bit and retries deletion.
    """
    os.chmod(path, stat.S_IWRITE)
    func(path)


def cleanup_repo(repo_path, cloned):
    """
    Delete repo if it was cloned by this tool.
    Handles Windows permission errors.
    """
    if cloned and os.path.exists(repo_path):
        print("\nCleaning up cloned repository...\n")
        try:
            shutil.rmtree(repo_path, onerror=remove_readonly)
            print("Repository removed successfully.\n")
        except Exception as e:
            print("Cleanup warning:", e)


def main():
    print("\n======================================")
    print("   QUANTUM SECURITY AUDIT PLATFORM")
    print("======================================\n")

    # User inputs
    domain = input("Enter domain to audit (TLS scan): ")
    repo_input = input("Enter repository path or GitHub URL: ")
    api_url = input("Enter API endpoint (optional): ")

    # Scan API if provided
    if api_url:
        print("\n[API] Scanning API endpoint...\n")
        api_output = scan_api(api_url)
    else:
        api_output = None

    # Prepare repo (clone if needed)
    repo_path, cloned = prepare_repo(repo_input)

    # Run TLS scan
    print("\n[1] Running TLS Analyzer...\n")
    tls_output = run_tls_scan(domain)

    # Run dependency scan
    print("\n[2] Running Crypto Dependency Scan...\n")
    dep_output = run_dependency_scan(repo_path)

    # Run crypto code scan
    print("\n[3] Running Crypto Code Scan...\n")
    crypto_output = run_crypto_scan(repo_path)

    # Generate CBOM
    print("\n[4] Generating CBOM Inventory...\n")
    generate_cbom(
        domain=domain,
        tls_info=tls_output,
        repo_path=repo_path,
        api_info=api_output
    )

    # Run PQC Recommendation
    print("\n[5] Running PQC Recommendation Engine...\n")
    pqc_output = run_pqc_recommendation()

    # Calculate risk
    print("\n[6] Calculating Quantum Risk Score...\n")
    risk_score = calculate_risk(tls_output, crypto_output, dep_output)

    # Generate report
    print("\n[7] Generating Final Report...\n")
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

    # NEW: log full audit report
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


if __name__ == "__main__":
    main()