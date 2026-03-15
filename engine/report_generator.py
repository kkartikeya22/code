import re
import json
import os
from datetime import datetime


def clean_terminal_output(text):
    """
    Removes ANSI color codes, ASCII banners, and UI artifacts
    from CLI security tool outputs before storing in logs.
    """

    if not text:
        return ""

    # Remove ANSI color escape sequences
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    text = ansi_escape.sub('', text)

    # Remove ASCII art lines
    cleaned_lines = []
    for line in text.splitlines():

        stripped = line.strip()

        if stripped == "":
            continue

        # Skip banner style lines
        if any(sym in stripped for sym in ["═══","██","╔","╗","╚","╝","┌","└","│","─","║","═"]):
            continue

        cleaned_lines.append(stripped)

    return "\n".join(cleaned_lines).strip()


def quantum_label(tls_info):
    """
    Determines quantum safety label based on TLS/key info.
    Accepts a dict with keys: 'key_exchange', 'signature'
    """

    key_exchange = tls_info.get("key_exchange", "")
    signature = tls_info.get("signature", "")

    # Quantum-safe indicators
    if "ML-KEM" in key_exchange or "PQC" in key_exchange:
        return "FULLY QUANTUM SAFE"

    # Classical crypto indicators
    if "X25519" in key_exchange or "ECDSA" in signature:
        return "NOT QUANTUM SAFE"

    return "UNKNOWN"


def generate_report(domain, repo_path, risk_score,
                    tls_output, dep_output,
                    crypto_output, pqc_output,
                    api_info=None):
    """
    Generates a full quantum security report.
    Accepts structured TLS info (dict) and optional API info.
    """

    # Clean outputs before displaying
    dep_output = clean_terminal_output(dep_output)
    crypto_output = clean_terminal_output(crypto_output)

    print("\n================================")
    print("   QUANTUM SECURITY REPORT")
    print("================================\n")

    print("Target Domain:", domain)
    print("Repository:", repo_path)
    print("Quantum Risk Score:", str(risk_score) + "/100")

    if risk_score >= 80:
        print("Risk Level: HIGH")
    elif risk_score >= 40:
        print("Risk Level: MEDIUM")
    else:
        print("Risk Level: LOW")

    # --- TLS Analysis ---
    print("\n-------------------------------")
    print("TLS ANALYSIS")
    print("-------------------------------\n")

    for key in ["tls_version", "cipher", "key_exchange", "signature", "quantum_safe"]:
        print(f"{key}: {tls_output.get(key, 'Unknown')}")

    # --- API TLS Analysis ---
    if api_info:
        print("\n-------------------------------")
        print("API TLS ANALYSIS")
        print("-------------------------------\n")

        for key in ["domain", "tls_version", "cipher", "key_exchange",
                    "signature", "quantum_safe", "status_code"]:
            print(f"{key}: {api_info.get(key, 'Unknown')}")

    # --- Dependency Scan ---
    print("\n-------------------------------")
    print("CRYPTO DEPENDENCY ANALYSIS")
    print("-------------------------------\n")

    print(dep_output)

    # --- Crypto Code Scan ---
    print("\n-------------------------------")
    print("CRYPTO CODE ANALYSIS")
    print("-------------------------------\n")

    print(crypto_output)

    # --- PQC Recommendations ---
    print("\n-------------------------------")
    print("PQC RECOMMENDATIONS")
    print("-------------------------------\n")

    print(pqc_output)

    # --- Quantum Safety Label ---
    print("\n-------------------------------")
    print("QUANTUM SAFETY STATUS")
    print("-------------------------------")

    label = quantum_label(tls_output)
    print("Domain Label:", label)

    if api_info:
        api_label = quantum_label(api_info)
        print("API Label:", api_label)

    print("\n================================")
    print(" End of Report")
    print("================================")


def log_full_audit(domain, repo_path, risk_score,
                   tls_output, dep_output,
                   crypto_output, pqc_output,
                   api_info=None):
    """
    Logs full CBOM-style audit results in JSON format.
    """

    os.makedirs("logs", exist_ok=True)

    logfile = "logs/audit_log.json"

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Clean scan outputs
    dep_output_clean = clean_terminal_output(dep_output)
    crypto_output_clean = clean_terminal_output(crypto_output)

    audit_data = {
        "scan_time": timestamp,

        "target": {
            "domain": domain,
            "repository": repo_path
        },

        "risk_score": risk_score,

        "tls_analysis": tls_output,

        "api_analysis": api_info,

        "dependency_scan": dep_output_clean,

        "crypto_scan": crypto_output_clean,

        "pqc_recommendation": pqc_output,

        "quantum_label": quantum_label(tls_output)
    }

    with open(logfile, "a") as f:
        json.dump(audit_data, f, indent=4)
        f.write("\n\n")

    print(f"Full audit logged → {logfile}")