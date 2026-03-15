import json
import os
from datetime import datetime


def generate_cbom(domain, tls_info, repo_path, api_info=None):

    # -----------------------------
    # Create CBOM folder
    # -----------------------------
    cbom_dir = "cbom"
    os.makedirs(cbom_dir, exist_ok=True)

    # -----------------------------
    # Single CBOM log file
    # -----------------------------
    cbom_file = os.path.join(cbom_dir, "cbom_log.json")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cbom_data = {
        "scan_time": timestamp,
        "assets": []
    }

    # -----------------------------
    # Domain TLS entry
    # -----------------------------
    domain_entry = {
        "asset_type": "domain",
        "domain": domain,
        "tls_version": tls_info.get("tls_version", "Unknown"),
        "cipher": tls_info.get("cipher", "Unknown"),
        "key_exchange": tls_info.get("key_exchange", "Unknown"),
        "signature": tls_info.get("signature", "Unknown"),
        "quantum_safe": tls_info.get("quantum_safe", False),
        "repository": repo_path
    }

    cbom_data["assets"].append(domain_entry)

    # -----------------------------
    # API TLS entry
    # -----------------------------
    if api_info:
        api_entry = {
            "asset_type": "api",
            "domain": api_info.get("domain", "Unknown"),
            "tls_version": api_info.get("tls_version", "Unknown"),
            "cipher": api_info.get("cipher", "Unknown"),
            "key_exchange": api_info.get("key_exchange", "Unknown"),
            "signature": api_info.get("signature", "Unknown"),
            "quantum_safe": api_info.get("quantum_safe", False),
            "status_code": api_info.get("status_code", None),
            "repository": repo_path
        }

        cbom_data["assets"].append(api_entry)

    # -----------------------------
    # Append to CBOM log
    # -----------------------------
    with open(cbom_file, "a") as f:
        f.write("\n\n")
        f.write("============================================\n")
        f.write(f"SCAN TIME: {timestamp}\n")
        f.write("============================================\n")
        json.dump(cbom_data, f, indent=4)
        f.write("\n")

    print(f"CBOM entry logged → {cbom_file}")