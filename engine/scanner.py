import subprocess
import re
import ssl
import socket
from urllib.parse import urlparse
import os


def extract_domain(domain_input):
    """Extract domain from URL or return as-is"""
    if domain_input.startswith(("http://", "https://")):
        return urlparse(domain_input).netloc
    return domain_input


def run_tls_scan(domain):
    """
    Runs TLS analyzer and extracts TLS cryptographic properties using Python's SSL module.
    """
    try:
        domain = extract_domain(domain)
        context = ssl.create_default_context()
        
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get certificate info
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                # Parse cipher information
                cipher_name = cipher[0] if cipher else "NOT DETECTED"
                
                # Determine TLS version
                tls_version = version if version else "UNKNOWN"
                
                # Determine key exchange and signature
                key_exchange = "ECDHE" if "ECDHE" in cipher_name else "RSA" if "RSA" in cipher_name else "X25519" if "X25519" in cipher_name else "NOT DETECTED"
                signature = "ECDSA" if "ECDSA" in cipher_name else "RSA" if "RSA" in cipher_name else "NOT DETECTED"
                
                # Check quantum safety (ML-KEM, PQC algorithms)
                quantum_safe = "ML-KEM" in cipher_name or "PQC" in cipher_name or "KYBER" in cipher_name
                
                return {
                    "tls_version": tls_version,
                    "cipher": cipher_name,
                    "key_exchange": key_exchange,
                    "signature": signature,
                    "quantum_safe": quantum_safe
                }
    
    except Exception as e:
        print(f"TLS scan error: {e}")
        return {
            "tls_version": "SCAN FAILED",
            "cipher": "SCAN FAILED",
            "key_exchange": "SCAN FAILED",
            "signature": "SCAN FAILED",
            "quantum_safe": False
        }


def run_dependency_scan(repo_path):
    """
    Scans repository for cryptographic dependencies without external tools.
    """
    crypto_libs = {
        "openssl": "OpenSSL",
        "libssl": "LibSSL",
        "cryptography": "Cryptography (Python)",
        "pycryptodome": "PyCryptodome",
        "pycrypto": "PyCrypto",
        "M2Crypto": "M2Crypto",
        "keyczar": "Keyczar",
        "tls": "TLS",
        "ssl": "SSL",
        "boringssl": "BoringSSL",
        "mbedtls": "MbedTLS",
        "wolfssl": "WolfSSL",
        "libgcrypt": "LibGcrypt",
        "nettle": "Nettle",
    }
    
    try:
        found_deps = []
        
        # Scan for files that might contain crypto dependencies
        if os.path.isdir(repo_path):
            for root, dirs, files in os.walk(repo_path):
                # Skip large directories
                if '.git' in dirs:
                    dirs.remove('.git')
                if '__pycache__' in dirs:
                    dirs.remove('__pycache__')
                if 'node_modules' in dirs:
                    dirs.remove('node_modules')
                    
                # Check requirement files
                for file in files:
                    if file in ['requirements.txt', 'setup.py', 'pyproject.toml', 'package.json', 'go.mod', 'Gemfile']:
                        filepath = os.path.join(root, file)
                        try:
                            with open(filepath, 'r', errors='ignore') as f:
                                content = f.read().lower()
                                for lib in crypto_libs:
                                    if lib in content:
                                        found_deps.append(f"{crypto_libs[lib]} (found in {file})")
                        except:
                            pass
        
        if found_deps:
            return "\n".join(found_deps)
        else:
            return "No cryptographic dependencies detected in requirement files."
    
    except Exception as e:
        print(f"Dependency scan error: {e}")
        return "DEPENDENCY SCAN FAILED"


def run_crypto_scan(repo_path):
    """
    Scans repository for cryptographic code patterns.
    """
    crypto_patterns = {
        r"RSA": "RSA encryption detected",
        r"AES": "AES encryption detected",
        r"SHA[0-9]": "SHA hash function detected",
        r"MD5": "MD5 hash (weak!) detected",
        r"DES|3DES": "DES/3DES encryption detected",
        r"ECDSA": "ECDSA signature detected",
        r"X25519": "X25519 key exchange detected",
        r"ChaCha20": "ChaCha20 encryption detected",
        r"Curve25519": "Curve25519 detected",
        r"ssl\.|tls\.|crypto\.|hmac\.": "Crypto library usage detected",
    }
    
    try:
        findings = []
        file_count = 0
        
        if os.path.isdir(repo_path):
            for root, dirs, files in os.walk(repo_path):
                # Skip large/unimportant directories
                skip_dirs = {'.git', '__pycache__', '.venv', 'node_modules', '.idea', 'dist', 'build'}
                dirs[:] = [d for d in dirs if d not in skip_dirs]
                
                for file in files:
                    # Check only code files
                    if file.endswith(('.py', '.js', '.ts', '.go', '.java', '.rs', '.c', '.cpp', '.h')):
                        file_count += 1
                        filepath = os.path.join(root, file)
                        try:
                            with open(filepath, 'r', errors='ignore') as f:
                                content = f.read()
                                for pattern, description in crypto_patterns.items():
                                    if re.search(pattern, content, re.IGNORECASE):
                                        if description not in findings:
                                            findings.append(description)
                        except:
                            pass
        
        if findings:
            result = f"Scanned {file_count} code files. Findings:\n"
            result += "\n".join(f"• {f}" for f in findings)
            return result
        else:
            return f"Scanned {file_count} code files. No cryptographic patterns detected."
    
    except Exception as e:
        print(f"Crypto scan error: {e}")
        return "CRYPTO SCAN FAILED"