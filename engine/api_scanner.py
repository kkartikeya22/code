import requests
import ssl
import socket
from urllib.parse import urlparse


def scan_api(api_url):
    """
    Scan the API endpoint for TLS information.

    Returns:
    {
        "domain": "api.example.com",
        "tls_version": "TLS 1.3",
        "cipher": "TLS_AES_128_GCM_SHA256",
        "key_exchange": "Unknown",
        "signature": "Unknown",
        "quantum_safe": False,
        "status_code": 200,
        "error": None
    }
    """

    result = {
        "domain": api_url,
        "tls_version": None,
        "cipher": None,
        "key_exchange": "Unknown",
        "signature": "Unknown",
        "quantum_safe": False,
        "status_code": None,
        "error": None
    }

    try:
        # -----------------------------
        # Parse hostname safely
        # -----------------------------
        parsed = urlparse(api_url)
        hostname = parsed.hostname
        port = parsed.port if parsed.port else 443

        # -----------------------------
        # TLS handshake
        # -----------------------------
        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:

                tls_version = ssock.version()
                cipher_info = ssock.cipher()  # (cipher_name, protocol, bits)

                result["tls_version"] = tls_version
                result["cipher"] = cipher_info[0]

                # Python doesn't expose key exchange
                result["key_exchange"] = "Unknown"

                # -----------------------------
                # Basic quantum safety detection
                # -----------------------------
                cipher = cipher_info[0].lower()

                if "rsa" in cipher or "ecdsa" in cipher:
                    result["quantum_safe"] = False
                else:
                    result["quantum_safe"] = False  # TLS today is not PQ-safe

        # -----------------------------
        # Check API availability
        # -----------------------------
        try:
            r = requests.get(api_url, timeout=5)
            result["status_code"] = r.status_code
        except Exception:
            result["status_code"] = "Request failed"

    except Exception as e:
        result["error"] = str(e)

    return result