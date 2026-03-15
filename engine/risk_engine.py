def calculate_risk(tls_info, crypto_output, dep_output):

    score = 0

    # Convert outputs to lowercase safely
    crypto_output = crypto_output.lower()
    dep_output = dep_output.lower()

    tls_version = str(tls_info.get("tls_version", "")).lower()
    cipher = str(tls_info.get("cipher", "")).lower()
    key_exchange = str(tls_info.get("key_exchange", "")).lower()
    signature = str(tls_info.get("signature", "")).lower()

    # -----------------------------
    # TLS VERSION RISKS
    # -----------------------------
    if "1.0" in tls_version:
        score += 40

    elif "1.1" in tls_version:
        score += 30

    elif "1.2" in tls_version:
        score += 10

    # -----------------------------
    # KEY EXCHANGE RISKS
    # -----------------------------
    if "x25519" in key_exchange:
        score += 30

    if "rsa" in key_exchange:
        score += 25

    if "ecdhe" in key_exchange:
        score += 25

    # -----------------------------
    # SIGNATURE RISKS
    # -----------------------------
    if "ecdsa" in signature:
        score += 25

    if "rsa" in signature:
        score += 25

    # -----------------------------
    # HASH RISKS
    # -----------------------------
    if "sha1" in crypto_output:
        score += 30

    if "md5" in crypto_output:
        score += 40

    # -----------------------------
    # DEPENDENCY RISKS
    # -----------------------------
    if "openssl" in dep_output:
        score += 10

    if "libssl" in dep_output:
        score += 10

    # -----------------------------
    # Normalize score
    # -----------------------------
    if score > 100:
        score = 100

    return score