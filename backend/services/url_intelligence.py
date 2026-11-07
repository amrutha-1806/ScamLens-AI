"""
SCAMLENS AI - Static URL Intelligence Engine

SECURITY CONTRACT
-----------------
Every function in this module operates on the URL *string only*.
Nothing here opens, fetches, resolves (DNS), crawls, pings or executes a URL.
Only the Python standard library string/parsing utilities are used.

The findings produced here are rule-based HEURISTIC INDICATORS. They are not
outputs of the Random Forest model and they are not confirmed malicious
verdicts. They are reported separately from the model prediction.
"""

from __future__ import annotations

import ipaddress
import math
import re
import unicodedata
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit

try:
    from src.features.url_features import extract_url_lexical_features, SUSPICIOUS_KEYWORDS
except ImportError:
    try:
        from features.url_features import extract_url_lexical_features, SUSPICIOUS_KEYWORDS
    except ImportError:
        extract_url_lexical_features = None
        SUSPICIOUS_KEYWORDS = ["login", "verify", "account", "secure", "update", "bank", "claim", "prize", "wp-content", "confirm", "free"]

ENGINE_NAME = "Static URL heuristic engine (rule-based, no network access)"
MAX_URL_LENGTH = 2048

# Known link-shortening services (domain match on registrable host).
URL_SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "tiny.cc", "cutt.ly", "rb.gy", "shorturl.at", "t.ly",
    "rebrand.ly", "s.id", "v.gd", "bl.ink", "short.io", "tr.im", "qr.ae",
    "lnkd.in", "trib.al", "soo.gd", "clck.ru", "shrtco.de", "u.to", "x.gd",
}

# TLDs frequently abused in phishing campaigns (an indicator, not proof).
SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "work", "gq", "cf", "ml", "ga", "tk", "fit",
    "icu", "country", "link", "buzz", "monster", "online", "site", "click",
    "loan", "club", "rest", "cam", "quest", "sbs", "cfd", "bar", "live",
    "support", "help", "win", "bid", "party", "review", "kim", "men",
}

# Common two-level public suffixes, so registrable domains are computed sensibly
# without downloading the Public Suffix List.
TWO_LEVEL_SUFFIXES = {
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "res.in", "nic.in",
    "firm.in", "gen.in", "ind.in", "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au", "gov.au", "co.nz", "co.jp", "com.br",
    "com.sg", "com.my", "co.za", "com.cn", "com.hk",
}

# Brand keyword -> official registrable domains. Used for impersonation and
# typosquatting checks only. This is a small, explicit, auditable list.
BRAND_DOMAINS: Dict[str, Tuple[str, ...]] = {
    "sbi": ("sbi.co.in", "onlinesbi.sbi", "sbi.bank.in", "onlinesbi.com"),
    "hdfc": ("hdfcbank.com", "hdfc.com", "hdfclife.com"),
    "hdfcbank": ("hdfcbank.com",),
    "icici": ("icicibank.com", "icicidirect.com"),
    "icicibank": ("icicibank.com",),
    "axisbank": ("axisbank.com",),
    "kotak": ("kotak.com",),
    "paytm": ("paytm.com",),
    "phonepe": ("phonepe.com",),
    "amazon": ("amazon.in", "amazon.com"),
    "flipkart": ("flipkart.com",),
    "paypal": ("paypal.com",),
    "google": ("google.com", "google.co.in"),
    "microsoft": ("microsoft.com", "live.com", "office.com"),
    "apple": ("apple.com", "icloud.com"),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com",),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "indiapost": ("indiapost.gov.in",),
    "incometax": ("incometax.gov.in",),
    "uidai": ("uidai.gov.in",),
    "irctc": ("irctc.co.in",),
    "linkedin": ("linkedin.com",),
}

SUSPICIOUS_PATH_KEYWORDS = (
    "login", "signin", "sign-in", "verify", "verification", "account", "secure",
    "update", "kyc", "banking", "confirm", "password", "otp", "wallet", "reward",
    "claim", "prize", "unlock", "suspend", "billing", "invoice", "refund",
)

RISKY_FILE_EXTENSIONS = (".exe", ".apk", ".scr", ".bat", ".cmd", ".msi", ".js", ".vbs", ".jar", ".zip", ".rar", ".iso")
REDIRECT_PARAM_NAMES = {"url", "redirect", "redirect_url", "redirect_uri", "next", "goto", "target", "dest", "destination", "return", "returnurl", "continue", "u", "r"}
STANDARD_PORTS = {None, 80, 443}

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_DOMAIN_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3}


def shannon_entropy(value: str) -> float:
    """Shannon entropy (bits per character) of a string. Pure math."""
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance (insert/delete/substitute)."""
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def registrable_domain(host: str) -> str:
    """Approximate registrable domain (eTLD+1) without network access."""
    labels = [p for p in host.split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    last_two = ".".join(labels[-2:])
    if last_two in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return last_two


def _ip_host(host: str) -> Optional[str]:
    """Return a normalised IP string if host is a literal / encoded IP address."""
    candidate = host.strip("[]")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        pass
    # Decimal (e.g. 3232235777) or hex (0xC0A80101) encoded IPv4 obfuscation.
    try:
        if re.fullmatch(r"\d{8,10}", candidate):
            return str(ipaddress.IPv4Address(int(candidate)))
        if re.fullmatch(r"0x[0-9a-fA-F]{1,8}", candidate):
            return str(ipaddress.IPv4Address(int(candidate, 16)))
    except (ValueError, ipaddress.AddressValueError):
        return None
    return None


def _finding(code: str, severity: str, title: str, detail: str, component: Optional[str] = None) -> Dict[str, Any]:
    f: Dict[str, Any] = {"code": code, "severity": severity, "title": title, "detail": detail}
    if component:
        f["component"] = component
    return f


def _decode_punycode(host: str) -> Optional[str]:
    if "xn--" not in host:
        return None
    try:
        return host.encode("ascii").decode("idna")
    except Exception:
        return None


def compute_structural_checks(
    url: str,
    intel_result: Dict[str, Any],
    lexical: Optional[Dict[str, float]] = None,
) -> List[Dict[str, Any]]:
    """
    Evaluate the 9 static lexical & structural checks for the URL string.
    Zero network interaction. Pure offline string inspection.

    Allowed statuses: "Detected" | "Not Detected" | "Unable to Evaluate"
    """
    checks: List[Dict[str, Any]] = []

    is_valid = bool(intel_result.get("valid", False))
    components = intel_result.get("components") or {}
    metrics = intel_result.get("metrics") or {}
    findings = intel_result.get("findings") or []
    finding_codes = {f.get("code") for f in findings if isinstance(f, dict)}
    brand_match = intel_result.get("brand_match") or {}

    scheme = (components.get("scheme") or "").lower()
    scheme_supplied = bool(components.get("scheme_supplied", False))
    host = components.get("host") or ""
    reg_domain = components.get("registrable_domain") or host
    is_ip = bool(components.get("is_ip_address", False))
    ip_addr = components.get("ip_address") or host
    subdomain_count = int(components.get("subdomain_count") or 0)
    url_length = int(metrics.get("url_length") or len(url))
    path = components.get("path") or ""
    path_segments = [p for p in path.split("/") if p]
    path_depth = len(path_segments)
    entropy = float(metrics.get("domain_entropy_bits") or 0.0)
    hyphen_count = int(metrics.get("hyphen_count_in_host") or host.count("-"))
    is_shortener = bool(metrics.get("is_shortener", False)) or ("url_shortener" in finding_codes)

    # 1. HTTPS Protocol
    # Clarification: HTTPS secures connection encryption only; it does NOT prove a website is safe.
    if not is_valid and not scheme_supplied:
        checks.append({
            "id": "https_protocol",
            "name": "HTTPS Protocol",
            "status": "Unable to Evaluate",
            "severity": "info",
            "explanation": "No protocol scheme (http:// or https://) was provided in the input URL; transport security cannot be verified statically.",
        })
    elif not scheme_supplied:
        checks.append({
            "id": "https_protocol",
            "name": "HTTPS Protocol",
            "status": "Unable to Evaluate",
            "severity": "info",
            "explanation": "No web scheme (http:// or https://) was explicitly supplied. Transport encryption status cannot be confirmed.",
        })
    elif scheme == "http":
        checks.append({
            "id": "https_protocol",
            "name": "HTTPS Protocol",
            "status": "Detected",
            "severity": "warning",
            "explanation": "Unencrypted HTTP scheme detected. Data is sent in cleartext without TLS encryption, vulnerable to interception or tampering.",
        })
    elif scheme == "https":
        checks.append({
            "id": "https_protocol",
            "name": "HTTPS Protocol",
            "status": "Not Detected",
            "severity": "safe",
            "explanation": "Uses HTTPS encryption for data in transit. Important: HTTPS secures connection encryption only; it does NOT prove that the destination website or owner is legitimate or safe.",
        })
    else:
        checks.append({
            "id": "https_protocol",
            "name": "HTTPS Protocol",
            "status": "Unable to Evaluate",
            "severity": "info",
            "explanation": f"Non-web scheme '{scheme}:' detected; HTTPS status cannot be evaluated.",
        })

    # 2. URL Length & Depth
    if url_length > 100 or path_depth >= 4 or "long_url" in finding_codes or "path_double_slash" in finding_codes:
        depth_str = f"{path_depth} path level{'s' if path_depth != 1 else ''}"
        checks.append({
            "id": "url_length_depth",
            "name": "URL Length & Depth",
            "status": "Detected",
            "severity": "warning",
            "explanation": f"Abnormal length or depth ({url_length} characters, {depth_str}). Deceptive links frequently use excessive length or deep subpaths to hide the real domain on smaller screens.",
        })
    else:
        depth_str = f"{path_depth} path level{'s' if path_depth != 1 else ''}"
        checks.append({
            "id": "url_length_depth",
            "name": "URL Length & Depth",
            "status": "Not Detected",
            "severity": "safe",
            "explanation": f"URL length ({url_length} characters) and path depth ({depth_str}) are within standard boundaries.",
        })

    # 3. Domain Structure
    if not is_valid and not host:
        checks.append({
            "id": "domain_structure",
            "name": "Domain Structure",
            "status": "Unable to Evaluate",
            "severity": "info",
            "explanation": "No valid domain or host could be identified to inspect domain structure.",
        })
    elif is_ip:
        checks.append({
            "id": "domain_structure",
            "name": "Domain Structure",
            "status": "Unable to Evaluate",
            "severity": "info",
            "explanation": "Domain structure analysis is not applicable because the target host is a numeric IP address rather than a domain name.",
        })
    else:
        domain_issues = []
        if "typosquatting" in finding_codes:
            domain_issues.append(f"possible typosquat of '{brand_match.get('brand', 'brand')}'")
        if "brand_impersonation" in finding_codes:
            domain_issues.append(f"brand name '{brand_match.get('brand', 'brand')}' on unauthorized domain '{reg_domain}'")
        if "idn_homograph" in finding_codes:
            domain_issues.append("internationalized/punycode look-alike characters")
        if "many_hyphens" in finding_codes:
            domain_issues.append(f"{hyphen_count} hyphens in host")
        if "high_entropy" in finding_codes:
            domain_issues.append(f"high character entropy ({entropy} bits/char)")
        if "suspicious_tld" in finding_codes:
            domain_issues.append(f"frequently abused .{components.get('tld', '')} TLD")

        if domain_issues:
            checks.append({
                "id": "domain_structure",
                "name": "Domain Structure",
                "status": "Detected",
                "severity": "danger" if any(f.get("severity") == "high" for f in findings if isinstance(f, dict) and f.get("code") in ("typosquatting", "brand_impersonation", "idn_homograph")) else "warning",
                "explanation": f"Suspicious domain structure detected: {'; '.join(domain_issues)}.",
            })
        else:
            checks.append({
                "id": "domain_structure",
                "name": "Domain Structure",
                "status": "Not Detected",
                "severity": "safe",
                "explanation": f"Domain name ('{reg_domain}') follows standard naming conventions with normal entropy ({entropy} bits/char).",
            })

    # 4. Subdomain Count
    if not is_valid and not host:
        checks.append({
            "id": "subdomain_count",
            "name": "Subdomain Count",
            "status": "Unable to Evaluate",
            "severity": "info",
            "explanation": "Unable to evaluate subdomains without a valid host.",
        })
    elif is_ip:
        checks.append({
            "id": "subdomain_count",
            "name": "Subdomain Count",
            "status": "Unable to Evaluate",
            "severity": "info",
            "explanation": "Subdomain count is not applicable to numeric IP addresses.",
        })
    elif subdomain_count >= 3 or "deep_subdomains" in finding_codes:
        checks.append({
            "id": "subdomain_count",
            "name": "Subdomain Count",
            "status": "Detected",
            "severity": "warning",
            "explanation": f"Excessive subdomain nesting detected ({subdomain_count} subdomain levels). Phishing links often chain subdomains to push the authentic domain off the screen.",
        })
    else:
        checks.append({
            "id": "subdomain_count",
            "name": "Subdomain Count",
            "status": "Not Detected",
            "severity": "safe",
            "explanation": f"Subdomain count ({subdomain_count} level{'s' if subdomain_count != 1 else ''}) is within normal operational parameters.",
        })

    # 5. Raw IP Hostname
    if is_ip:
        checks.append({
            "id": "raw_ip_hostname",
            "name": "Raw IP Hostname",
            "status": "Detected",
            "severity": "danger",
            "explanation": f"Host is a raw numerical IP address ({ip_addr}) instead of a domain name. Legitimate organizations rarely instruct users to navigate to raw IP addresses.",
        })
    elif not is_valid and not host:
        checks.append({
            "id": "raw_ip_hostname",
            "name": "Raw IP Hostname",
            "status": "Unable to Evaluate",
            "severity": "info",
            "explanation": "No host was identified to determine if an IP address is present.",
        })
    else:
        checks.append({
            "id": "raw_ip_hostname",
            "name": "Raw IP Hostname",
            "status": "Not Detected",
            "severity": "safe",
            "explanation": f"Host uses a registered domain name ('{host}'), not a raw IP address.",
        })

    # 6. @ Symbol Obfuscation
    if "@" in url or "userinfo_at" in finding_codes:
        checks.append({
            "id": "at_symbol_obfuscation",
            "name": "@ Symbol Obfuscation",
            "status": "Detected",
            "severity": "danger",
            "explanation": "Deceptive '@' symbol detected in the address authority. Browsers disregard text before '@' and route to the host that follows, disguising the true destination.",
        })
    else:
        checks.append({
            "id": "at_symbol_obfuscation",
            "name": "@ Symbol Obfuscation",
            "status": "Not Detected",
            "severity": "safe",
            "explanation": "No '@' symbol credential obfuscation detected in the address authority.",
        })

    # 7. Phishing Keywords
    matched_keywords = set()
    url_lower = url.lower()
    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if kw in url_lower:
            matched_keywords.add(kw)
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url_lower:
            matched_keywords.add(kw)

    if matched_keywords:
        kw_str = ", ".join(sorted(matched_keywords)[:6])
        checks.append({
            "id": "phishing_keywords",
            "name": "Phishing Keywords",
            "status": "Detected",
            "severity": "warning",
            "explanation": f"Detected sensitive phishing keywords ({kw_str}) commonly leveraged in credential-harvesting or account verification lures.",
        })
    else:
        checks.append({
            "id": "phishing_keywords",
            "name": "Phishing Keywords",
            "status": "Not Detected",
            "severity": "safe",
            "explanation": "No typical phishing or credential-harvesting keywords found in the URL.",
        })

    # 8. URL Shortener Service
    if not is_valid and not host:
        checks.append({
            "id": "url_shortener_service",
            "name": "URL Shortener Service",
            "status": "Unable to Evaluate",
            "severity": "info",
            "explanation": "Unable to evaluate URL shorteners without a valid host.",
        })
    elif is_ip:
        checks.append({
            "id": "url_shortener_service",
            "name": "URL Shortener Service",
            "status": "Unable to Evaluate",
            "severity": "info",
            "explanation": "Shortener detection is not applicable to numeric IP addresses.",
        })
    elif is_shortener:
        checks.append({
            "id": "url_shortener_service",
            "name": "URL Shortener Service",
            "status": "Detected",
            "severity": "warning",
            "explanation": f"'{reg_domain}' is a known URL shortening service that conceals the true destination without revealing where it leads.",
        })
    else:
        checks.append({
            "id": "url_shortener_service",
            "name": "URL Shortener Service",
            "status": "Not Detected",
            "severity": "safe",
            "explanation": f"Host ('{reg_domain}') is a direct domain name, not an identified URL shortening or masking service.",
        })

    # 9. Special Character Density
    special_symbols = sum(url.count(c) for c in ['-', '_', '&', '=', '?', '%', '/', '.', '@', '+', ':'])
    digits_in_host = metrics.get("digit_count_in_host", 0)
    has_encoded_host = "encoded_host" in finding_codes
    has_redirect = "embedded_redirect" in finding_codes

    if has_encoded_host or has_redirect or special_symbols > 14 or (digits_in_host >= 4 and not is_ip):
        detail_reasons = []
        if has_encoded_host:
            detail_reasons.append("percent-encoded host characters")
        if has_redirect:
            detail_reasons.append("embedded redirect parameters")
        if special_symbols > 14:
            detail_reasons.append(f"{special_symbols} special symbols")
        if digits_in_host >= 4 and not is_ip:
            detail_reasons.append(f"{digits_in_host} numeric digits in host")
        checks.append({
            "id": "special_character_density",
            "name": "Special Character Density",
            "status": "Detected",
            "severity": "warning",
            "explanation": f"High density of special characters or parameters ({'; '.join(detail_reasons)}), often used to evade security filters or conceal targets.",
        })
    else:
        checks.append({
            "id": "special_character_density",
            "name": "Special Character Density",
            "status": "Not Detected",
            "severity": "safe",
            "explanation": f"Special character count ({special_symbols} symbols) and encoding patterns are within normal web link distributions.",
        })

    return checks


def compute_url_component_offsets(
    url: str,
    scheme_supplied: bool,
    host: str,
    reg_domain: str,
    subdomain: Optional[str],
    tld: Optional[str],
    port: Optional[int],
    path: str,
    query: str,
) -> Dict[str, Tuple[int, int]]:
    """
    Compute exact character offsets (start, end) for parsed URL components
    relative to the submitted raw URL string.

    Guarantees:
    - 0 <= start < end <= len(url)
    - url[start:end] strictly corresponds to the component representation.
    """
    offsets: Dict[str, Tuple[int, int]] = {}
    if not url:
        return offsets

    # 1. Scheme
    auth_start = 0
    if scheme_supplied:
        m_scheme = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*)://", url)
        if m_scheme:
            offsets["scheme"] = (0, m_scheme.end(1))
            auth_start = m_scheme.end()

    # 2. Userinfo check
    userinfo_match = re.match(r"^(?:[^/@]+)@", url[auth_start:])
    if userinfo_match:
        host_start = auth_start + userinfo_match.end()
    else:
        host_start = auth_start

    # 3. Host and host sub-components
    if host:
        h_idx = url.lower().find(host.lower(), host_start)
        if h_idx != -1:
            host_start = h_idx
            host_end = host_start + len(host)
            offsets["host"] = (host_start, host_end)

            # Subdomain
            if subdomain and host.lower().startswith(subdomain.lower() + "."):
                offsets["subdomain"] = (host_start, host_start + len(subdomain))

            # Registrable domain
            if reg_domain and host.lower().endswith(reg_domain.lower()):
                reg_start = host_end - len(reg_domain)
                offsets["registrable_domain"] = (reg_start, host_end)

                # TLD
                if tld and reg_domain.lower().endswith("." + tld.lower()):
                    offsets["tld"] = (host_end - len(tld), host_end)

            after_host = host_end

            # Port
            if port is not None:
                port_match = re.match(r"^:(\d+)", url[host_end:])
                if port_match:
                    offsets["port"] = (host_end + 1, host_end + port_match.end(1))
                    after_host = host_end + port_match.end()

            # Path
            if path and path != "/" and url[after_host:].startswith(path):
                offsets["path"] = (after_host, after_host + len(path))
                after_path = after_host + len(path)
            elif path == "/" and url[after_host:].startswith("/"):
                offsets["path"] = (after_host, after_host + 1)
                after_path = after_host + 1
            else:
                after_path = after_host

            # Query
            if query:
                q_idx = url.find("?" + query, after_path)
                if q_idx != -1:
                    offsets["query"] = (q_idx + 1, q_idx + 1 + len(query))

    # Strict validation: every offset must satisfy 0 <= start < end <= len(url)
    validated: Dict[str, Tuple[int, int]] = {}
    url_len = len(url)
    for comp_name, (start, end) in offsets.items():
        if 0 <= start < end <= url_len:
            validated[comp_name] = (start, end)

    return validated


def analyze_url_static(raw_url: str) -> Dict[str, Any]:
    """
    Decompose a URL string and evaluate static lexical warning signs.

    Never raises for malformed input: returns a structured result with
    ``valid=False`` and an explanatory ``error`` instead.
    """
    result: Dict[str, Any] = {
        "engine": ENGINE_NAME,
        "network_access": False,
        "input": "",
        "valid": False,
        "error": None,
        "normalized_url": None,
        "components": None,
        "metrics": None,
        "findings": [],
        "heuristic_level": "Not assessed",
        "heuristic_score": 0,
        "structural_checks": [],
        "lexical_features": None,
        "disclaimer": (
            "Heuristic indicators are rule-based observations about the URL text. "
            "They are not Random Forest model output and do not confirm that a site is malicious. "
            "The URL was never opened, fetched or resolved."
        ),
    }

    if raw_url is None:
        result["error"] = "No URL provided."
        result["structural_checks"] = compute_structural_checks("", result, None)
        return result

    url = str(raw_url).strip()
    # Strip control characters / whitespace that can hide content.
    url = "".join(ch for ch in url if unicodedata.category(ch)[0] != "C")
    result["input"] = url[:MAX_URL_LENGTH]
    if not url:
        result["error"] = "No URL provided."
        result["structural_checks"] = compute_structural_checks("", result, None)
        return result
    if len(url) > MAX_URL_LENGTH:
        result["error"] = f"URL exceeds the {MAX_URL_LENGTH}-character limit."
        result["structural_checks"] = compute_structural_checks(url, result, None)
        return result
    if any(ch.isspace() for ch in url):
        result["error"] = "URL contains whitespace and cannot be parsed as a single address."
        result["structural_checks"] = compute_structural_checks(url, result, None)
        return result

    scheme_supplied = bool(_SCHEME_RE.match(url))
    parse_target = url if scheme_supplied else f"http://{url}"
    try:
        parts = urlsplit(parse_target)
        port = parts.port  # raises ValueError for invalid ports
    except ValueError as exc:
        result["error"] = f"Malformed URL: {exc}"
        result["structural_checks"] = compute_structural_checks(url, result, None)
        return result

    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    if scheme not in {"http", "https"}:
        findings = [_finding(
            "non_web_scheme", "medium", "Non-web URL scheme",
            f"The scheme '{scheme}:' is not a normal web link (http/https). Schemes such as javascript:, data: or file: can be abused.",
        )]
        result.update(valid=False, error=f"Unsupported scheme '{scheme}'. Only http and https URLs are analysed.", findings=findings)
        result["structural_checks"] = compute_structural_checks(url, result, None)
        return result
    if not host:
        result["error"] = "Malformed URL: no host name could be identified."
        result["structural_checks"] = compute_structural_checks(url, result, None)
        return result

    findings: List[Dict[str, str]] = []
    ip_value = _ip_host(host)
    is_ip = ip_value is not None
    decoded_idn = _decode_punycode(host)
    non_ascii_host = any(ord(ch) > 127 for ch in host)

    if not is_ip and not non_ascii_host:
        labels_ok = all(_DOMAIN_LABEL_RE.match(lbl) for lbl in host.split(".") if lbl)
        if not labels_ok or "." not in host:
            result["error"] = "Malformed URL: the host name is not a valid domain or IP address."
            result["structural_checks"] = compute_structural_checks(url, result, None)
            return result

    labels = [p for p in host.split(".") if p]
    tld = "" if is_ip else (labels[-1] if labels else "")
    reg_domain = host if is_ip else registrable_domain(host)
    subdomain = "" if is_ip or reg_domain == host else host[: -(len(reg_domain) + 1)]
    sub_labels = [s for s in subdomain.split(".") if s]
    reg_label = reg_domain.split(".")[0] if reg_domain and not is_ip else ""

    path = parts.path or ""
    query_pairs = parse_qsl(parts.query, keep_blank_values=True)
    decoded_path = unquote(path).lower()
    host_entropy = round(shannon_entropy(reg_label or host), 3)
    url_lower = url.lower()
    digits_in_host = sum(ch.isdigit() for ch in host)

    # ---------------- Findings (all static) ----------------
    if scheme == "http":
        findings.append(_finding("no_https", "medium", "Unencrypted HTTP scheme",
                                 "The link uses http:// rather than https://, so traffic to it would not be encrypted. Many legitimate sites still use HTTPS for any login or payment page.", component="scheme"))
    if not scheme_supplied:
        findings.append(_finding("no_scheme", "low", "No scheme supplied",
                                 "No http:// or https:// prefix was provided; http:// was assumed for parsing only.", component="scheme"))
    if is_ip:
        findings.append(_finding("ip_host", "high", "Raw IP address used as host",
                                 f"The host is an IP address ({ip_value}) instead of a domain name. Legitimate organisations rarely ask users to visit raw IP addresses.", component="host"))
    if parts.username is not None or "@" in (parts.netloc or ""):
        findings.append(_finding("userinfo_at", "high", "'@' symbol in the address authority",
                                 "Text before an '@' in the address is ignored by browsers, so a URL can appear to start with a trusted name while pointing elsewhere.", component="host"))
    if decoded_idn or non_ascii_host:
        shown = decoded_idn or host
        findings.append(_finding("idn_homograph", "high", "Internationalised (punycode / non-ASCII) host",
                                 f"The host contains non-ASCII characters ({shown}). Look-alike Unicode characters can imitate well-known brand names.", component="host"))
    reg_root = reg_domain.split(".")[0] if reg_domain else ""
    if not is_ip and any(reg_domain == s or reg_domain.endswith("." + s) for s in URL_SHORTENERS):
        findings.append(_finding("url_shortener", "medium", "URL shortening service",
                                 f"'{reg_domain}' is a link shortener, which hides the real destination. The final destination cannot be known without visiting the link, which SCAMLENS never does.", component="registrable_domain"))
    if tld and tld in SUSPICIOUS_TLDS:
        findings.append(_finding("suspicious_tld", "medium", f"Frequently abused top-level domain (.{tld})",
                                 f"The .{tld} extension is commonly seen in phishing campaigns. Many legitimate sites also use it, so this is only an indicator.", component="tld"))
    if len(sub_labels) >= 3:
        findings.append(_finding("deep_subdomains", "medium", "Many subdomain levels",
                                 f"The host has {len(sub_labels)} subdomain levels ({subdomain}). Deep nesting is sometimes used to push the real domain out of view.", component="subdomain"))
    if not is_ip and host.count("-") >= 3:
        findings.append(_finding("many_hyphens", "low", "Many hyphens in host",
                                 f"The host contains {host.count('-')} hyphens. Hyphen-heavy names (e.g. secure-login-verify-...) are common in look-alike domains.", component="host"))
    if not is_ip and reg_label and len(reg_label) >= 10 and host_entropy >= 3.6 and digits_in_host >= 2:
        findings.append(_finding("high_entropy", "medium", "Random-looking domain name",
                                 f"The domain label '{reg_label}' has high character entropy ({host_entropy} bits/char) and contains digits, which can indicate an algorithmically generated domain.", component="registrable_domain"))
    if len(url) > 100:
        findings.append(_finding("long_url", "low", "Unusually long URL",
                                 f"The URL is {len(url)} characters long. Very long URLs can hide the meaningful part of the address."))
    if port not in STANDARD_PORTS:
        findings.append(_finding("non_standard_port", "medium", f"Non-standard port ({port})",
                                 "Web pages normally use ports 80 or 443. A custom port is unusual for consumer-facing services.", component="port"))
    if "//" in path:
        findings.append(_finding("path_double_slash", "low", "Double slash inside path",
                                 "A '//' inside the path can be used to embed a second address or confuse readers.", component="path"))
    path_kw = sorted({kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in decoded_path or kw in host})
    if path_kw:
        findings.append(_finding("credential_keywords", "medium" if len(path_kw) >= 2 else "low", "Sensitive-action keywords in URL",
                                 "The URL text contains: " + ", ".join(path_kw) + ". These words are common in credential-harvesting links but also appear on genuine sites.", component="path"))
    redirect_params = [k for k, v in query_pairs if k.lower() in REDIRECT_PARAM_NAMES and re.match(r"^(https?:)?//", unquote(v).strip(), re.I)]
    if redirect_params:
        findings.append(_finding("embedded_redirect", "medium", "Embedded redirect parameter",
                                 f"Query parameter(s) {', '.join(redirect_params)} contain another web address, a pattern used by open-redirect phishing.", component="query"))
    if any(decoded_path.endswith(ext) for ext in RISKY_FILE_EXTENSIONS):
        findings.append(_finding("risky_download", "high", "Link points to an executable or archive file",
                                 "The path ends with a file type (e.g. .apk, .exe, .zip) that can install software. Never install files from unsolicited links.", component="path"))
    if "%" in url and re.search(r"%[0-9a-fA-F]{2}", parts.netloc or ""):
        findings.append(_finding("encoded_host", "medium", "Percent-encoded characters in host",
                                 "The host portion contains percent-encoding, which can disguise the real domain.", component="host"))

    # Brand impersonation / typosquatting.
    brand_match: Optional[Dict[str, Any]] = None
    if not is_ip:
        tokens = set(re.split(r"[.\-_]", host)) | set(re.split(r"[.\-_]", decoded_path))
        tokens.discard("")
        official_hit = None
        for brand, officials in BRAND_DOMAINS.items():
            if any(reg_domain == o or host.endswith("." + o) for o in officials):
                official_hit = brand
                break
        if official_hit is None:
            for brand, officials in BRAND_DOMAINS.items():
                in_host = brand in re.split(r"[.\-_]", host) or (len(brand) >= 5 and brand in host)
                if in_host:
                    brand_match = {"brand": brand, "type": "impersonation", "official_domains": list(officials)}
                    brand_comp = "subdomain" if (subdomain and brand in subdomain) else "registrable_domain"
                    findings.append(_finding("brand_impersonation", "high", f"Brand name '{brand}' used on an unrelated domain",
                                             f"The host mentions '{brand}', but the registrable domain is '{reg_domain}', not an official domain ({', '.join(officials)}). This is a common impersonation pattern.", component=brand_comp))
                    break
            if brand_match is None and reg_label and len(reg_label) >= 4:
                host_segments = [s for s in re.split(r"[.\-_]", host) if len(s) >= 4]
                candidate_labels = list(dict.fromkeys([reg_label] + host_segments))
                for brand, officials in BRAND_DOMAINS.items():
                    for official in officials:
                        official_label = official.split(".")[0]
                        if len(official_label) < 4:
                            continue
                        for cand in candidate_labels:
                            if cand == official_label:
                                continue
                            dist = levenshtein(cand, official_label)
                            if 0 < dist <= (1 if len(official_label) <= 6 else 2):
                                brand_match = {"brand": brand, "type": "typosquat", "edit_distance": dist, "official_domains": list(officials)}
                                findings.append(_finding("typosquatting", "high", f"Possible typosquat of '{official}'",
                                                         f"'{cand}' differs from the official name '{official_label}' by {dist} character edit(s). Look-alike spellings are a classic phishing technique.", component="registrable_domain"))
                                break
                        if brand_match:
                            break
                    if brand_match:
                        break
        else:
            brand_match = {"brand": official_hit, "type": "official_domain", "official_domains": list(BRAND_DOMAINS[official_hit])}

    score = sum(_SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings if f["code"] != "no_scheme")
    high_count = sum(1 for f in findings if f["severity"] == "high")
    if high_count >= 2 or score >= 7:
        level = "High"
    elif high_count == 1 or score >= 4:
        level = "Elevated"
    elif score >= 1:
        level = "Low"
    else:
        level = "No notable indicators"

    offsets = compute_url_component_offsets(
        url=url,
        scheme_supplied=scheme_supplied,
        host=host,
        reg_domain=reg_domain,
        subdomain=subdomain,
        tld=tld,
        port=port,
        path=parts.path,
        query=parts.query,
    )

    result.update(
        valid=True,
        normalized_url=parse_target,
        components={
            "scheme": scheme,
            "scheme_supplied": scheme_supplied,
            "host": host,
            "decoded_host": decoded_idn,
            "registrable_domain": reg_domain,
            "subdomain": subdomain or None,
            "subdomain_count": len(sub_labels),
            "tld": tld or None,
            "port": port,
            "path": path or "/",
            "query_parameter_count": len(query_pairs),
            "query_parameter_names": [k for k, _ in query_pairs][:20],
            "fragment": parts.fragment or None,
            "is_ip_address": is_ip,
            "ip_address": ip_value,
            "offsets": offsets,
        },
        metrics={
            "url_length": len(url),
            "host_length": len(host),
            "domain_entropy_bits": host_entropy,
            "digit_count_in_host": digits_in_host,
            "hyphen_count_in_host": host.count("-"),
            "dot_count": url.count("."),
            "uses_https": scheme == "https",
            "is_shortener": any(f["code"] == "url_shortener" for f in findings),
            "suspicious_tld": any(f["code"] == "suspicious_tld" for f in findings),
        },
        brand_match=brand_match,
        findings=findings,
        heuristic_level=level,
        heuristic_score=score,
    )

    # ---------------- Structural Checks (9 dimensions) ----------------
    lexical = None
    if extract_url_lexical_features is not None:
        try:
            lexical = extract_url_lexical_features(url)
        except Exception:
            lexical = None

    structural_checks = compute_structural_checks(url, result, lexical)
    result["structural_checks"] = structural_checks
    if lexical:
        result["lexical_features"] = lexical

    risk_verdict = calculate_url_risk_verdict(result)
    result["risk_verdict"] = risk_verdict

    return result


_URL_IN_TEXT_RE = re.compile(
    r"""(?ix)
    (?:https?://|www\.)[^\s<>"'()\[\]{}]+
    """
)


def extract_urls(text: str, limit: int = 10) -> List[str]:
    """Extract URL-like substrings from free text (static regex, no network)."""
    if not text:
        return []
    seen: List[str] = []
    for match in _URL_IN_TEXT_RE.finditer(text):
        candidate = match.group(0).rstrip(".,;:!?)\u2019\u201d'\"")
        if candidate.lower().startswith("www."):
            candidate = "http://" + candidate
        if candidate not in seen:
            seen.append(candidate)
        if len(seen) >= limit:
            break
    return seen


def calculate_url_risk_verdict(url_intel: Dict[str, Any]) -> Dict[str, Any]:
    """
    Derive the risk score, risk probability, risk level, and classification prediction
    strictly from static URL heuristic analysis findings and severity.

    Guarantees:
    - risk_probability == round(risk_score / 100.0, 4) (strictly synchronized)
    - risk_level is determined according to standard application risk thresholds.
    - Zero dependency on SMS-trained text ML models.
    - Official domain matches provide supporting evidence, but never suppress suspicious findings.
    """
    findings = url_intel.get("findings", [])
    high_count = sum(1 for f in findings if f.get("severity") == "high")
    score = url_intel.get("heuristic_score", 0)
    heuristic_level = url_intel.get("heuristic_level", "No notable indicators")
    brand_match = url_intel.get("brand_match")

    # 1. Base Score Calculation from Static Heuristic Findings
    if score == 0 or heuristic_level == "No notable indicators":
        # Zero structural risk indicators found.
        risk_score = 0.0
        risk_level = "Low"
        prediction = "Legitimate"
    elif heuristic_level == "Low":
        # Low severity indicators (score 1 to 3, high_count == 0)
        # Low risk tier: [0.0, 24.99]
        risk_score = round(min(24.0, score * 7.5), 1)
        risk_level = "Low"
        prediction = "Legitimate"
    elif heuristic_level == "Elevated":
        # Elevated severity: high_count == 1 OR score 4 to 6
        if high_count >= 1:
            # Contains at least one severe indicator (e.g. raw IP host or executable download)
            # High risk tier: [50.0, 74.99]
            risk_score = round(min(74.0, 50.0 + (score - 3) * 6.0), 1)
            risk_level = "High"
            prediction = "Scam/Phishing"
        else:
            # Multiple medium/low indicators without severe signals (e.g. HTTP + shortener + keywords)
            # Suspicious risk tier: [25.0, 49.99]
            risk_score = round(min(49.0, 25.0 + (score - 3) * 8.0), 1)
            risk_level = "Suspicious"
            prediction = "Legitimate"
    else:  # "High"
        # High severity: high_count >= 2 OR score >= 7
        if high_count >= 2 or score >= 9:
            # Severe compound phishing signals (Very High risk tier: [75.0, 100.0])
            risk_score = round(min(96.0, 78.0 + (score - 8) * 3.0), 1)
            risk_level = "Very High"
            prediction = "Scam/Phishing"
        else:
            # High severity signals (e.g. score 7 or 8 with high_count == 1, such as deceptive brand + suspicious TLD)
            # High risk tier: [50.0, 74.99]
            risk_score = round(min(74.5, 70.0 + (score - 7) * 4.5), 1)
            risk_level = "High"
            prediction = "Scam/Phishing"

    # Strictly synchronized probability
    risk_probability = round(risk_score / 100.0, 4)

    # 2. Explanatory Indicators
    indicators: List[str] = []
    for f in findings:
        tag = f"[URL] {f['title']}"
        indicators.append(tag)

    if brand_match:
        b_name = str(brand_match.get("brand", "")).upper()
        b_type = brand_match.get("type")
        if b_type == "official_domain":
            indicators.append(f"[Verified Domain] Host matches official domain for {b_name} (supporting evidence).")
        elif b_type in ("impersonation", "typosquat"):
            brand_indicator = f"[Deceptive Brand] Host appears to imitate {b_name}."
            if brand_indicator not in indicators:
                indicators.insert(0, brand_indicator)

    if not indicators:
        indicators.append("No suspicious structural indicators detected in URL text.")

    # 3. Plain-Language Safety Guidance (honest, no false guarantees of safety)
    # Guidance must always agree with the static findings: "no suspicious indicators" wording is
    # only used when the engine really found nothing. Scores and classifications are unaffected.
    official_name = (
        str(brand_match.get("brand", "")).upper()
        if brand_match and brand_match.get("type") == "official_domain"
        else None
    )
    if risk_level == "Low":
        if findings:
            titles = [str(f.get("title", "")).strip() for f in findings if f.get("title")]
            shown = "; ".join(titles[:3]) + (f"; and {len(titles) - 3} more" if len(titles) > 3 else "")
            has_notable = any(f.get("severity") in ("medium", "high") for f in findings)
            if has_notable:
                lead = (
                    f"A suspicious indicator was detected in the URL: {shown}. "
                    if len(findings) == 1
                    else f"Suspicious indicators were detected in the URL: {shown}. "
                )
                lead += (
                    "The overall static risk remains Low because only limited evidence was found, "
                    "but review this link carefully before clicking it. "
                )
            else:
                lead = (
                    f"Minor URL indicator(s) noted: {shown}. The overall static risk is Low, "
                    "but treat this link with normal caution. "
                )
            if official_name:
                lead += (
                    f"The host matches a recognized official domain for {official_name}, but an official "
                    "domain match does not make the path or query content of the link safe. "
                )
            guidance = (
                lead
                + "Automated static analysis cannot inspect the destination page content; always ensure you are "
                "on a genuine secure connection before entering credentials."
            )
        elif official_name:
            guidance = (
                f"The link points to a recognized official domain for {official_name} "
                "with no suspicious structural indicators. Automated static analysis cannot inspect dynamic "
                "destination page content; always ensure you are on a genuine secure connection before entering credentials."
            )
        else:
            guidance = (
                "No suspicious structural indicators detected in the URL text. While the link structure appears "
                "standard, automated static analysis cannot inspect external website content or guarantee server safety. "
                "Always exercise standard caution before sharing credentials or financial details."
            )
    elif risk_level == "Suspicious":
        guidance = (
            "Elevated risk signals detected in the URL structure. Avoid entering sensitive passwords, "
            "financial information, or downloading files from this address without independent verification."
        )
    elif risk_level == "High":
        guidance = (
            "High-risk deceptive indicators detected in the URL structure. Do not visit this link or "
            "provide passwords, OTPs, or financial information. Verify the address through an official channel."
        )
    else:  # Very High
        guidance = (
            "Critical phishing or malicious patterns detected in the URL structure. Do not click or open "
            "this link under any circumstances. Never disclose personal data, credentials, or OTPs."
        )

    return {
        "risk_score": risk_score,
        "risk_probability": risk_probability,
        "risk_level": risk_level,
        "prediction": prediction,
        "model": "Static URL Heuristic Engine",
        "indicators": indicators,
        "guidance": guidance,
    }
