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


def _finding(code: str, severity: str, title: str, detail: str) -> Dict[str, str]:
    return {"code": code, "severity": severity, "title": title, "detail": detail}


def _decode_punycode(host: str) -> Optional[str]:
    if "xn--" not in host:
        return None
    try:
        return host.encode("ascii").decode("idna")
    except Exception:
        return None


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
        "disclaimer": (
            "Heuristic indicators are rule-based observations about the URL text. "
            "They are not Random Forest model output and do not confirm that a site is malicious. "
            "The URL was never opened, fetched or resolved."
        ),
    }

    if raw_url is None:
        result["error"] = "No URL provided."
        return result

    url = str(raw_url).strip()
    # Strip control characters / whitespace that can hide content.
    url = "".join(ch for ch in url if unicodedata.category(ch)[0] != "C")
    result["input"] = url[:MAX_URL_LENGTH]
    if not url:
        result["error"] = "No URL provided."
        return result
    if len(url) > MAX_URL_LENGTH:
        result["error"] = f"URL exceeds the {MAX_URL_LENGTH}-character limit."
        return result
    if any(ch.isspace() for ch in url):
        result["error"] = "URL contains whitespace and cannot be parsed as a single address."
        return result

    scheme_supplied = bool(_SCHEME_RE.match(url))
    parse_target = url if scheme_supplied else f"http://{url}"
    try:
        parts = urlsplit(parse_target)
        port = parts.port  # raises ValueError for invalid ports
    except ValueError as exc:
        result["error"] = f"Malformed URL: {exc}"
        return result

    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    if scheme not in {"http", "https"}:
        findings = [_finding(
            "non_web_scheme", "medium", "Non-web URL scheme",
            f"The scheme '{scheme}:' is not a normal web link (http/https). Schemes such as javascript:, data: or file: can be abused.",
        )]
        result.update(valid=False, error=f"Unsupported scheme '{scheme}'. Only http and https URLs are analysed.", findings=findings)
        return result
    if not host:
        result["error"] = "Malformed URL: no host name could be identified."
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
                                 "The link uses http:// rather than https://, so traffic to it would not be encrypted. Many legitimate sites still use HTTPS for any login or payment page."))
    if not scheme_supplied:
        findings.append(_finding("no_scheme", "low", "No scheme supplied",
                                 "No http:// or https:// prefix was provided; http:// was assumed for parsing only."))
    if is_ip:
        findings.append(_finding("ip_host", "high", "Raw IP address used as host",
                                 f"The host is an IP address ({ip_value}) instead of a domain name. Legitimate organisations rarely ask users to visit raw IP addresses."))
    if parts.username is not None or "@" in (parts.netloc or ""):
        findings.append(_finding("userinfo_at", "high", "'@' symbol in the address authority",
                                 "Text before an '@' in the address is ignored by browsers, so a URL can appear to start with a trusted name while pointing elsewhere."))
    if decoded_idn or non_ascii_host:
        shown = decoded_idn or host
        findings.append(_finding("idn_homograph", "high", "Internationalised (punycode / non-ASCII) host",
                                 f"The host contains non-ASCII characters ({shown}). Look-alike Unicode characters can imitate well-known brand names."))
    reg_root = reg_domain.split(".")[0] if reg_domain else ""
    if not is_ip and any(reg_domain == s or reg_domain.endswith("." + s) for s in URL_SHORTENERS):
        findings.append(_finding("url_shortener", "medium", "URL shortening service",
                                 f"'{reg_domain}' is a link shortener, which hides the real destination. The final destination cannot be known without visiting the link, which SCAMLENS never does."))
    if tld and tld in SUSPICIOUS_TLDS:
        findings.append(_finding("suspicious_tld", "medium", f"Frequently abused top-level domain (.{tld})",
                                 f"The .{tld} extension is commonly seen in phishing campaigns. Many legitimate sites also use it, so this is only an indicator."))
    if len(sub_labels) >= 3:
        findings.append(_finding("deep_subdomains", "medium", "Many subdomain levels",
                                 f"The host has {len(sub_labels)} subdomain levels ({subdomain}). Deep nesting is sometimes used to push the real domain out of view."))
    if not is_ip and host.count("-") >= 3:
        findings.append(_finding("many_hyphens", "low", "Many hyphens in host",
                                 f"The host contains {host.count('-')} hyphens. Hyphen-heavy names (e.g. secure-login-verify-...) are common in look-alike domains."))
    if not is_ip and reg_label and len(reg_label) >= 10 and host_entropy >= 3.6 and digits_in_host >= 2:
        findings.append(_finding("high_entropy", "medium", "Random-looking domain name",
                                 f"The domain label '{reg_label}' has high character entropy ({host_entropy} bits/char) and contains digits, which can indicate an algorithmically generated domain."))
    if len(url) > 100:
        findings.append(_finding("long_url", "low", "Unusually long URL",
                                 f"The URL is {len(url)} characters long. Very long URLs can hide the meaningful part of the address."))
    if port not in STANDARD_PORTS:
        findings.append(_finding("non_standard_port", "medium", f"Non-standard port ({port})",
                                 "Web pages normally use ports 80 or 443. A custom port is unusual for consumer-facing services."))
    if "//" in path:
        findings.append(_finding("path_double_slash", "low", "Double slash inside path",
                                 "A '//' inside the path can be used to embed a second address or confuse readers."))
    path_kw = sorted({kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in decoded_path or kw in host})
    if path_kw:
        findings.append(_finding("credential_keywords", "medium" if len(path_kw) >= 2 else "low", "Sensitive-action keywords in URL",
                                 "The URL text contains: " + ", ".join(path_kw) + ". These words are common in credential-harvesting links but also appear on genuine sites."))
    redirect_params = [k for k, v in query_pairs if k.lower() in REDIRECT_PARAM_NAMES and re.match(r"^(https?:)?//", unquote(v).strip(), re.I)]
    if redirect_params:
        findings.append(_finding("embedded_redirect", "medium", "Embedded redirect parameter",
                                 f"Query parameter(s) {', '.join(redirect_params)} contain another web address, a pattern used by open-redirect phishing."))
    if any(decoded_path.endswith(ext) for ext in RISKY_FILE_EXTENSIONS):
        findings.append(_finding("risky_download", "high", "Link points to an executable or archive file",
                                 "The path ends with a file type (e.g. .apk, .exe, .zip) that can install software. Never install files from unsolicited links."))
    if "%" in url and re.search(r"%[0-9a-fA-F]{2}", parts.netloc or ""):
        findings.append(_finding("encoded_host", "medium", "Percent-encoded characters in host",
                                 "The host portion contains percent-encoding, which can disguise the real domain."))

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
                    findings.append(_finding("brand_impersonation", "high", f"Brand name '{brand}' used on an unrelated domain",
                                             f"The host mentions '{brand}', but the registrable domain is '{reg_domain}', not an official domain ({', '.join(officials)}). This is a common impersonation pattern."))
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
                                                         f"'{cand}' differs from the official name '{official_label}' by {dist} character edit(s). Look-alike spellings are a classic phishing technique."))
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
