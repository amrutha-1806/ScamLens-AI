"""
SCAMLENS AI — SSRF-Protected URL Redirect & Advanced Link Inspector

SECURITY CONTRACT (FEATURE 3):
- Allows ONLY http:// and https:// schemes.
- Blocks all private, loopback, link-local, cloud metadata (169.254.169.254),
  Carrier-Grade NAT (100.64.0.0/10), multicast, unspecified, and reserved IP addresses.
- Blocks internal hostnames (localhost, *.local, *.internal, metadata.google.internal).
- Protects against DNS rebinding by resolving DNS once per hop, validating every
  returned IP address, and connecting directly to the validated public IP while
  preserving the Host header and TLS SNI server_hostname.
- Follows at most MAX_REDIRECTS (5) hops manually, re-validating every redirect target.
- Uses strict socket timeouts (2.5s) and reads headers only (0 body bytes executed).
- Never claims a URL is safe solely because no warning was triggered.
"""

from __future__ import annotations

import http.client
import ipaddress
import re
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from backend.services.url_intelligence import (
    BRAND_DOMAINS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    analyze_url_static,
    calculate_url_risk_verdict,
    levenshtein,
    registrable_domain,
)

MAX_REDIRECTS = 5
HOP_TIMEOUT_SECONDS = 2.5
MAX_URL_LEN = 2048

BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata",
    "metadata.google.internal",
    "instance-data",
    "169.254.169.254",
}

BLOCKED_HOST_SUFFIXES = (
    ".local",
    ".localhost",
    ".internal",
    ".intranet",
    ".corp",
    ".home",
    ".lan",
    ".arpa",
)

# Common visual character substitutions used in lookalike domains
LEET_SUBSTITUTIONS = (
    ("0", "o"),
    ("1", "l"),
    ("1", "i"),
    ("rn", "m"),
    ("vv", "w"),
    ("5", "s"),
    ("3", "e"),
    ("4", "a"),
)


def is_ip_public_and_safe(ip_str: str) -> Tuple[bool, Optional[str]]:
    """
    Validate that an IPv4 or IPv6 address is strictly public and routable.
    Rejects loopback, private, link-local, metadata, CGNAT, multicast, reserved,
    and IPv4-mapped private IPv6 addresses.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, f"Invalid IP address format: {ip_str}"

    # Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped

    if ip_obj.is_loopback:
        return False, "Blocked loopback IP address (SSRF protection)."
    if ip_obj.is_private:
        return False, "Blocked private network IP address (SSRF protection)."
    if ip_obj.is_link_local:
        return False, "Blocked link-local / cloud metadata IP address (SSRF protection)."
    if ip_obj.is_multicast:
        return False, "Blocked multicast IP address (SSRF protection)."
    if ip_obj.is_unspecified:
        return False, "Blocked unspecified (0.0.0.0 / ::) IP address (SSRF protection)."
    if ip_obj.is_reserved:
        return False, "Blocked reserved IP address range (SSRF protection)."

    # Explicitly block RFC 6598 Carrier-Grade NAT (100.64.0.0/10) and Benchmarking (198.18.0.0/15)
    if isinstance(ip_obj, ipaddress.IPv4Address):
        cgnat_net = ipaddress.IPv4Network("100.64.0.0/10")
        benchmark_net = ipaddress.IPv4Network("198.18.0.0/15")
        if ip_obj in cgnat_net or ip_obj in benchmark_net:
            return False, "Blocked internal/shared address space (SSRF protection)."

    if not ip_obj.is_global:
        return False, "Blocked non-global IP address (SSRF protection)."

    return True, None


def validate_and_resolve_host(hostname: str, port: int) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Validate hostname and resolve its DNS records, ensuring every resolved IP is public.
    Returns (is_safe, first_validated_ip, error_reason).
    """
    if not hostname:
        return False, None, "Missing hostname in URL."

    lower_host = hostname.strip().lower().rstrip(".")
    if lower_host in BLOCKED_HOSTNAMES or any(lower_host.endswith(suf) for suf in BLOCKED_HOST_SUFFIXES):
        return False, None, f"Blocked internal or local hostname '{lower_host}' (SSRF protection)."

    # Check if hostname is already a literal IP
    literal_candidate = lower_host.strip("[]")
    try:
        ipaddress.ip_address(literal_candidate)
        ok, reason = is_ip_public_and_safe(literal_candidate)
        if not ok:
            return False, None, reason
        return True, literal_candidate, None
    except ValueError:
        pass

    # Check decimal/hex encoded IPv4 literals (e.g. 2130706433 or 0x7f000001)
    if re.fullmatch(r"\d{8,10}", literal_candidate) or re.fullmatch(r"0x[0-9a-fA-F]{1,8}", literal_candidate):
        return False, None, "Blocked obfuscated numeric IP literal (SSRF protection)."

    try:
        addr_info = socket.getaddrinfo(lower_host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False, None, f"Destination hostname '{lower_host}' could not be resolved via DNS."
    except Exception as exc:
        return False, None, f"DNS resolution error: {exc}"

    if not addr_info:
        return False, None, f"No DNS records returned for '{lower_host}'."

    validated_ips: List[str] = []
    for family, _, _, _, sockaddr in addr_info:
        ip_str = str(sockaddr[0])
        ok, reason = is_ip_public_and_safe(ip_str)
        if not ok:
            # If ANY DNS record points to an internal/private IP, abort immediately
            return False, None, f"DNS resolution for '{lower_host}' returned a restricted IP ({reason})"
        if ip_str not in validated_ips:
            validated_ips.append(ip_str)

    return True, validated_ips[0], None


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """
    Connects directly to a pre-validated public IP address (preventing DNS rebinding)
    while validating the TLS certificate against the original hostname via SNI.
    """

    def __init__(self, pinned_ip: str, original_host: str, port: int, timeout: float):
        super().__init__(pinned_ip, port=port, timeout=timeout, context=ssl.create_default_context())
        self._original_host = original_host

    def connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._original_host)


def _perform_single_hop_request(
    scheme: str,
    hostname: str,
    pinned_ip: str,
    port: int,
    path_and_query: str,
) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """
    Perform a single non-redirecting HEAD request (with GET fallback) to the pinned IP.
    Reads response status and Location header ONLY (zero body execution).
    Returns (status_code, location_header, error_reason).
    """
    conn: Optional[http.client.HTTPConnection] = None
    try:
        if scheme == "https":
            conn = _PinnedHTTPSConnection(pinned_ip, hostname, port, timeout=HOP_TIMEOUT_SECONDS)
        else:
            conn = http.client.HTTPConnection(pinned_ip, port=port, timeout=HOP_TIMEOUT_SECONDS)

        host_header = hostname if port in (80, 443) else f"{hostname}:{port}"
        headers = {
            "Host": host_header,
            "User-Agent": "SCAMLENS-SafeLinkChecker/1.0 (+https://scamlens-ai-seven.vercel.app)",
            "Accept": "*/*",
            "Connection": "close",
        }
        conn.request("HEAD", path_and_query or "/", headers=headers)
        resp = conn.getresponse()
        status = int(resp.status)
        location = resp.getheader("Location")
        conn.close()
        conn = None

        # Some shorteners return 405 Method Not Allowed on HEAD; retry with Range GET without reading body
        if status == 405 and location is None:
            if scheme == "https":
                conn = _PinnedHTTPSConnection(pinned_ip, hostname, port, timeout=HOP_TIMEOUT_SECONDS)
            else:
                conn = http.client.HTTPConnection(pinned_ip, port=port, timeout=HOP_TIMEOUT_SECONDS)
            headers["Range"] = "bytes=0-0"
            conn.request("GET", path_and_query or "/", headers=headers)
            resp = conn.getresponse()
            status = int(resp.status)
            location = resp.getheader("Location")
            conn.close()
            conn = None

        return status, location, None
    except ssl.SSLError as exc:
        return None, None, f"TLS/SSL certificate verification failed: {exc.reason if hasattr(exc, 'reason') else exc}"
    except socket.timeout:
        return None, None, f"Connection timed out after {HOP_TIMEOUT_SECONDS}s."
    except Exception as exc:
        return None, None, f"Destination could not be reached safely: {exc}"
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def detect_lookalike_and_homograph_warnings(url: str) -> List[Dict[str, str]]:
    """
    Detect character substitutions (e.g. paypa1, g00gle, rnicrosoft), punycode/IDN homographs,
    and lookalike domain patterns in simple language.
    """
    warnings: List[Dict[str, str]] = []
    try:
        candidate = url.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", candidate):
            candidate = "http://" + candidate
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower().rstrip(".")
    except Exception:
        return warnings

    if not host:
        return warnings

    reg = registrable_domain(host)
    sld = reg.split(".")[0] if reg else host

    # 1. Punycode / IDN homograph check
    if "xn--" in host:
        decoded = None
        try:
            decoded = host.encode("ascii").decode("idna")
        except Exception:
            decoded = None
        exp = (
            f"This domain uses Punycode ('{host}'"
            + (f", which renders as '{decoded}'" if decoded else "")
            + "). Attackers use non-Latin lookalike letters to imitate trusted websites."
        )
        warnings.append({
            "code": "PUNYCODE_IDN_HOMOGRAPH",
            "severity": "high",
            "title": "Internationalized (Punycode) Lookalike Risk",
            "explanation": exp,
            "plain_explanation": exp,
        })

    # 2. Mixed non-ASCII characters in hostname
    if any(ord(c) > 127 for c in host):
        exp = "The website address contains non-ASCII characters that can visually mimic standard English letters (IDN homograph attack)."
        warnings.append({
            "code": "NON_ASCII_HOST",
            "severity": "high",
            "title": "Non-Standard Characters in Domain Name",
            "explanation": exp,
            "plain_explanation": exp,
        })

    # 3. Character substitution / leet-speak brand lookalike detection (e.g., 0->o, 1->l, rn->m)
    normalized_candidates = {sld}
    de_leeted = sld
    for src, dst in LEET_SUBSTITUTIONS:
        if src in de_leeted:
            normalized_candidates.add(de_leeted.replace(src, dst))
            de_leeted = de_leeted.replace(src, dst)
    normalized_candidates.add(de_leeted)

    all_official_domains = {d for domains in BRAND_DOMAINS.values() for d in domains}
    if reg not in all_official_domains:
        for brand, official_list in BRAND_DOMAINS.items():
            if len(brand) < 4:
                continue
            matched_sub = False
            for cand in normalized_candidates:
                if cand != sld and (cand == brand or brand in cand):
                    exp = (
                        f"The domain '{reg}' substitutes lookalike characters (such as '0' for 'o', '1' for 'l', or 'rn' for 'm') "
                        f"to mimic {brand.upper()} (official domain: {official_list[0]})."
                    )
                    warnings.append({
                        "code": "CHARACTER_SUBSTITUTION_SPOOF",
                        "severity": "high",
                        "title": f"Character Substitution Imitating {brand.upper()}",
                        "explanation": exp,
                        "plain_explanation": exp,
                    })
                    matched_sub = True
                    break
            if not matched_sub and sld != brand and levenshtein(sld, brand) == 1:
                exp = (
                    f"The domain '{reg}' is only one letter different from '{brand}' "
                    f"(official domain: {official_list[0]}). This is a common typosquatting trap."
                )
                warnings.append({
                    "code": "TYPOSQUAT_LOOKALIKE",
                    "severity": "high",
                    "title": f"Lookalike Spelling Targeting {brand.upper()}",
                    "explanation": exp,
                    "plain_explanation": exp,
                })

    return warnings


def inspect_url_advanced(url: str, resolve_redirects: bool = True) -> Dict[str, Any]:
    """
    Perform complete static URL analysis + optional SSRF-guarded redirect chain inspection.
    """
    raw_url = (url or "").strip()
    if not raw_url or len(raw_url) > MAX_URL_LEN:
        raise ValueError("Please provide a valid URL up to 2,048 characters.")

    parsed = urlsplit(raw_url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return {
            "original_url": raw_url,
            "normalized_url": raw_url,
            "final_resolved_url": None,
            "final_url": None,
            "destination_verified": False,
            "redirected": False,
            "redirect_count": 0,
            "resolution_status": "blocked_scheme",
            "resolution_note": f"Blocked disallowed URL scheme '{scheme or 'missing'}:' (only http:// and https:// are permitted).",
            "resolution_message": f"Blocked disallowed URL scheme '{scheme or 'missing'}:'.",
            "ssrf_blocked": True,
            "is_shortened": False,
            "is_shortener": False,
            "redirect_hops": [],
            "hops": [],
            "advanced_warnings": [
                {
                    "code": "DISALLOWED_URL_SCHEME",
                    "severity": "high",
                    "title": f"Blocked Non-Web URL Scheme ({scheme or 'unknown'})",
                    "explanation": "Only standard http:// and https:// web links can be inspected safely.",
                    "plain_explanation": "Only standard http:// and https:// web links can be inspected safely.",
                }
            ],
            "warnings": [],
            "safety_disclaimer": (
                "Important: Even if no suspicious warning is detected or if the destination could not be verified, "
                "that does NOT guarantee a website is safe."
            ),
        }
    if not parsed.hostname:
        raise ValueError("URL is missing a valid hostname.")

    # 1. Run static intelligence on the submitted URL
    initial_intel = analyze_url_static(raw_url)
    if not initial_intel.get("valid", True):
        raise ValueError(initial_intel.get("error", "Malformed URL"))

    is_shortener = bool(initial_intel.get("metrics", {}).get("is_shortener", False))
    hops: List[Dict[str, Any]] = []
    current_url = raw_url
    resolution_status = "not_requested"
    resolution_message = "Static analysis completed without network contact."
    ssrf_blocked = False

    if resolve_redirects:
        resolution_status = "verified"
        for hop_index in range(MAX_REDIRECTS + 1):
            hop_parts = urlsplit(current_url)
            hop_scheme = (hop_parts.scheme or "").lower()
            hop_host = (hop_parts.hostname or "").lower()
            try:
                hop_port = hop_parts.port or (443 if hop_scheme == "https" else 80)
            except ValueError:
                resolution_status = "unverified"
                resolution_message = "Redirect target contained an invalid port."
                break

            if hop_scheme not in ("http", "https"):
                resolution_status = "blocked"
                resolution_message = f"Blocked redirect to non-HTTP(S) scheme '{hop_scheme}:'."
                ssrf_blocked = True
                break

            is_safe, pinned_ip, err_reason = validate_and_resolve_host(hop_host, hop_port)
            if not is_safe or not pinned_ip:
                if err_reason and "SSRF protection" in err_reason:
                    resolution_status = "blocked"
                    ssrf_blocked = True
                else:
                    resolution_status = "unverified"
                resolution_message = err_reason or "Destination could not be safely resolved."
                hops.append({
                    "hop": hop_index + 1,
                    "url": current_url,
                    "host": hop_host,
                    "status_code": None,
                    "note": resolution_message,
                })
                break

            path_query = hop_parts.path or "/"
            if hop_parts.query:
                path_query = f"{path_query}?{hop_parts.query}"

            status_code, location, req_err = _perform_single_hop_request(
                hop_scheme, hop_host, pinned_ip, hop_port, path_query
            )
            if req_err is not None or status_code is None:
                resolution_status = "unverified"
                resolution_message = req_err or "Destination server did not respond within the safety timeout."
                hops.append({
                    "hop": hop_index + 1,
                    "url": current_url,
                    "host": hop_host,
                    "status_code": None,
                    "note": resolution_message,
                })
                break

            hops.append({
                "hop": hop_index + 1,
                "url": current_url,
                "host": hop_host,
                "status_code": status_code,
                "RedirectLocation": location,
            })

            if status_code in (301, 302, 303, 307, 308) and location:
                if hop_index + 1 >= MAX_REDIRECTS:
                    resolution_status = "unverified"
                    resolution_message = f"Stopped after reaching the maximum safe redirect limit ({MAX_REDIRECTS} hops)."
                    break
                next_url = urljoin(current_url, location.strip())
                current_url = next_url
                continue
            else:
                resolution_status = "verified"
                resolution_message = (
                    f"Safely traced {len(hops)} hop(s) to final destination."
                    if len(hops) > 1
                    else "Link points directly to its destination without HTTP redirects."
                )
                break

    final_url = current_url if hops else raw_url
    redirect_count = max(0, len([h for h in hops if h.get("status_code") in (301, 302, 303, 307, 308)]))
    final_intel = analyze_url_static(final_url) if final_url != raw_url else initial_intel
    active_intel = final_intel if final_intel.get("valid") else initial_intel
    verdict = calculate_url_risk_verdict(active_intel)

    # Combine lookalike / homograph / redirect warnings in simple language
    simple_warnings: List[Dict[str, str]] = []
    if is_shortener:
        exp = (
            f"The original link uses a URL shortener ('{initial_intel.get('components', {}).get('registrable_domain', '')}'), "
            "which conceals the real website until someone clicks it."
        )
        simple_warnings.append({
            "code": "URL_SHORTENER_DETECTED",
            "severity": "medium",
            "title": "Shortened URL Hides True Destination",
            "explanation": exp,
            "plain_explanation": exp,
        })

    if redirect_count > 0:
        initial_reg = initial_intel.get("components", {}).get("registrable_domain", "")
        final_reg = active_intel.get("components", {}).get("registrable_domain", "")
        cross_domain = initial_reg and final_reg and initial_reg != final_reg
        exp = (
            f"This link forwards visitors from '{initial_reg or raw_url}' to '{final_reg or final_url}'. "
            "Always inspect the final destination domain before entering any information."
        )
        simple_warnings.append({
            "code": "REDIRECT_CHAIN_DETECTED",
            "severity": "high" if redirect_count >= 2 or cross_domain else "medium",
            "title": f"Redirected Across {redirect_count} Hop(s)",
            "explanation": exp,
            "plain_explanation": exp,
        })

    for w in detect_lookalike_and_homograph_warnings(raw_url):
        simple_warnings.append(w)
    if final_url != raw_url:
        existing_codes = {(w["code"], w["title"]) for w in simple_warnings}
        for w in detect_lookalike_and_homograph_warnings(final_url):
            if (w["code"], w["title"]) not in existing_codes:
                simple_warnings.append(w)

    # Also include plain-language findings from static URL intelligence
    existing_titles = {w["title"] for w in simple_warnings}
    for f in active_intel.get("findings", []):
        if f.get("title") not in existing_titles:
            detail_str = str(f.get("detail", ""))
            simple_warnings.append({
                "code": str(f.get("code", "finding")),
                "severity": str(f.get("severity", "medium")),
                "title": str(f.get("title", "Suspicious URL Pattern")),
                "explanation": detail_str,
                "plain_explanation": detail_str,
            })

    effective_status = "blocked_ssrf" if ssrf_blocked else resolution_status
    is_verified = effective_status == "verified"

    return {
        "original_url": raw_url,
        "normalized_url": str(initial_intel.get("normalized_url", raw_url)),
        "final_resolved_url": final_url if is_verified else None,
        "final_url": final_url if is_verified else None,
        "destination_verified": is_verified,
        "redirected": final_url != raw_url and is_verified,
        "redirect_count": redirect_count,
        "resolution_status": effective_status,
        "resolution_note": resolution_message,
        "resolution_message": resolution_message,
        "ssrf_blocked": ssrf_blocked,
        "is_shortened": is_shortener,
        "is_shortener": is_shortener,
        "redirect_hops": hops,
        "hops": hops,
        "advanced_warnings": simple_warnings,
        "warnings": simple_warnings,
        "prediction": verdict["prediction"],
        "risk_level": verdict["risk_level"],
        "risk_score": verdict["risk_score"],
        "risk_probability": verdict["risk_probability"],
        "url_intelligence": active_intel,
        "safety_disclaimer": (
            "Important: Even if no suspicious warning is detected or if the destination could not be verified, "
            "that does NOT guarantee a website is safe. Never enter passwords, OTPs, or banking details on unfamiliar links."
        ),
    }
