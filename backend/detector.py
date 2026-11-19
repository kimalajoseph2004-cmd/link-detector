import os
import re
import ssl
import socket
import base64
import difflib
import whois
import dns.resolver
import requests
import tldextract
from datetime import datetime, timezone
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()
SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")

SUSPICIOUS_TLDS = {"xyz", "top", "club", "work", "click", "link", "gq", "tk", "ml", "cf"}
BRAND_KEYWORDS = {"paypal", "amazon", "apple", "google", "microsoft", "netflix", "bank", "instagram", "whatsapp"}


def check_typosquatting(extracted) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    full_host = f"{extracted.subdomain}.{extracted.domain}".lower().strip(".")
    main_domain = extracted.domain.lower()

    if "xn--" in full_host:
        score += 45
        reasons.append("Punycode/homograph domain detected (possible lookalike characters).")

    tokens = [t for t in re.split(r"[-.]", full_host) if t]
    for brand in BRAND_KEYWORDS:
        if brand in full_host and main_domain != brand:
            score += 45
            reasons.append(f"Possible brand impersonation of '{brand}'.")
            break
        for token in tokens:
            if token != brand and difflib.SequenceMatcher(None, token, brand).ratio() >= 0.80:
                score += 40
                reasons.append(f"Typosquatting detected: '{token}' closely mimics '{brand}'.")
                return score, reasons
    return score, reasons


def check_dns(domain: str) -> tuple[int, list[str]]:
    if not domain:
        return 0, []
    try:
        socket.gethostbyname(domain)
        return 0, []
    except Exception:
        return 20, ["No valid DNS 'A' record found for this domain."]


def check_ssl(hostname: str) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                if (not_after - datetime.now(timezone.utc)).days < 0:
                    score += 35
                    reasons.append("SSL certificate has expired.")
    except ssl.SSLCertVerificationError:
        score += 40
        reasons.append("Invalid or untrusted SSL certificate.")
    except Exception:
        score += 20
        reasons.append("Could not verify HTTPS/SSL connection.")
    return score, reasons


def trace_and_inspect(url: str) -> tuple[int, int, list[str], str]:
    infra_score = 0
    content_score = 0
    reasons = []
    final_url = url
    try:
        resp = requests.get(
            url,
            timeout=5,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (SecurityAuditor)"},
        )
        final_url = resp.url
        if len(resp.history) >= 3:
            infra_score += 20
            reasons.append(f"Excessive redirects detected ({len(resp.history)} hops).")

        orig_dom = tldextract.extract(url).registered_domain
        final_dom = tldextract.extract(final_url).registered_domain
        if orig_dom and final_dom and orig_dom != final_dom:
            infra_score += 25
            reasons.append(f"Redirects to a different domain ({final_dom}).")

        html = resp.text.lower()
        if 'type="password"' in html or "type='password'" in html:
            content_score += 25
            reasons.append("Page contains a password input field (credential-harvesting risk).")
    except Exception:
        infra_score += 10
        reasons.append("Target server unreachable or timed out.")
    return infra_score, content_score, reasons, final_url


def check_threat_feeds(url: str) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    if SAFE_BROWSING_KEY:
        endpoint = f"https://googleapis.com{SAFE_BROWSING_KEY}"
        payload = {
            "client": {"clientId": "link-detector", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        try:
            if requests.post(endpoint, json=payload, timeout=5).json().get("matches"):
                score += 85
                reasons.append("Flagged as dangerous by Google Safe Browsing.")
        except Exception:
            pass

    if VIRUSTOTAL_KEY:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://virustotal.com{url_id}"
        try:
            resp = requests.get(endpoint, headers={"x-apikey": VIRUSTOTAL_KEY}, timeout=5)
            if resp.status_code == 200:
                stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
                malicious = stats.get("malicious", 0)
                if malicious > 0:
                    score += min(malicious * 25, 85)
                    reasons.append(f"Flagged by {malicious} VirusTotal security vendors.")
        except Exception:
            pass
    return score, reasons


def analyze_url(raw_url: str) -> dict:
    raw_url = raw_url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url

    parsed = urlparse(raw_url)
    hostname = parsed.hostname or ""
    extracted = tldextract.extract(raw_url)
    domain = extracted.registered_domain.lower()

    url_score = 0
    infra_score = 0
    reasons = []

    if parsed.scheme != "https":
        url_score += 15
        reasons.append("Does not use HTTPS encryption.")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        url_score += 45
        reasons.append("Uses a raw IP address instead of a domain name.")
    if "@" in raw_url:
        url_score += 35
        reasons.append("Contains '@' symbol used to disguise destinations.")
    if extracted.subdomain and len(extracted.subdomain.split(".")) >= 3:
        url_score += 20
        reasons.append("Excessive number of subdomains.")
    if extracted.suffix.lower() in SUSPICIOUS_TLDS:
        url_score += 15
        reasons.append(f"Uses a high-risk TLD (.{extracted.suffix}).")

    t_score, t_reasons = check_typosquatting(extracted)
    url_score += t_score
    reasons.extend(t_reasons)

    if domain:
        try:
            w = whois.whois(domain)
            creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if creation:
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - creation).days
                if age_days < 30:
                    infra_score += 35
                    reasons.append(f"Domain registered very recently ({age_days} days ago).")
        except Exception:
            infra_score += 10
            reasons.append("WHOIS registration details hidden or unavailable.")

    d_score, d_reasons = check_dns(domain)
    infra_score += d_score
    reasons.extend(d_reasons)

    if hostname:
        s_score, s_reasons = check_ssl(hostname)
        infra_score += s_score
        reasons.extend(s_reasons)

    r_score, content_score, r_reasons, final_url = trace_and_inspect(raw_url)
    infra_score += r_score
    reasons.extend(r_reasons)

    threat_score, threat_reasons = check_threat_feeds(final_url)
    reasons.extend(threat_reasons)

    url_score = min(url_score, 100)
    infra_score = min(infra_score, 100)
    content_score = min(content_score, 100)
    threat_score = min(threat_score, 100)

    total_score = min(url_score + infra_score + content_score + threat_score, 100)
    verdict = "Safe" if total_score < 25 else "Suspicious" if total_score < 60 else "High Risk"

    return {
        "input_url": raw_url,
        "final_url": final_url,
        "domain": domain or hostname,
        "risk_score": total_score,
        "verdict": verdict,
        "breakdown": {
            "url_structure": url_score,
            "infrastructure": infra_score,
            "content": content_score,
            "threat_intel": threat_score,
        },
        "reasons": reasons or ["Passed all heuristic, DNS, SSL, and threat-feed checks."],
    }
