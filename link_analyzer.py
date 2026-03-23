import os
import re
import ssl
import json
import socket
import shutil
import threading
import subprocess
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime, timezone
from html import unescape
from urllib.parse import urlparse

import requests


UA = "Mozilla/5.0"
SECTION_LINE = "═" * 78
SUB_LINE = "─" * 78


def load_api_keys():
    keys = {
        "abuseipdb": "",
    }
    if not os.path.exists("apis.txt"):
        return keys
    try:
        with open("apis.txt", "r", encoding="utf-8") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    keys[k.strip().lower()] = v.strip()
    except Exception:
        pass
    return keys


API_KEYS = load_api_keys()
ABUSEIPDB_API_KEY = API_KEYS.get("abuseipdb", "")


def get_windows_codepages():
    oem = None
    acp = None
    if os.name == "nt":
        try:
            import ctypes
            k32 = ctypes.windll.kernel32
            oem = f"cp{k32.GetOEMCP()}"
            acp = f"cp{k32.GetACP()}"
        except Exception:
            pass
    return oem, acp


def score_decoded_text(text):
    if not text:
        return -10

    weird_chars = "ЂЃ‚ѓ„…†‡€‰Љ‹ЊЌЋЏђ‘’“”•–—�"
    russian_letters = len(re.findall(r"[А-Яа-яЁё]", text))
    latin_letters = len(re.findall(r"[A-Za-z]", text))
    digits = len(re.findall(r"\d", text))
    weird = sum(text.count(ch) for ch in weird_chars)
    replacement = text.count("�")

    common_words = [
        "обмен",
        "пакет",
        "приблизительно",
        "превышен",
        "интервал",
        "адрес",
        "сервер",
        "маршрут",
        "ответ",
        "узел",
        "request",
        "reply",
        "packets",
        "approximate",
        "statistics",
        "tracing",
        "route",
    ]
    common_hits = 0
    low = text.lower()
    for w in common_words:
        if w in low:
            common_hits += 1

    return russian_letters + latin_letters * 0.2 + digits * 0.1 + common_hits * 20 - weird * 8 - replacement * 15


def decode_console_bytes(data):
    if not data:
        return ""

    oem, acp = get_windows_codepages()

    candidates = []
    encodings = []

    if os.name == "nt":
        if oem:
            encodings.append(oem)
        if acp and acp not in encodings:
            encodings.append(acp)

    for enc in ("cp866", "cp1251", "utf-8", "utf-8-sig"):
        if enc not in encodings:
            encodings.append(enc)

    for enc in encodings:
        try:
            text = data.decode(enc)
            candidates.append((score_decoded_text(text), text))
        except Exception:
            pass

    if candidates:
        candidates.sort(key=lambda x: x[0], reverse=True)
        return candidates[0][1]

    return data.decode("utf-8", errors="replace")


def clean_console_text(text):
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = "\n".join(line.rstrip() for line in text.splitlines())
    return text.strip()


def run_command(cmd, timeout=20):
    result = {
        "command": " ".join(cmd),
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "error": None,
    }

    try:
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
                startupinfo=startupinfo,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                timeout=timeout,
            )

        result["returncode"] = proc.returncode
        result["stdout"] = clean_console_text(decode_console_bytes(proc.stdout))
        result["stderr"] = clean_console_text(decode_console_bytes(proc.stderr))

    except FileNotFoundError:
        result["error"] = f"Команда не найдена: {cmd[0]}"
    except Exception as e:
        result["error"] = str(e)

    return result


def normalize_text(s):
    return " ".join((s or "").split()).strip()


def defang_url(url):
    return (
        (url or "")
        .replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
    )


def parse_url_info(url):
    p = urlparse(url)
    return {
        "input_url": url,
        "defanged_url": defang_url(url),
        "scheme": p.scheme or None,
        "domain": (p.hostname or "").lower() or None,
        "path": p.path or "/",
        "query": p.query or None,
        "fragment": p.fragment or None,
        "port": p.port,
        "netloc": p.netloc or None,
    }


def parse_dt(value):
    if not value:
        return None
    raw = value.strip()
    fmts = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d",
        "%b %d %H:%M:%S %Y GMT",
        "%a %b %d %H:%M:%S %Y",
        "%d.%m.%Y",
    ]
    for fmt in fmts:
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            pass
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def format_dt(value):
    dt = parse_dt(value)
    if dt:
        return dt.astimezone(timezone.utc).strftime("%d.%m.%Y %H:%M:%S UTC")
    return value


def domain_age_days(created_value):
    dt = parse_dt(created_value)
    if not dt:
        return None
    return (datetime.now(timezone.utc) - dt.astimezone(timezone.utc)).days


def extract_title(text):
    m = re.search(r"<title[^>]*>(.*?)</title>", text or "", re.I | re.S)
    if not m:
        return None
    return normalize_text(unescape(m.group(1)))


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def get_whois_domain(domain):
    if not domain:
        return None
    d = domain.strip(".").lower()
    if d.startswith("www."):
        return d[4:]
    return d


def dns_lookup_socket(domain):
    result = {"a_from_socket": [], "error": None}
    try:
        infos = socket.getaddrinfo(domain, None)
        addrs = []
        for item in infos:
            sockaddr = item[4]
            if sockaddr and sockaddr[0] not in addrs:
                addrs.append(sockaddr[0])
        result["a_from_socket"] = addrs
    except Exception as e:
        result["error"] = str(e)
    return result


def parse_nslookup_default(text):
    server_name = None
    server_ip = None
    resolved = []
    lines = (text or "").splitlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()
        low = line.lower()
        if (low.startswith("server:") or "сервер" in low) and i + 1 < len(lines):
            if ":" in line:
                server_name = line.split(":", 1)[1].strip() or None
            nxt = lines[i + 1].strip()
            if nxt.lower().startswith("address:") or "address" in nxt.lower() or "адрес" in nxt.lower():
                server_ip = nxt.split(":", 1)[1].strip() if ":" in nxt else None
        i += 1

    for m in re.finditer(r"Address:\s*([0-9a-fA-F\.:]+)", text or "", re.I):
        ip = m.group(1).strip()
        if ip and ip != server_ip and ip not in resolved:
            resolved.append(ip)

    for m in re.finditer(r"Адрес:\s*([0-9a-fA-F\.:]+)", text or "", re.I):
        ip = m.group(1).strip()
        if ip and ip != server_ip and ip not in resolved:
            resolved.append(ip)

    return {
        "dns_server_name": server_name,
        "dns_server_ip": server_ip,
        "resolved_ips": resolved,
    }


def parse_nslookup_mx(text):
    records = []
    pattern = re.compile(r"MX preference =\s*(\d+),\s*mail exchanger =\s*(\S+)", re.I)
    for pref, host in pattern.findall(text or ""):
        ip_match = re.search(rf"{re.escape(host)}\s+internet address =\s*([0-9\.]+)", text or "", re.I)
        records.append(
            {
                "preference": pref,
                "host": host.rstrip("."),
                "ip": ip_match.group(1) if ip_match else None,
            }
        )
    return records


def parse_nslookup_ns(text):
    hosts = re.findall(r"nameserver =\s*(\S+)", text or "", re.I)
    records = []
    seen = set()
    for host in hosts:
        h = host.rstrip(".")
        if h in seen:
            continue
        seen.add(h)
        ip_match = re.search(rf"{re.escape(host)}\s+internet address =\s*([0-9\.]+)", text or "", re.I)
        records.append({"host": h, "ip": ip_match.group(1) if ip_match else None})
    return records


def parse_nslookup_txt(text):
    values = []
    lines = (text or "").splitlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if "text =" in line.lower():
            val = line.split("=", 1)[1].strip().strip('"')
            values.append(val)
    if not values:
        quoted = re.findall(r'"([^"]+)"', text or "")
        values.extend(quoted)
    uniq = []
    for v in values:
        if v not in uniq:
            uniq.append(v)
    return uniq


def parse_spf(txt_records):
    spf = next((x for x in txt_records if x.lower().startswith("v=spf1")), None)
    if not spf:
        return None
    tokens = spf.split()
    return {
        "raw": spf,
        "ip4": [t[4:] for t in tokens if t.startswith("ip4:")],
        "ip6": [t[4:] for t in tokens if t.startswith("ip6:")],
        "include": [t[8:] for t in tokens if t.startswith("include:")],
        "policy": next((t for t in tokens if t.endswith("all")), None),
    }


def http_fetch(url):
    result = {
        "head": {},
        "get": {},
        "redirects": [],
        "page_title": None,
        "body_preview": None,
        "cookies": [],
        "error": None,
    }
    try:
        try:
            head = requests.head(
                url,
                timeout=15,
                allow_redirects=False,
                headers={"User-Agent": UA},
            )
            result["head"] = {
                "status_code": head.status_code,
                "reason": getattr(head, "reason", None),
                "url": head.url,
                "headers": dict(head.headers),
            }
        except Exception as e:
            result["head"] = {"error": str(e)}

        resp = requests.get(
            url,
            timeout=20,
            allow_redirects=True,
            headers={"User-Agent": UA},
        )

        redirects = []
        for r in resp.history:
            redirects.append(
                {
                    "status_code": r.status_code,
                    "reason": getattr(r, "reason", None),
                    "url": r.url,
                    "location": r.headers.get("Location"),
                    "server": r.headers.get("Server"),
                }
            )

        security_headers = {
            "Strict-Transport-Security": resp.headers.get("Strict-Transport-Security"),
            "Content-Security-Policy": resp.headers.get("Content-Security-Policy"),
            "X-Frame-Options": resp.headers.get("X-Frame-Options"),
            "X-Content-Type-Options": resp.headers.get("X-Content-Type-Options"),
            "Referrer-Policy": resp.headers.get("Referrer-Policy"),
        }

        cookies = []
        for c in resp.cookies:
            cookies.append(
                {
                    "name": c.name,
                    "domain": c.domain,
                    "path": c.path,
                    "secure": c.secure,
                    "expires": c.expires,
                }
            )

        text = resp.text if "text" in (resp.headers.get("Content-Type") or "").lower() else ""
        result["get"] = {
            "status_code": resp.status_code,
            "reason": getattr(resp, "reason", None),
            "final_url": resp.url,
            "server": resp.headers.get("Server"),
            "content_type": resp.headers.get("Content-Type"),
            "content_length": resp.headers.get("Content-Length"),
            "headers": dict(resp.headers),
            "security_headers": security_headers,
        }
        result["redirects"] = redirects
        result["page_title"] = extract_title(text)
        result["body_preview"] = normalize_text(unescape(text[:1200])) if text else None
        result["cookies"] = cookies
    except Exception as e:
        result["error"] = str(e)
    return result


def tls_probe(domain):
    result = {
        "ok": False,
        "error": None,
        "protocol": None,
        "cipher": None,
        "subject_cn": None,
        "issuer_cn": None,
        "not_before": None,
        "not_after": None,
        "san": [],
        "openssl": {},
    }
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as s:
                cert = s.getpeercert()
                san = []
                for item in cert.get("subjectAltName", []):
                    if len(item) == 2 and item[0] == "DNS":
                        san.append(item[1])
                subject_cn = dict(x[0] for x in cert.get("subject", [])).get("commonName")
                issuer_cn = dict(x[0] for x in cert.get("issuer", [])).get("commonName")
                result.update(
                    {
                        "ok": True,
                        "protocol": s.version(),
                        "cipher": s.cipher()[0] if s.cipher() else None,
                        "subject_cn": subject_cn,
                        "issuer_cn": issuer_cn,
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "san": san,
                    }
                )
    except Exception as e:
        result["error"] = str(e)

    if shutil.which("openssl"):
        openssl_res = run_command(
            ["openssl", "s_client", "-connect", f"{domain}:443", "-servername", domain],
            timeout=25,
        )
        openssl_text = (openssl_res.get("stdout") or "") + "\n" + (openssl_res.get("stderr") or "")
        verify_match = re.search(r"Verify return code:\s*(\d+)\s*\(([^)]+)\)", openssl_text, re.I)
        subject_match = re.search(r"subject=.*?CN\s*=\s*([^\n/]+)", openssl_text, re.I)
        issuer_match = re.search(r"issuer=.*?CN\s*=\s*([^\n/]+)", openssl_text, re.I)
        protocol_match = re.search(r"Protocol\s*:\s*(TLS[^\s]+)", openssl_text, re.I)
        cipher_match = re.search(r"Cipher\s*:\s*([A-Z0-9_\-]+)", openssl_text, re.I)

        result["openssl"] = {
            "available": True,
            "returncode": openssl_res.get("returncode"),
            "verify_code": verify_match.group(1) if verify_match else None,
            "verify_text": verify_match.group(2) if verify_match else None,
            "subject_cn": subject_match.group(1).strip() if subject_match else None,
            "issuer_cn": issuer_match.group(1).strip() if issuer_match else None,
            "protocol": protocol_match.group(1) if protocol_match else None,
            "cipher": cipher_match.group(1) if cipher_match else None,
            "raw_excerpt": "\n".join((openssl_text or "").splitlines()[:80]),
        }
    else:
        result["openssl"] = {
            "available": False,
            "error": "openssl не найден в системе",
        }

    return result


def whois_probe(domain):
    result = {
        "available": True,
        "error": None,
        "registrar": None,
        "created": None,
        "updated": None,
        "expires": None,
        "status": [],
        "name_servers": [],
        "raw_excerpt": None,
    }

    if not shutil.which("whois"):
        result["available"] = False
        result["error"] = "whois не найден в системе"
        return result

    raw = run_command(["whois", domain], timeout=30)
    text = raw.get("stdout") or raw.get("stderr") or ""
    result["raw_excerpt"] = "\n".join(text.splitlines()[:120]) if text else None

    def pick(patterns):
        for p in patterns:
            m = re.search(p, text, re.I | re.M)
            if m:
                return m.group(1).strip().strip('"')
        return None

    result["registrar"] = pick(
        [
            r"^\s*Registrar:\s*(.+)$",
            r"^\s*registrar:\s*(.+)$",
        ]
    )
    result["created"] = pick(
        [
            r"^\s*Creation Date:\s*(.+)$",
            r"^\s*created:\s*(.+)$",
            r"^\s*Registered on:\s*(.+)$",
            r"^\s*Registration Time:\s*(.+)$",
            r"^\s*Domain Create Date:\s*(.+)$",
        ]
    )
    result["updated"] = pick(
        [
            r"^\s*Updated Date:\s*(.+)$",
            r"^\s*updated:\s*(.+)$",
            r"^\s*Last updated on:\s*(.+)$",
            r"^\s*changed:\s*(.+)$",
        ]
    )
    result["expires"] = pick(
        [
            r"^\s*Registry Expiry Date:\s*(.+)$",
            r"^\s*Expiry Date:\s*(.+)$",
            r"^\s*Expires on:\s*(.+)$",
            r"^\s*paid-till:\s*(.+)$",
            r"^\s*Registrar Registration Expiration Date:\s*(.+)$",
        ]
    )
    statuses = re.findall(r"^\s*Domain Status:\s*(.+)$", text, re.I | re.M)
    ns = re.findall(r"^\s*Name Server:\s*(.+)$", text, re.I | re.M)
    result["status"] = [normalize_text(x) for x in statuses]
    result["name_servers"] = [normalize_text(x).rstrip(".") for x in ns]
    return result


def ipinfo_lookup(ip):
    if not ip:
        return {"ok": False, "error": "IP не определён"}
    try:
        r = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=12,
            headers={"User-Agent": UA},
        )
        data = r.json()
        return {
            "ok": True,
            "ip": data.get("ip"),
            "hostname": data.get("hostname"),
            "city": data.get("city"),
            "region": data.get("region"),
            "country": data.get("country"),
            "org": data.get("org"),
            "loc": data.get("loc"),
            "postal": data.get("postal"),
            "timezone": data.get("timezone"),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def abuseipdb_check(ip):
    if not ip:
        return {"ok": False, "error": "IP не определён"}
    if not ABUSEIPDB_API_KEY:
        return {"ok": False, "error": "Ключ AbuseIPDB отсутствует в apis.txt"}
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": ABUSEIPDB_API_KEY,
                "Accept": "application/json",
                "User-Agent": UA,
            },
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=15,
        )
        if r.status_code != 200:
            return {
                "ok": False,
                "error": f"HTTP {r.status_code}",
                "body": r.text[:1000],
            }
        data = r.json().get("data", {})
        return {
            "ok": True,
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
            "last_reported_at": data.get("lastReportedAt"),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def urlsafe(domain):
    return f"http://{domain}" if not domain.startswith(("http://", "https://")) else domain


def run_extra_commands(domain, ip):
    results = {}

    results["nslookup_domain"] = run_command(["nslookup", domain], timeout=15)
    results["nslookup_mx"] = run_command(["nslookup", "-type=mx", domain], timeout=15)
    results["nslookup_ns"] = run_command(["nslookup", "-type=ns", domain], timeout=15)
    results["nslookup_txt"] = run_command(["nslookup", "-type=txt", domain], timeout=15)

    if ip:
        results["nslookup_ip"] = run_command(["nslookup", ip], timeout=15)

    if os.name == "nt":
        results["ping"] = run_command(["ping", "-n", "2", domain], timeout=20)
        results["traceroute"] = run_command(["tracert", "-d", domain], timeout=40)
    else:
        results["ping"] = run_command(["ping", "-c", "2", domain], timeout=20)
        results["traceroute"] = run_command(["traceroute", "-n", domain], timeout=40)

    if shutil.which("curl"):
        results["curl_head"] = run_command(["curl", "-I", urlsafe(domain)], timeout=25)
        results["curl_head_follow"] = run_command(["curl", "-L", "-I", urlsafe(domain)], timeout=25)
    else:
        results["curl_head"] = {
            "command": "curl -I",
            "error": "curl не найден в системе",
            "stdout": "",
            "stderr": "",
            "returncode": None,
        }
        results["curl_head_follow"] = {
            "command": "curl -L -I",
            "error": "curl не найден в системе",
            "stdout": "",
            "stderr": "",
            "returncode": None,
        }

    if shutil.which("openssl"):
        results["openssl_s_client"] = run_command(
            ["openssl", "s_client", "-connect", f"{domain}:443", "-servername", domain],
            timeout=25,
        )
    else:
        results["openssl_s_client"] = {
            "command": "openssl s_client",
            "error": "openssl не найден в системе",
            "stdout": "",
            "stderr": "",
            "returncode": None,
        }

    return results


def analyze_target_url(url):
    if not url.startswith(("http://", "https://")):
        raise ValueError("Введите URL, начинающийся с http:// или https://")

    url_info = parse_url_info(url)
    domain = url_info["domain"]
    if not domain:
        raise ValueError("Не удалось определить домен из URL")

    dns_socket = dns_lookup_socket(domain)

    nslookup_default = run_command(["nslookup", domain], timeout=15)
    nslookup_mx = run_command(["nslookup", "-type=mx", domain], timeout=15)
    nslookup_ns = run_command(["nslookup", "-type=ns", domain], timeout=15)
    nslookup_txt = run_command(["nslookup", "-type=txt", domain], timeout=15)

    dns_default_parsed = parse_nslookup_default(nslookup_default.get("stdout", ""))
    resolved_ips = dns_default_parsed["resolved_ips"] or dns_socket.get("a_from_socket") or []
    primary_ip = resolved_ips[0] if resolved_ips else None
    ptr = reverse_dns(primary_ip) if primary_ip else None

    dns = {
        "dns_server_name": dns_default_parsed.get("dns_server_name"),
        "dns_server_ip": dns_default_parsed.get("dns_server_ip"),
        "resolved_ips": resolved_ips,
        "mx_records": parse_nslookup_mx(nslookup_mx.get("stdout", "")),
        "ns_records": parse_nslookup_ns(nslookup_ns.get("stdout", "")),
        "txt_records": parse_nslookup_txt(nslookup_txt.get("stdout", "")),
        "spf": None,
        "ptr": ptr,
        "raw": {
            "nslookup_default": nslookup_default,
            "nslookup_mx": nslookup_mx,
            "nslookup_ns": nslookup_ns,
            "nslookup_txt": nslookup_txt,
        },
    }
    dns["spf"] = parse_spf(dns["txt_records"])

    http = http_fetch(url)
    tls = tls_probe(domain)
    whois = whois_probe(get_whois_domain(domain))
    geo = ipinfo_lookup(primary_ip)
    abuse = abuseipdb_check(primary_ip)
    extra = run_extra_commands(domain, primary_ip)

    summary = {
        "input_url": url_info["input_url"],
        "defanged_url": url_info["defanged_url"],
        "domain": domain,
        "scheme": url_info["scheme"],
        "ip": primary_ip,
        "ptr": ptr,
        "final_url": http.get("get", {}).get("final_url"),
        "http_status": http.get("get", {}).get("status_code"),
        "page_title": http.get("page_title"),
        "server": http.get("get", {}).get("server"),
        "content_type": http.get("get", {}).get("content_type"),
        "tls_protocol": tls.get("protocol"),
        "tls_cipher": tls.get("cipher"),
        "tls_subject_cn": tls.get("subject_cn"),
        "tls_issuer_cn": tls.get("issuer_cn"),
        "tls_not_after": format_dt(tls.get("not_after")),
        "registrar": whois.get("registrar"),
        "created": format_dt(whois.get("created")),
        "updated": format_dt(whois.get("updated")),
        "expires": format_dt(whois.get("expires")),
        "domain_age_days": domain_age_days(whois.get("created")),
        "geo_org": geo.get("org") if geo.get("ok") else None,
        "geo_country": geo.get("country") if geo.get("ok") else None,
        "abuse_score": abuse.get("abuse_confidence_score") if abuse.get("ok") else None,
        "abuse_reports": abuse.get("total_reports") if abuse.get("ok") else None,
    }

    return {
        "summary": summary,
        "url_info": url_info,
        "dns": dns,
        "http": http,
        "tls": tls,
        "whois": whois,
        "geo": geo,
        "abuse": abuse,
        "extra": extra,
    }


def parse_ping_summary(text):
    result = {
        "host": None,
        "ip": None,
        "sent": None,
        "received": None,
        "lost": None,
        "loss_percent": None,
        "min_ms": None,
        "max_ms": None,
        "avg_ms": None,
        "raw_excerpt": None,
    }
    if not text:
        return result

    result["raw_excerpt"] = "\n".join(text.splitlines()[:20])

    m = re.search(r"Ping\s+(.+?)\s+\[([0-9\.]+)\]", text, re.I)
    if not m:
        m = re.search(r"Pinging\s+(.+?)\s+\[([0-9\.]+)\]", text, re.I)
    if m:
        result["host"] = m.group(1).strip()
        result["ip"] = m.group(2).strip()

    m = re.search(
        r"Sent\s*=\s*(\d+).+?Received\s*=\s*(\d+).+?Lost\s*=\s*(\d+)\s*\((\d+)%\s*loss\)",
        text,
        re.I | re.S,
    )
    if not m:
        m = re.search(
            r"Отправлено\s*=\s*(\d+).+?Получено\s*=\s*(\d+).+?Потеряно\s*=\s*(\d+)\s*\((\d+)%\s*потерь\)",
            text,
            re.I | re.S,
        )
    if m:
        result["sent"] = m.group(1)
        result["received"] = m.group(2)
        result["lost"] = m.group(3)
        result["loss_percent"] = m.group(4)

    m = re.search(
        r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms",
        text,
        re.I,
    )
    if not m:
        m = re.search(
            r"Минимальное\s*=\s*(\d+)мсек,\s*Максимальное\s*=\s*(\d+)мсек,\s*Среднее\s*=\s*(\d+)мсек",
            text,
            re.I,
        )
    if m:
        result["min_ms"] = m.group(1)
        result["max_ms"] = m.group(2)
        result["avg_ms"] = m.group(3)

    return result


def parse_traceroute_summary(text):
    result = {
        "target": None,
        "ip": None,
        "max_hops": None,
        "hops": [],
        "raw_excerpt": None,
    }
    if not text:
        return result

    result["raw_excerpt"] = "\n".join(text.splitlines()[:60])

    m = re.search(r"Tracing route to\s+(.+?)\s+\[([0-9\.]+)\]", text, re.I)
    if not m:
        m = re.search(r"Трассировка маршрута к\s+(.+?)\s+\[([0-9\.]+)\]", text, re.I)
    if m:
        result["target"] = m.group(1).strip()
        result["ip"] = m.group(2).strip()

    m = re.search(r"over a maximum of\s+(\d+)\s+hops", text, re.I)
    if not m:
        m = re.search(r"с максимальным числом прыжков\s+(\d+)", text, re.I)
    if m:
        result["max_hops"] = m.group(1)

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        hop_match = re.match(r"^(\d+)\s+(.+)$", line)
        if not hop_match:
            continue

        hop_num = hop_match.group(1)
        rest = hop_match.group(2)

        ip_match = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})$", rest)
        ip = ip_match.group(1) if ip_match else None

        times = re.findall(r"(\d+)\s*ms", rest, re.I)
        stars = rest.count("*")

        result["hops"].append(
            {
                "hop": hop_num,
                "ip": ip,
                "times_ms": times,
                "timeouts": stars,
                "raw": line,
            }
        )

    return result


def format_value(value):
    if value is None or value == "":
        return "—"
    if isinstance(value, bool):
        return "Да" if value else "Нет"
    if isinstance(value, list):
        if not value:
            return "—"
        return ", ".join(str(x) for x in value)
    if isinstance(value, dict):
        if not value:
            return "—"
        return json.dumps(value, ensure_ascii=False, indent=2)
    return str(value)


def add_section(lines, title):
    lines.append(SECTION_LINE)
    lines.append(title)
    lines.append(SECTION_LINE)


def add_field(lines, label, value, width=28):
    lines.append(f"{label:<{width}} {format_value(value)}")


def render_summary(data):
    s = data["summary"]
    lines = []
    add_section(lines, "ОБЩАЯ СВОДКА")
    add_field(lines, "Исходный URL", s.get("input_url"))
    add_field(lines, "Defanged URL", s.get("defanged_url"))
    add_field(lines, "Домен", s.get("domain"))
    add_field(lines, "IP-адрес", s.get("ip"))
    add_field(lines, "PTR", s.get("ptr"))
    add_field(lines, "Финальный URL", s.get("final_url"))
    add_field(lines, "HTTP-статус", s.get("http_status"))
    add_field(lines, "Заголовок страницы", s.get("page_title"))
    add_field(lines, "Server", s.get("server"))
    add_field(lines, "Content-Type", s.get("content_type"))
    add_field(lines, "TLS протокол", s.get("tls_protocol"))
    add_field(lines, "TLS cipher", s.get("tls_cipher"))
    add_field(lines, "TLS Subject CN", s.get("tls_subject_cn"))
    add_field(lines, "TLS Issuer CN", s.get("tls_issuer_cn"))
    add_field(lines, "Сертификат до", s.get("tls_not_after"))
    add_field(lines, "Регистратор", s.get("registrar"))
    add_field(lines, "Создан", s.get("created"))
    add_field(lines, "Обновлён", s.get("updated"))
    add_field(lines, "Истекает", s.get("expires"))
    add_field(lines, "Возраст домена, дней", s.get("domain_age_days"))
    add_field(lines, "Организация IP", s.get("geo_org"))
    add_field(lines, "Страна IP", s.get("geo_country"))
    add_field(lines, "AbuseIPDB score", s.get("abuse_score"))
    add_field(lines, "AbuseIPDB reports", s.get("abuse_reports"))
    return "\n".join(lines)


def render_url_info(data):
    u = data["url_info"]
    lines = []
    add_section(lines, "URL INFO")
    add_field(lines, "Исходный URL", u.get("input_url"))
    add_field(lines, "Defanged URL", u.get("defanged_url"))
    add_field(lines, "Scheme", u.get("scheme"))
    add_field(lines, "Netloc", u.get("netloc"))
    add_field(lines, "Домен", u.get("domain"))
    add_field(lines, "Путь", u.get("path"))
    add_field(lines, "Query", u.get("query"))
    add_field(lines, "Fragment", u.get("fragment"))
    add_field(lines, "Port", u.get("port"))
    return "\n".join(lines)


def render_dns(data):
    d = data["dns"]
    lines = []
    add_section(lines, "DNS")
    add_field(lines, "DNS-сервер", d.get("dns_server_name"))
    add_field(lines, "IP DNS-сервера", d.get("dns_server_ip"))
    add_field(lines, "Resolved IP", d.get("resolved_ips"))
    add_field(lines, "PTR", d.get("ptr"))

    lines.append(SUB_LINE)
    lines.append("NS-записи")
    if d.get("ns_records"):
        for rec in d["ns_records"]:
            lines.append(f"  • {rec.get('host')}  |  IP: {rec.get('ip') or '—'}")
    else:
        lines.append("  —")

    lines.append(SUB_LINE)
    lines.append("MX-записи")
    if d.get("mx_records"):
        for rec in d["mx_records"]:
            lines.append(
                f"  • Preference: {rec.get('preference')}  |  Host: {rec.get('host')}  |  IP: {rec.get('ip') or '—'}"
            )
    else:
        lines.append("  —")

    lines.append(SUB_LINE)
    lines.append("TXT-записи")
    if d.get("txt_records"):
        for rec in d["txt_records"]:
            lines.append(f"  • {rec}")
    else:
        lines.append("  —")

    lines.append(SUB_LINE)
    lines.append("SPF")
    spf = d.get("spf")
    if spf:
        add_field(lines, "Raw", spf.get("raw"))
        add_field(lines, "Policy", spf.get("policy"))
        add_field(lines, "ip4", spf.get("ip4"))
        add_field(lines, "ip6", spf.get("ip6"))
        add_field(lines, "include", spf.get("include"))
    else:
        lines.append("  —")

    return "\n".join(lines)


def render_http(data):
    h = data["http"]
    lines = []
    add_section(lines, "HTTP")
    if h.get("error"):
        add_field(lines, "Ошибка", h.get("error"))
        return "\n".join(lines)

    head = h.get("head", {})
    get_part = h.get("get", {})

    lines.append("HEAD")
    add_field(lines, "Status", f"{head.get('status_code')} {head.get('reason') or ''}".strip())
    add_field(lines, "URL", head.get("url"))
    add_field(lines, "Location", head.get("headers", {}).get("Location"))
    add_field(lines, "Server", head.get("headers", {}).get("Server"))
    add_field(lines, "Content-Type", head.get("headers", {}).get("Content-Type"))
    add_field(lines, "Content-Length", head.get("headers", {}).get("Content-Length"))

    lines.append(SUB_LINE)
    lines.append("GET")
    add_field(lines, "Status", f"{get_part.get('status_code')} {get_part.get('reason') or ''}".strip())
    add_field(lines, "Final URL", get_part.get("final_url"))
    add_field(lines, "Server", get_part.get("server"))
    add_field(lines, "Content-Type", get_part.get("content_type"))
    add_field(lines, "Content-Length", get_part.get("content_length"))
    add_field(lines, "Title", h.get("page_title"))

    lines.append(SUB_LINE)
    lines.append("Redirect chain")
    if h.get("redirects"):
        for i, r in enumerate(h["redirects"], start=1):
            lines.append(f"  {i}. {r.get('status_code')} {r.get('reason') or ''} | {r.get('url')} -> {r.get('location') or '—'}")
    else:
        lines.append("  —")

    lines.append(SUB_LINE)
    lines.append("Security headers")
    for k, v in (get_part.get("security_headers") or {}).items():
        add_field(lines, k, v)

    lines.append(SUB_LINE)
    lines.append("Cookies")
    if h.get("cookies"):
        for c in h["cookies"]:
            lines.append(f"  • {c.get('name')}  |  domain={c.get('domain') or '—'}  |  path={c.get('path') or '—'}  |  secure={c.get('secure')}")
    else:
        lines.append("  —")

    lines.append(SUB_LINE)
    lines.append("Body preview")
    lines.append(h.get("body_preview") or "—")

    return "\n".join(lines)


def render_tls(data):
    t = data["tls"]
    lines = []
    add_section(lines, "TLS / SSL")
    add_field(lines, "Проверка socket", "Успешно" if t.get("ok") else "Неуспешно")
    add_field(lines, "Ошибка", t.get("error"))
    add_field(lines, "Протокол", t.get("protocol"))
    add_field(lines, "Cipher", t.get("cipher"))
    add_field(lines, "Subject CN", t.get("subject_cn"))
    add_field(lines, "Issuer CN", t.get("issuer_cn"))
    add_field(lines, "NotBefore", format_dt(t.get("not_before")))
    add_field(lines, "NotAfter", format_dt(t.get("not_after")))
    add_field(lines, "SAN", t.get("san"))

    lines.append(SUB_LINE)
    lines.append("OpenSSL")
    o = t.get("openssl", {})
    add_field(lines, "Доступен", o.get("available"))
    add_field(lines, "Return code", o.get("returncode"))
    add_field(lines, "Verify code", o.get("verify_code"))
    add_field(lines, "Verify text", o.get("verify_text"))
    add_field(lines, "Protocol", o.get("protocol"))
    add_field(lines, "Cipher", o.get("cipher"))
    add_field(lines, "Subject CN", o.get("subject_cn"))
    add_field(lines, "Issuer CN", o.get("issuer_cn"))
    if o.get("error"):
        add_field(lines, "Ошибка", o.get("error"))
    return "\n".join(lines)


def render_whois(data):
    w = data["whois"]
    lines = []
    add_section(lines, "WHOIS")
    add_field(lines, "Доступен", w.get("available"))
    add_field(lines, "Ошибка", w.get("error"))
    add_field(lines, "Registrar", w.get("registrar"))
    add_field(lines, "Creation Date", format_dt(w.get("created")))
    add_field(lines, "Updated Date", format_dt(w.get("updated")))
    add_field(lines, "Expiry Date", format_dt(w.get("expires")))
    add_field(lines, "Возраст домена, дней", domain_age_days(w.get("created")))

    lines.append(SUB_LINE)
    lines.append("Domain Status")
    if w.get("status"):
        for x in w["status"]:
            lines.append(f"  • {x}")
    else:
        lines.append("  —")

    lines.append(SUB_LINE)
    lines.append("Name Server")
    if w.get("name_servers"):
        for x in w["name_servers"]:
            lines.append(f"  • {x}")
    else:
        lines.append("  —")

    return "\n".join(lines)


def render_geo(data):
    g = data["geo"]
    lines = []
    add_section(lines, "GEO / IPINFO")
    add_field(lines, "OK", g.get("ok"))
    add_field(lines, "Ошибка", g.get("error"))
    add_field(lines, "IP", g.get("ip"))
    add_field(lines, "Hostname", g.get("hostname"))
    add_field(lines, "Country", g.get("country"))
    add_field(lines, "Region", g.get("region"))
    add_field(lines, "City", g.get("city"))
    add_field(lines, "Org / ASN", g.get("org"))
    add_field(lines, "Coordinates", g.get("loc"))
    add_field(lines, "Postal", g.get("postal"))
    add_field(lines, "Timezone", g.get("timezone"))
    return "\n".join(lines)


def render_abuse(data):
    a = data["abuse"]
    lines = []
    add_section(lines, "ABUSEIPDB")
    add_field(lines, "OK", a.get("ok"))
    add_field(lines, "Ошибка", a.get("error"))
    add_field(lines, "IP", a.get("ip"))
    add_field(lines, "Abuse score", a.get("abuse_confidence_score"))
    add_field(lines, "Total reports", a.get("total_reports"))
    add_field(lines, "Country code", a.get("country_code"))
    add_field(lines, "ISP", a.get("isp"))
    add_field(lines, "Usage type", a.get("usage_type"))
    add_field(lines, "Domain", a.get("domain"))
    add_field(lines, "Last reported", format_dt(a.get("last_reported_at")))
    if a.get("body"):
        lines.append(SUB_LINE)
        lines.append("Response excerpt")
        lines.append(a.get("body"))
    return "\n".join(lines)


def render_extra(data):
    e = data["extra"]
    lines = []
    add_section(lines, "EXTRA COMMANDS")

    ordered = [
        "nslookup_domain",
        "nslookup_mx",
        "nslookup_ns",
        "nslookup_txt",
        "nslookup_ip",
        "ping",
        "traceroute",
        "curl_head",
        "curl_head_follow",
        "openssl_s_client",
    ]

    for key in ordered:
        if key not in e:
            continue

        item = e[key]
        lines.append(key.upper())
        add_field(lines, "Command", item.get("command"))
        add_field(lines, "Return code", item.get("returncode"))
        add_field(lines, "Error", item.get("error"))

        if key == "ping":
            ping_data = parse_ping_summary(item.get("stdout", ""))
            lines.append("Parsed summary")
            add_field(lines, "Target", ping_data.get("host"))
            add_field(lines, "IP", ping_data.get("ip"))
            add_field(lines, "Sent", ping_data.get("sent"))
            add_field(lines, "Received", ping_data.get("received"))
            add_field(lines, "Lost", ping_data.get("lost"))
            add_field(lines, "Loss %", ping_data.get("loss_percent"))
            add_field(lines, "Min ms", ping_data.get("min_ms"))
            add_field(lines, "Max ms", ping_data.get("max_ms"))
            add_field(lines, "Avg ms", ping_data.get("avg_ms"))
            if ping_data.get("raw_excerpt"):
                lines.append("STDOUT")
                lines.append(ping_data["raw_excerpt"])

        elif key == "traceroute":
            tr_data = parse_traceroute_summary(item.get("stdout", ""))
            lines.append("Parsed summary")
            add_field(lines, "Target", tr_data.get("target"))
            add_field(lines, "IP", tr_data.get("ip"))
            add_field(lines, "Max hops", tr_data.get("max_hops"))
            if tr_data.get("hops"):
                lines.append("Hops")
                for hop in tr_data["hops"][:40]:
                    times = ", ".join(f"{x} ms" for x in hop.get("times_ms", [])) if hop.get("times_ms") else "—"
                    lines.append(
                        f"  • Hop {hop.get('hop')}: IP={hop.get('ip') or '—'} | RTT={times} | timeouts={hop.get('timeouts')}"
                    )
            if tr_data.get("raw_excerpt"):
                lines.append("STDOUT")
                lines.append(tr_data["raw_excerpt"])

        else:
            if item.get("stdout"):
                lines.append("STDOUT")
                lines.append(item["stdout"][:6000])
            if item.get("stderr"):
                lines.append("STDERR")
                lines.append(item["stderr"][:3000])

        lines.append(SUB_LINE)

    return "\n".join(lines)


def render_full_report(data):
    parts = [
        render_summary(data),
        render_url_info(data),
        render_dns(data),
        render_http(data),
        render_tls(data),
        render_whois(data),
        render_geo(data),
        render_abuse(data),
        render_extra(data),
    ]
    return "\n\n".join(parts).strip() + "\n"


def create_link_analyzer_frame(root, parent, bg_color, btn_color, text_color, frame_bg, output_bg):
    frame = tk.Frame(parent, bg=bg_color)

    top = tk.LabelFrame(
        frame,
        text="Link analyzer",
        bg=frame_bg,
        fg=text_color,
        padx=10,
        pady=10,
    )
    top.pack(fill="x", padx=10, pady=10)

    tk.Label(
        top,
        text="URL:",
        bg=frame_bg,
        fg=text_color,
        font=("Arial", 10, "bold"),
    ).grid(row=0, column=0, sticky="w", padx=5, pady=5)

    url_var = tk.StringVar()
    entry = tk.Entry(top, textvariable=url_var, width=95)
    entry.grid(row=0, column=1, sticky="we", padx=5, pady=5)

    top.grid_columnconfigure(1, weight=1)

    btns = tk.Frame(frame, bg=bg_color)
    btns.pack(fill="x", padx=10, pady=(0, 10))

    text = tk.Text(
        frame,
        wrap="word",
        bg=output_bg,
        fg=text_color,
        insertbackground=text_color,
        font=("Consolas", 10),
        padx=12,
        pady=12,
    )
    text.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    scroll = tk.Scrollbar(text)
    scroll.pack(side="right", fill="y")
    text.config(yscrollcommand=scroll.set)
    scroll.config(command=text.yview)

    def set_output(value):
        text.delete("1.0", tk.END)
        text.insert(tk.END, value)

    def do_copy():
        content = text.get("1.0", tk.END).strip()
        if not content:
            return
        root.clipboard_clear()
        root.clipboard_append(content)
        messagebox.showinfo("Готово", "Результат скопирован в буфер обмена.")

    def do_clear():
        text.delete("1.0", tk.END)

    def do_save():
        content = text.get("1.0", tk.END).strip()
        if not content:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        messagebox.showinfo("Готово", "Результат сохранён.")

    def do_analyze():
        url = url_var.get().strip()
        if not url:
            messagebox.showerror("Ошибка", "Введите URL.")
            return

        set_output("Выполняется анализ...\n\nЭто может занять до 20–40 секунд из-за traceroute / whois / внешних запросов.\n")

        def worker():
            try:
                result = analyze_target_url(url)
                report = render_full_report(result)
                frame.after(0, lambda: set_output(report))
            except Exception as e:
                frame.after(0, lambda: set_output(f"Ошибка анализа:\n{e}"))

        threading.Thread(target=worker, daemon=True).start()

    tk.Button(
        btns,
        text="Анализировать",
        bg=btn_color,
        fg="white",
        command=do_analyze,
    ).pack(side="left", padx=(0, 8))

    tk.Button(
        btns,
        text="Копировать",
        bg=btn_color,
        fg="white",
        command=do_copy,
    ).pack(side="left", padx=(0, 8))

    tk.Button(
        btns,
        text="Сохранить",
        bg=btn_color,
        fg="white",
        command=do_save,
    ).pack(side="left", padx=(0, 8))

    tk.Button(
        btns,
        text="Очистить",
        bg=btn_color,
        fg="white",
        command=do_clear,
    ).pack(side="left", padx=(0, 8))

    entry.bind("<Return>", lambda event: do_analyze())

    return frame