#!/usr/bin/env python3


#######
# dev by medicineh
#######

"""
MediWebScan -- full web recon suite.

subdomain enum · fingerprint · WAF detection · dir brute · crawl ·
nuclei · screenshots · subdomain takeover · param mining · stealth mode
JSON + HTML reports.

pip install requests dnspython
"""

import argparse
import html as html_mod
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urljoin

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.exit("[!] pip install requests")

try:
    import dns.resolver
except ImportError:
    dns = None

# ── paleta ──────────────────────────────────────────────────────────────────

R = "\033[31m"
G = "\033[32m"
Y = "\033[33m"
C = "\033[36m"
B = "\033[1m"
D = "\033[2m"  # dim
Z = "\033[0m"


def log(msg):
    print(f"{G}[+]{Z} {msg}")


def warn(msg):
    print(f"{Y}[-]{Z} {msg}")


def err(msg):
    print(f"{R}[!]{Z} {msg}")


def banner(msg):
    print(f"\n{C}{'─'*60}")
    print(f"  {msg}")
    print(f"{'─'*60}{Z}")


def has(bin_name):
    return shutil.which(bin_name) is not None


# ── stealth ─────────────────────────────────────────────────────────────────

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]

# config global que main() rellena
STEALTH = {"enabled": False, "delay_min": 0, "delay_max": 0}


def stealth_delay():
    """pausa aleatoria si el modo stealth esta activo"""
    if STEALTH["enabled"] and STEALTH["delay_max"] > 0:
        time.sleep(random.uniform(STEALTH["delay_min"], STEALTH["delay_max"]))


def get_session():
    """session de requests con User-Agent aleatorio"""
    s = requests.Session()
    s.headers["User-Agent"] = random.choice(USER_AGENTS)
    s.verify = False
    return s


def sget(url, **kwargs):
    """GET con stealth delay y UA aleatorio"""
    stealth_delay()
    kwargs.setdefault("timeout", 10)
    kwargs.setdefault("verify", False)
    kwargs.setdefault("allow_redirects", True)
    kwargs.setdefault("headers", {})
    kwargs["headers"].setdefault("User-Agent", random.choice(USER_AGENTS))
    return requests.get(url, **kwargs)


def shead(url, **kwargs):
    """HEAD con stealth delay y UA aleatorio"""
    stealth_delay()
    kwargs.setdefault("timeout", 10)
    kwargs.setdefault("verify", False)
    kwargs.setdefault("allow_redirects", True)
    kwargs.setdefault("headers", {})
    kwargs["headers"].setdefault("User-Agent", random.choice(USER_AGENTS))
    return requests.head(url, **kwargs)


def shell(cmd, timeout=300, stdin_data=None):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout, input=stdin_data)
        return r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    except Exception:
        return ""


# ── crt.sh ──────────────────────────────────────────────────────────────────

def from_crtsh(domain):
    log("crt.sh -- certificados SSL en registros publicos (CT logs)")
    found = set()
    try:
        r = sget(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
        for row in r.json():
            for name in row.get("name_value", "").split("\n"):
                name = name.strip().lower().replace("*.", "")
                if name.endswith(f".{domain}") or name == domain:
                    found.add(name)
    except Exception:
        warn("crt.sh no respondio")
    print(f"    {len(found)} subdominios")
    return found


# ── herramientas pasivas ────────────────────────────────────────────────────

def from_subfinder(domain):
    if not has("subfinder"):
        warn("subfinder no instalado")
        return set()
    log("subfinder -- APIs: Shodan, VirusTotal, SecurityTrails...")
    out = shell(["subfinder", "-d", domain, "-silent"])
    s = {l.strip().lower() for l in out.splitlines() if l.strip()}
    print(f"    {len(s)} subdominios")
    return s


def from_amass(domain):
    if not has("amass"):
        warn("amass no instalado")
        return set()
    log("amass pasivo -- OSINT completo (max 5 min)")
    out = shell(["amass", "enum", "-passive", "-d", domain], timeout=300)
    s = {l.strip().lower() for l in out.splitlines() if l.strip()}
    print(f"    {len(s)} subdominios")
    return s


def from_assetfinder(domain):
    if not has("assetfinder"):
        warn("assetfinder no instalado")
        return set()
    log("assetfinder -- Facebook CT, Wayback, VirusTotal...")
    out = shell(["assetfinder", "--subs-only", domain])
    s = set()
    for l in out.splitlines():
        l = l.strip().lower()
        if l.endswith(f".{domain}") or l == domain:
            s.add(l)
    print(f"    {len(s)} subdominios")
    return s


# ── brute DNS ───────────────────────────────────────────────────────────────

def brute_dns(domain, wordlist, threads):
    found = set()

    if has("gobuster") and os.path.isfile(wordlist):
        log(f"brute DNS con gobuster ({os.path.basename(wordlist)})")
        out = shell([
            "gobuster", "dns", "--domain", domain,
            "-w", wordlist, "-t", str(threads), "--wildcard", "--no-color"
        ], timeout=600)
        for l in out.splitlines():
            l = l.replace("Found: ", "").strip().lower()
            if l.endswith(f".{domain}"):
                found.add(l)
        print(f"    {len(found)}")
        return found

    if dns is None or not os.path.isfile(wordlist):
        warn("ni gobuster ni dnspython para brute -- skip")
        return found

    log(f"brute DNS con dnspython ({os.path.basename(wordlist)})")
    res = dns.resolver.Resolver()
    res.nameservers = ["1.1.1.1", "8.8.8.8"]
    res.timeout = 3
    res.lifetime = 3
    words = Path(wordlist).read_text().splitlines()

    def probe(w):
        fqdn = f"{w.strip()}.{domain}"
        try:
            res.resolve(fqdn, "A")
            return fqdn
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        for r in pool.map(probe, words):
            if r:
                found.add(r.lower())
    print(f"    {len(found)}")
    return found


# ── alive check ─────────────────────────────────────────────────────────────

def alive_check(subs, threads):
    urls = []

    if has("httpx"):
        log("httpx -- comprobando respuestas HTTP/HTTPS")
        inp = "\n".join(subs)
        try:
            r = subprocess.run(
                ["httpx", "-silent", "-mc", "200,301,302,403,401,500",
                 "-t", str(threads)],
                input=inp, capture_output=True, text=True, timeout=300
            )
            urls = [l.strip() for l in r.stdout.splitlines() if l.strip()]
        except Exception:
            pass

    if not urls:
        log("alive check manual con requests")

        def try_sub(sub):
            for scheme in ("https", "http"):
                try:
                    shead(f"{scheme}://{sub}", timeout=5)
                    return f"{scheme}://{sub}"
                except Exception:
                    pass
            return None

        with ThreadPoolExecutor(max_workers=threads) as pool:
            for r in pool.map(try_sub, subs):
                if r:
                    urls.append(r)

    urls = sorted(set(urls))
    print(f"    {len(urls)} vivos")
    return urls


# ── WAF / CDN detection ────────────────────────────────────────────────────

WAF_SIGNATURES = {
    "cf-ray":          "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "server: cloudflare": "Cloudflare",
    "x-sucuri-id":     "Sucuri",
    "x-sucuri-cache":  "Sucuri",
    "server: sucuri":  "Sucuri",
    "x-akamai-transformed": "Akamai",
    "server: akamaighost":  "Akamai",
    "x-cdn: imperva":  "Imperva/Incapsula",
    "x-iinfo":         "Imperva/Incapsula",
    "x-fw-hash":       "F5 BIG-IP",
    "server: bigip":   "F5 BIG-IP",
    "x-powered-by: aws lambda": "AWS WAF/CloudFront",
    "x-amz-cf-id":     "AWS CloudFront",
    "x-azure-ref":     "Azure Front Door",
    "server: ddos-guard": "DDoS-Guard",
    "server: barracuda": "Barracuda",
    "x-denied-reason":  "Fortinet FortiWeb",
    "server: mod_security": "ModSecurity",
}


def detect_waf_manual(url):
    """detecta WAF/CDN revisando cabeceras y respuestas"""
    detected = set()
    try:
        r = sget(url, timeout=10)
        hdrs_raw = "\n".join(f"{k.lower()}: {v.lower()}" for k, v in r.headers.items())

        for sig, waf_name in WAF_SIGNATURES.items():
            if sig.lower() in hdrs_raw:
                detected.add(waf_name)

        # probar con payload sospechoso para provocar bloqueo
        test_url = url.rstrip("/") + "/?id=1' OR '1'='1"
        try:
            r2 = sget(test_url, timeout=10, allow_redirects=False)
            if r2.status_code in (403, 406, 429, 503):
                body = r2.text[:5000].lower()
                if "cloudflare" in body:
                    detected.add("Cloudflare")
                elif "sucuri" in body:
                    detected.add("Sucuri")
                elif "incapsula" in body or "imperva" in body:
                    detected.add("Imperva/Incapsula")
                elif "ddos" in body:
                    detected.add("DDoS-Guard")
                elif "mod_security" in body or "modsecurity" in body:
                    detected.add("ModSecurity")
                elif "access denied" in body or "blocked" in body:
                    detected.add("WAF (genérico)")
        except Exception:
            pass
    except Exception:
        pass
    return detected


def waf_phase(alive, outdir, threads):
    if not alive:
        return "", {}

    waf_cache = {}  # url -> set of WAF names
    out_path = os.path.join(outdir, "waf.txt")

    # wafw00f si esta
    if has("wafw00f"):
        log(f"wafw00f -- detectando WAF/CDN en {len(alive)} urls")
        for url in alive:
            out = shell(["wafw00f", url, "-o-"], timeout=60)
            waf_cache[url] = set()
            for l in out.splitlines():
                if "is behind" in l.lower():
                    # "The site https://x.com is behind Cloudflare (Cloudflare Inc.)"
                    m = re.search(r"is behind (.+?)(?:\s*\(|$)", l, re.I)
                    if m:
                        waf_cache[url].add(m.group(1).strip())
                elif "no waf" in l.lower():
                    pass  # limpio
    else:
        log(f"Detectando WAF/CDN manualmente en {len(alive)} urls")

    # siempre hacer tambien deteccion manual para complementar
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(detect_waf_manual, u): u for u in alive}
        for f in as_completed(futs):
            url = futs[f]
            detected = f.result()
            existing = waf_cache.get(url, set())
            waf_cache[url] = existing | detected

    # output
    with open(out_path, "w") as fp:
        for url in sorted(waf_cache):
            wafs = waf_cache[url]
            if wafs:
                line = f"{url}  →  {', '.join(sorted(wafs))}"
                fp.write(line + "\n")
                print(f"    {Y}{line}{Z}")
            else:
                fp.write(f"{url}  →  (sin WAF detectado)\n")
                print(f"    {url}  →  {G}limpio{Z}")

    return out_path, waf_cache


# ── cabeceras ───────────────────────────────────────────────────────────────

SEC_HDRS = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "CSP"),
    ("x-frame-options", "XFO"),
    ("x-content-type-options", "XCTO"),
    ("x-xss-protection", "XXSS"),
    ("permissions-policy", "PP"),
    ("referrer-policy", "RP"),
]


def grab_headers(url):
    try:
        r = shead(url, timeout=10)
        return dict(r.headers)
    except Exception:
        return {}


def headers_phase(alive, outdir, threads):
    if not alive:
        return ""

    log(f"Cabeceras HTTP de {len(alive)} urls")
    data = {}
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(grab_headers, u): u for u in alive}
        for f in as_completed(futs):
            data[futs[f]] = f.result()

    out_path = os.path.join(outdir, "headers.txt")
    with open(out_path, "w") as fp:
        for url in sorted(data):
            fp.write(f"--- {url} ---\n")
            h = data[url]
            if h:
                for k, v in h.items():
                    fp.write(f"  {k}: {v}\n")
            else:
                fp.write("  (no response)\n")
            fp.write("\n")

    col = 42
    hdr = f"{'URL':<{col}}" + "".join(f"{s:<6}" for _, s in SEC_HDRS)
    sep = "-" * len(hdr)
    print(f"    {hdr}")
    print(f"    {sep}")
    lines = [hdr, sep]

    for url in sorted(data):
        lower_h = {k.lower(): v for k, v in data[url].items()}
        row = f"{url:<{col}}"
        for full, _ in SEC_HDRS:
            row += f"{'ok':<6}" if full in lower_h else f"{'--':<6}"
        print(f"    {row}")
        lines.append(row)

    with open(out_path, "a") as fp:
        fp.write("\n-- security headers --\n")
        for l in lines:
            fp.write(l + "\n")

    return out_path


# ── tech detection ──────────────────────────────────────────────────────────

SIGS = {
    "wp-content": "WordPress", "wp-includes": "WordPress",
    "joomla": "Joomla", "drupal": "Drupal", "shopify": "Shopify",
    "__next": "Next.js", "nuxt": "Nuxt.js",
    "angular": "Angular", "vue.js": "Vue.js",
    "laravel": "Laravel", "django": "Django", "flask": "Flask",
    "rails": "Rails", "bootstrap": "Bootstrap",
    "tailwindcss": "Tailwind", "jquery": "jQuery",
    "cloudflare": "Cloudflare", "react": "React",
    "express": "Express.js", "tomcat": "Apache Tomcat",
    "aspnet": "ASP.NET", "asp.net": "ASP.NET",
}


def fingerprint(url):
    info = {"url": url, "server": "", "via": "", "stack": []}
    try:
        r = sget(url, timeout=10)
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        info["server"] = hdrs.get("server", "")
        info["via"] = hdrs.get("x-powered-by", "")

        body = r.text[:50_000].lower()
        for sig, name in SIGS.items():
            if sig in body and name not in info["stack"]:
                info["stack"].append(name)

        m = re.search(r"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)", body)
        if m and m.group(1) not in info["stack"]:
            info["stack"].append(m.group(1))
    except Exception:
        pass
    return info


def tech_phase(alive, outdir, threads):
    """devuelve (out_path, tech_cache) donde tech_cache = {url: [techs]}"""
    tech_cache = {}
    if not alive:
        return "", tech_cache

    out_path = os.path.join(outdir, "tech.txt")

    if has("whatweb"):
        log(f"whatweb -- fingerprinting {len(alive)} urls")
        inp = os.path.join(outdir, "_ww.tmp")
        Path(inp).write_text("\n".join(alive))
        shell([
            "whatweb", f"--input-file={inp}", f"--log-brief={out_path}",
            "--color=never", "--max-threads", str(threads),
            "--follow-redirect=same-site", "-q"
        ], timeout=300)
        try:
            os.unlink(inp)
        except OSError:
            pass
        if os.path.isfile(out_path) and os.path.getsize(out_path) > 0:
            with open(out_path) as fp:
                for i, l in enumerate(fp):
                    if i > 40:
                        break
                    print(f"    {l.rstrip()}")
            with open(out_path) as fp:
                for l in fp:
                    parts = l.strip().split()
                    if parts:
                        url_part = parts[0]
                        techs = [p for p in parts[1:]
                                 if not p.startswith("[") and not p.startswith("http")]
                        tech_cache[url_part] = techs

    # siempre complementar con fingerprint propio
    log(f"Fingerprint propio sobre {len(alive)} urls")
    results = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(fingerprint, u): u for u in alive}
        for f in as_completed(futs):
            results.append(f.result())

    need_write = not (os.path.isfile(out_path) and os.path.getsize(out_path) > 0)
    mode = "w" if need_write else "a"
    with open(out_path, mode) as fp:
        if not need_write:
            fp.write("\n-- fingerprint propio --\n")
        for t in sorted(results, key=lambda x: x["url"]):
            existing = tech_cache.get(t["url"], [])
            existing.extend(t["stack"])
            tech_cache[t["url"]] = list(set(existing))

            parts = [t["url"]]
            if t["server"]:
                parts.append(t["server"])
            if t["via"]:
                parts.append(t["via"])
            if t["stack"]:
                parts.append(", ".join(t["stack"]))
            line = " | ".join(parts)
            fp.write(line + "\n")
            if need_write:
                print(f"    {line}")

    return out_path, tech_cache


# ── nmap ────────────────────────────────────────────────────────────────────

def resolve_hosts(alive, threads):
    """resuelve hostnames -> IPs, devuelve set de IPs"""
    hosts = set()
    for u in alive:
        p = urlparse(u)
        h = p.hostname or p.path
        hosts.add(h)

    ips = set()
    def resolve(h):
        try:
            return socket.gethostbyname(h)
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        for r in pool.map(resolve, hosts):
            if r:
                ips.add(r)
    return ips


def nmap_phase(alive, outdir, threads):
    if not has("nmap"):
        warn("nmap no instalado")
        return ""

    log("Resolviendo hostnames a IPs")
    ips = resolve_hosts(alive, threads)
    if not ips:
        warn("0 IPs resueltas")
        return ""
    print(f"    {len(ips)} IPs")

    ip_file = os.path.join(outdir, "ips.txt")
    Path(ip_file).write_text("\n".join(sorted(ips)))

    nmap_txt = os.path.join(outdir, "nmap.txt")
    nmap_xml = os.path.join(outdir, "nmap.xml")

    log(f"nmap -sV -sC top 1000 sobre {len(ips)} IPs")
    warn("puede tardar unos minutos")
    shell([
        "nmap", "-sV", "-sC", "--top-ports", "1000", "-T4", "--open",
        "-iL", ip_file, "-oN", nmap_txt, "-oX", nmap_xml
    ], timeout=900)

    if os.path.isfile(nmap_txt):
        with open(nmap_txt) as fp:
            for l in fp:
                if "/tcp" in l and "open" in l:
                    print(f"    {l.rstrip()}")
    return nmap_txt


def vuln_phase(outdir):
    ip_file = os.path.join(outdir, "ips.txt")
    if not os.path.isfile(ip_file):
        warn("no hay ips.txt")
        return ""
    if not has("nmap"):
        warn("nmap no instalado")
        return ""

    vuln_txt = os.path.join(outdir, "nmap_vuln.txt")
    vuln_xml = os.path.join(outdir, "nmap_vuln.xml")

    log("nmap --script vuln (CVEs, misconfigs)")
    warn("puede tardar 5-15 min por IP")
    shell([
        "nmap", "--script", "vuln", "--top-ports", "200", "-T4", "--open",
        "-iL", ip_file, "-oN", vuln_txt, "-oX", vuln_xml
    ], timeout=1800)

    if os.path.isfile(vuln_txt):
        with open(vuln_txt) as fp:
            for l in fp:
                stripped = l.strip()
                if any(k in stripped.upper() for k in ("VULNERABLE", "CVE-", "STATE:", "| ", "|_")):
                    print(f"    {l.rstrip()}")
    return vuln_txt


# ── subdomain takeover ─────────────────────────────────────────────────────

# servicios conocidos vulnerables a takeover y sus fingerprints
TAKEOVER_FINGERPRINTS = {
    "github.io": {
        "cnames": ["github.io"],
        "body": ["there isn't a github pages site here", "for root urls"],
    },
    "herokuapp.com": {
        "cnames": ["herokuapp.com", "herokussl.com"],
        "body": ["no such app", "heroku | no such app"],
    },
    "s3.amazonaws.com": {
        "cnames": ["s3.amazonaws.com", ".s3.amazonaws.com", "s3-website"],
        "body": ["nosuchbucket", "the specified bucket does not exist"],
    },
    "azure": {
        "cnames": [".azurewebsites.net", ".cloudapp.azure.com", ".azure-api.net",
                    ".azurefd.net", ".blob.core.windows.net", ".trafficmanager.net"],
        "body": ["404 web site not found", "the resource you are looking for has been removed"],
    },
    "shopify": {
        "cnames": ["myshopify.com"],
        "body": ["sorry, this shop is currently unavailable", "only one step left"],
    },
    "tumblr": {
        "cnames": ["domains.tumblr.com"],
        "body": ["there's nothing here", "whatever you were looking for"],
    },
    "wordpress.com": {
        "cnames": ["wordpress.com"],
        "body": ["do you want to register"],
    },
    "ghost.io": {
        "cnames": ["ghost.io"],
        "body": ["the thing you were looking for is no longer here"],
    },
    "surge.sh": {
        "cnames": ["surge.sh"],
        "body": ["project not found"],
    },
    "bitbucket.io": {
        "cnames": ["bitbucket.io"],
        "body": ["repository not found"],
    },
    "pantheon.io": {
        "cnames": ["pantheonsite.io"],
        "body": ["404 error unknown site"],
    },
    "fastly": {
        "cnames": ["fastly.net", "fastlylb.net"],
        "body": ["fastly error: unknown domain"],
    },
    "zendesk": {
        "cnames": ["zendesk.com"],
        "body": ["help center closed"],
    },
    "unbounce": {
        "cnames": ["unbouncepages.com"],
        "body": ["the requested url was not found"],
    },
    "cargo": {
        "cnames": ["cargocollective.com"],
        "body": ["404 not found"],
    },
    "flyio": {
        "cnames": ["fly.dev", "edgeapp.net"],
        "body": ["404 not found"],
    },
}


def check_cname(subdomain):
    """resuelve CNAME de un subdominio"""
    if dns is None:
        # fallback: dig
        if has("dig"):
            out = shell(["dig", "+short", "CNAME", subdomain], timeout=10)
            cnames = [l.strip().rstrip(".").lower() for l in out.splitlines() if l.strip()]
            return cnames
        return []
    try:
        res = dns.resolver.Resolver()
        res.nameservers = ["1.1.1.1", "8.8.8.8"]
        res.timeout = 5
        res.lifetime = 5
        answers = res.resolve(subdomain, "CNAME")
        return [str(r.target).rstrip(".").lower() for r in answers]
    except Exception:
        return []


def takeover_phase(subs, alive, outdir, threads):
    if not subs:
        return ""

    out_path = os.path.join(outdir, "takeover.txt")
    findings = []

    log(f"Comprobando subdomain takeover en {len(subs)} subdominios")
    log("Resolviendo CNAMEs y buscando servicios huérfanos...")

    def check_sub(sub):
        cnames = check_cname(sub)
        if not cnames:
            return None

        result = {"sub": sub, "cnames": cnames, "vulnerable": False,
                  "service": "", "evidence": ""}

        for service, info in TAKEOVER_FINGERPRINTS.items():
            for cname in cnames:
                for pattern in info["cnames"]:
                    if pattern in cname:
                        # CNAME apunta a servicio potencialmente vulnerable
                        result["service"] = service
                        # comprobar si el servicio devuelve error
                        for scheme in ("https", "http"):
                            try:
                                r = sget(f"{scheme}://{sub}", timeout=8)
                                body = r.text[:10_000].lower()
                                for fingerprint_text in info["body"]:
                                    if fingerprint_text in body:
                                        result["vulnerable"] = True
                                        result["evidence"] = fingerprint_text
                                        return result
                            except Exception:
                                # conexion rechazada = podria ser vulnerable
                                result["evidence"] = "connection refused"
                                result["vulnerable"] = True
                                return result
                        # CNAME coincide pero no hay fingerprint → sospechoso
                        result["evidence"] = f"CNAME → {cname}"
                        return result
        return result

    with ThreadPoolExecutor(max_workers=min(threads, 15)) as pool:
        futs = {pool.submit(check_sub, sub): sub for sub in subs}
        for f in as_completed(futs):
            r = f.result()
            if r:
                findings.append(r)

    # output
    vulns = [f for f in findings if f["vulnerable"]]
    suspects = [f for f in findings if not f["vulnerable"] and f["service"]]

    with open(out_path, "w") as fp:
        if vulns:
            fp.write("== VULNERABLES ==\n")
            for f in vulns:
                line = f"[VULN] {f['sub']} → CNAME: {', '.join(f['cnames'])} | servicio: {f['service']} | evidencia: {f['evidence']}"
                fp.write(line + "\n")
                print(f"    {R}{line}{Z}")

        if suspects:
            fp.write("\n== SOSPECHOSOS ==\n")
            for f in suspects:
                line = f"[???] {f['sub']} → CNAME: {', '.join(f['cnames'])} | servicio: {f['service']}"
                fp.write(line + "\n")
                print(f"    {Y}{line}{Z}")

        if not vulns and not suspects:
            fp.write("(ningún subdominio vulnerable a takeover)\n")
            print(f"    {G}ningun subdominio vulnerable a takeover{Z}")

    log(f"Takeover: {len(vulns)} vulnerables, {len(suspects)} sospechosos")
    return out_path


# ── dir brute ───────────────────────────────────────────────────────────────

TECH_EXTENSIONS = {
    "WordPress":  "php,txt,xml,html,log,bak,old,zip,gz,sql,conf,ini,env",
    "Joomla":     "php,txt,xml,html,log,bak,old,zip,gz,sql,conf,ini,env",
    "Drupal":     "php,txt,xml,html,module,inc,install,info,log,bak,env",
    "Laravel":    "php,txt,html,json,env,log,bak,old,zip,sql,conf",
    "Django":     "py,txt,html,json,env,log,bak,old,zip,sql,conf,yaml,yml",
    "Flask":      "py,txt,html,json,env,log,bak,old,zip,sql,conf,yaml,yml",
    "Rails":      "rb,txt,html,json,env,log,bak,old,zip,sql,conf,yml,yaml",
    "Next.js":    "js,jsx,ts,tsx,json,html,txt,env,map,bak,old,zip,conf",
    "Nuxt.js":    "js,vue,json,html,txt,env,map,bak,old,zip,conf",
    "Angular":    "js,ts,json,html,txt,env,map,bak,old,zip,conf",
    "Vue.js":     "js,vue,json,html,txt,env,map,bak,old,zip,conf",
    "React":      "js,jsx,ts,tsx,json,html,txt,env,map,bak,old,zip",
    "ASP.NET":    "asp,aspx,ashx,asmx,config,bak,old,txt,xml,json,zip,sql",
    "Apache Tomcat": "jsp,do,action,xml,properties,bak,old,txt,json,war,zip",
    "Express.js": "js,json,html,txt,env,map,bak,old,zip,conf,yaml",
    "Shopify":    "json,html,txt,xml",
}
DEFAULT_EXTENSIONS = "php,html,txt,js,json,xml,bak,old,zip,gz,sql,conf,env,log,asp,aspx,jsp,do"

DIR_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
    "/usr/share/dirb/wordlists/big.txt",
    "/usr/share/wordlists/dirb/big.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
]


def _pick_extensions(url, tech_cache):
    stack = tech_cache.get(url, [])
    exts = set()
    for tech in stack:
        for key, val in TECH_EXTENSIONS.items():
            if key.lower() in tech.lower():
                exts.update(val.split(","))
    if not exts:
        return DEFAULT_EXTENSIONS
    exts.update(["bak", "old", "zip", "txt", "env", "log", "sql", "conf"])
    return ",".join(sorted(exts))


def _pick_wordlist(user_wl):
    if user_wl and os.path.isfile(user_wl):
        return user_wl
    for wl in DIR_WORDLISTS:
        if os.path.isfile(wl):
            return wl
    return None


def _gobuster_dir(url, wordlist, extensions, threads, timeout=600):
    cmd = [
        "gobuster", "dir", "-u", url, "-w", wordlist,
        "-t", str(threads), "--no-color", "-q",
        "-s", "200,204,301,302,307,308,401,403,405,500",
        "--timeout", "10s", "-k", "-e",
    ]
    if extensions:
        cmd += ["-x", extensions]
    return shell(cmd, timeout=timeout)


def _dirb_scan(url, wordlist, extensions, timeout=600):
    cmd = ["dirb", url, wordlist, "-S", "-r", "-z", "50"]
    if extensions:
        ext_list = extensions.split(",")
        cmd += ["-X", "." + ",.".join(ext_list)]
    out = shell(cmd, timeout=timeout)
    results = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("+ ") or line.startswith("==> DIRECTORY:"):
            results.append(line)
    return "\n".join(results)


def _python_dir_brute(url, wordlist, extensions, threads):
    words = Path(wordlist).read_text().splitlines()
    paths = []
    for w in words:
        w = w.strip()
        if not w or w.startswith("#"):
            continue
        paths.append(f"/{w}")
        if extensions:
            for ext in extensions.split(","):
                paths.append(f"/{w}.{ext}")

    results = []

    def probe(path):
        full = url.rstrip("/") + path
        try:
            r = sget(full, timeout=8, allow_redirects=False)
            if r.status_code in (200, 204, 301, 302, 307, 308, 401, 403, 405, 500):
                return f"{full} (Status: {r.status_code}) [Size: {len(r.content)}]"
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as pool:
        for r in pool.map(probe, paths):
            if r:
                results.append(r)

    return "\n".join(results)


def dir_brute(alive, outdir, dir_wordlist, threads, tech_cache=None, waf_cache=None):
    if not alive:
        warn("no hay urls vivas")
        return ""

    if tech_cache is None:
        tech_cache = {}
    if waf_cache is None:
        waf_cache = {}

    wordlist = _pick_wordlist(dir_wordlist)
    if not wordlist:
        warn("no se encontro ninguna wordlist de directorios")
        return ""

    use_gobuster = has("gobuster")
    use_dirb = has("dirb")

    if not use_gobuster and not use_dirb:
        warn("ni gobuster ni dirb -- fallback con requests (lento)")
        tool_name = "python-requests"
    elif use_gobuster:
        tool_name = "gobuster"
    else:
        tool_name = "dirb"

    out_path = os.path.join(outdir, "dirs.txt")
    dirs_dir = os.path.join(outdir, "dirs_per_host")
    os.makedirs(dirs_dir, exist_ok=True)

    wl_lines = sum(1 for _ in open(wordlist))
    log(f"Dir brute con {tool_name} sobre {len(alive)} hosts")
    log(f"Wordlist: {os.path.basename(wordlist)} ({wl_lines} palabras)")
    log(f"Extensiones adaptadas a la tecnologia de cada host")
    print()

    all_findings = {}

    for i, url in enumerate(alive, 1):
        extensions = _pick_extensions(url, tech_cache)
        hostname = urlparse(url).hostname or "unknown"
        host_file = os.path.join(dirs_dir, f"{hostname}.txt")

        # avisar si tiene WAF
        wafs = waf_cache.get(url, set())
        waf_note = f"  {Y}⚠ WAF: {', '.join(wafs)}{Z}" if wafs else ""

        print(f"  {C}[{i}/{len(alive)}]{Z} {B}{url}{Z}{waf_note}")
        print(f"         ext: {D}{extensions}{Z}")

        if use_gobuster:
            raw = _gobuster_dir(url, wordlist, extensions, threads)
        elif use_dirb:
            raw = _dirb_scan(url, wordlist, extensions)
        else:
            raw = _python_dir_brute(url, wordlist, extensions, threads)

        lines = []
        for l in raw.splitlines():
            l = l.strip()
            if l and not l.startswith("Error") and not l.startswith("Progress"):
                lines.append(l)

        all_findings[url] = lines

        with open(host_file, "w") as fp:
            fp.write(f"# {url}\n# tool: {tool_name}\n# wordlist: {wordlist}\n")
            fp.write(f"# extensions: {extensions}\n")
            fp.write(f"# {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")
            for l in lines:
                fp.write(l + "\n")

        if not lines:
            print(f"         {Y}(nada){Z}")
        else:
            print(f"         {G}{len(lines)} rutas{Z}")
            for j, l in enumerate(lines):
                if j < 25:
                    print(f"           {l}")
            if len(lines) > 25:
                print(f"           ... +{len(lines) - 25} mas")
        print()

    total_findings = 0
    with open(out_path, "w") as fp:
        fp.write(f"# MediWebScan -- dir brute\n")
        fp.write(f"# tool: {tool_name} | wordlist: {os.path.basename(wordlist)}\n")
        fp.write(f"# {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")
        for url in sorted(all_findings):
            lines = all_findings[url]
            total_findings += len(lines)
            fp.write(f"\n{'='*60}\n {url}\n ext: {_pick_extensions(url, tech_cache)}\n")
            fp.write(f" encontrados: {len(lines)}\n{'='*60}\n")
            for l in lines:
                fp.write(f"  {l}\n")
            if not lines:
                fp.write("  (nada)\n")

    log(f"Total: {total_findings} rutas en {len(alive)} hosts")
    return out_path


# ── crawl + JS endpoints ───────────────────────────────────────────────────

def crawl_phase(alive, outdir, threads):
    if not alive:
        return ""

    out_path = os.path.join(outdir, "crawl.txt")
    all_urls = set()

    # katana (JS-aware recursive crawler)
    if has("katana"):
        log(f"katana -- crawl recursivo con rendering JS sobre {len(alive)} urls")
        inp = "\n".join(alive)
        out = shell([
            "katana", "-list", "-", "-silent", "-d", "3",
            "-jc",  # JS crawl
            "-kf", "all",  # all known files
            "-c", str(threads),
            "-o", out_path,
        ], timeout=600, stdin_data=inp)
        if os.path.isfile(out_path):
            with open(out_path) as fp:
                all_urls = {l.strip() for l in fp if l.strip()}
    else:
        log(f"Crawl propio con requests sobre {len(alive)} urls (sin katana)")

    # crawl propio siempre complementa
    def simple_crawl(url):
        found = set()
        try:
            r = sget(url, timeout=10)
            body = r.text[:200_000]
            # extraer links de href y src
            for m in re.finditer(r'(?:href|src|action)\s*=\s*["\']([^"\'#]+)', body, re.I):
                link = m.group(1)
                if link.startswith("//"):
                    link = "https:" + link
                elif link.startswith("/"):
                    link = urljoin(url, link)
                elif not link.startswith("http"):
                    link = urljoin(url, link)
                found.add(link)
            # extraer endpoints de JS
            for m in re.finditer(r'["\'](/[a-zA-Z0-9._\-/]{2,80})["\']', body):
                path = m.group(1)
                if not any(path.endswith(ext) for ext in (".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf")):
                    found.add(urljoin(url, path))
            # API endpoints en JS
            for m in re.finditer(r'["\'](?:https?://[^"\']+/api/[^"\']*)["\']', body):
                found.add(m.group(0).strip("\"'"))
        except Exception:
            pass
        return found

    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(simple_crawl, u): u for u in alive}
        for f in as_completed(futs):
            all_urls |= f.result()

    # filtrar solo URLs del dominio objetivo
    domain_hosts = set()
    for u in alive:
        p = urlparse(u)
        if p.hostname:
            parts = p.hostname.split(".")
            if len(parts) >= 2:
                domain_hosts.add(".".join(parts[-2:]))

    filtered = set()
    for u in all_urls:
        try:
            p = urlparse(u)
            if p.hostname:
                host_parts = p.hostname.split(".")
                if len(host_parts) >= 2:
                    base = ".".join(host_parts[-2:])
                    if base in domain_hosts:
                        filtered.add(u)
        except Exception:
            pass

    with open(out_path, "w") as fp:
        for u in sorted(filtered):
            fp.write(u + "\n")

    print(f"    {len(filtered)} URLs descubiertas por crawling")
    return out_path


# ── params & endpoints (waybackurls, gau) ──────────────────────────────────

def params_phase(domain, alive, outdir, threads):
    out_path = os.path.join(outdir, "params.txt")
    all_urls = set()

    # waybackurls
    if has("waybackurls"):
        log("waybackurls -- URLs historicas de Wayback Machine")
        for url in alive:
            hostname = urlparse(url).hostname or domain
            out = shell(["waybackurls", hostname], timeout=120)
            for l in out.splitlines():
                l = l.strip()
                if l:
                    all_urls.add(l)
        print(f"    {len(all_urls)} URLs de Wayback")
    else:
        warn("waybackurls no instalado")

    # gau (GetAllUrls)
    if has("gau"):
        log("gau -- URLs de AlienVault OTX, Wayback, Common Crawl, URLScan")
        before_count = len(all_urls)
        for url in alive:
            hostname = urlparse(url).hostname or domain
            out = shell(["gau", "--threads", str(threads), hostname], timeout=120)
            for l in out.splitlines():
                l = l.strip()
                if l:
                    all_urls.add(l)
        print(f"    +{len(all_urls) - before_count} URLs nuevas de gau")
    else:
        warn("gau no instalado")

    # fallback: Wayback Machine API directa
    if not has("waybackurls") and not has("gau"):
        log("Consultando Wayback Machine API directamente")
        for url in alive:
            hostname = urlparse(url).hostname or domain
            try:
                r = sget(
                    f"https://web.archive.org/cdx/search/cdx?url=*.{hostname}/*&output=text&fl=original&collapse=urlkey",
                    timeout=30
                )
                for l in r.text.splitlines():
                    l = l.strip()
                    if l:
                        all_urls.add(l)
            except Exception:
                pass
        print(f"    {len(all_urls)} URLs de Wayback API")

    # extraer parametros unicos
    params_found = {}  # param_name -> set of example URLs
    for u in all_urls:
        try:
            parsed = urlparse(u)
            qs = parse_qs(parsed.query)
            for param in qs:
                if param not in params_found:
                    params_found[param] = set()
                if len(params_found[param]) < 3:
                    params_found[param].add(u)
        except Exception:
            pass

    # guardar
    with open(out_path, "w") as fp:
        fp.write(f"# MediWebScan -- params & endpoints\n")
        fp.write(f"# {len(all_urls)} URLs totales\n")
        fp.write(f"# {len(params_found)} parametros unicos\n\n")

        fp.write("== PARAMETROS ENCONTRADOS ==\n")
        for param in sorted(params_found):
            fp.write(f"\n  {param}:\n")
            for ex in list(params_found[param])[:3]:
                fp.write(f"    {ex}\n")

        fp.write(f"\n\n== TODAS LAS URLs ({len(all_urls)}) ==\n")
        for u in sorted(all_urls):
            fp.write(u + "\n")

    # URLs interesantes (con extensiones jugosas)
    juicy_exts = (".sql", ".bak", ".old", ".zip", ".tar", ".gz", ".env",
                  ".config", ".conf", ".log", ".xml", ".json", ".yaml",
                  ".yml", ".php.bak", ".swp", ".db", ".sqlite")
    juicy = [u for u in all_urls if any(u.lower().endswith(ext) for ext in juicy_exts)]

    juicy_path = os.path.join(outdir, "params_juicy.txt")
    if juicy:
        with open(juicy_path, "w") as fp:
            for u in sorted(juicy):
                fp.write(u + "\n")

    print(f"    {len(params_found)} parametros unicos")
    print(f"    {len(juicy)} URLs con extensiones jugosas")
    if juicy:
        for u in juicy[:15]:
            print(f"      {R}{u}{Z}")
        if len(juicy) > 15:
            print(f"      ... +{len(juicy) - 15} mas en {juicy_path}")

    return out_path


# ── nuclei ──────────────────────────────────────────────────────────────────

def nuclei_phase(alive, outdir, threads):
    if not has("nuclei"):
        warn("nuclei no instalado -- instalar: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        return ""

    if not alive:
        return ""

    out_path = os.path.join(outdir, "nuclei.txt")
    out_json = os.path.join(outdir, "nuclei.json")
    targets = os.path.join(outdir, "_nuclei_targets.tmp")
    Path(targets).write_text("\n".join(alive))

    log(f"nuclei -- escaneando {len(alive)} urls con templates de vulnerabilidades")
    log("Busca CVEs, misconfigs, exposures, default logins, etc.")
    warn("puede tardar bastante dependiendo del numero de targets")

    shell([
        "nuclei", "-l", targets, "-o", out_path, "-jsonl", out_json,
        "-c", str(threads), "-silent",
        "-severity", "info,low,medium,high,critical",
        "-retries", "2",
    ], timeout=1800)

    try:
        os.unlink(targets)
    except OSError:
        pass

    if os.path.isfile(out_path) and os.path.getsize(out_path) > 0:
        with open(out_path) as fp:
            for i, l in enumerate(fp):
                severity = ""
                ll = l.lower()
                if "critical" in ll:
                    severity = R
                elif "high" in ll:
                    severity = R
                elif "medium" in ll:
                    severity = Y
                else:
                    severity = ""
                print(f"    {severity}{l.rstrip()}{Z}")
                if i > 50:
                    print(f"    ... (ver {out_path})")
                    break
    else:
        print(f"    (sin hallazgos)")

    return out_path


# ── screenshots ─────────────────────────────────────────────────────────────

def screenshot_phase(alive, outdir, threads):
    if not alive:
        return ""

    ss_dir = os.path.join(outdir, "screenshots")
    os.makedirs(ss_dir, exist_ok=True)

    # gowitness
    if has("gowitness"):
        log(f"gowitness -- screenshots de {len(alive)} urls")
        targets = os.path.join(outdir, "_ss_targets.tmp")
        Path(targets).write_text("\n".join(alive))

        shell([
            "gowitness", "file", "-f", targets,
            "--screenshot-path", ss_dir,
            "--threads", str(min(threads, 10)),
            "--timeout", "15",
        ], timeout=600)

        try:
            os.unlink(targets)
        except OSError:
            pass

        # gowitness genera su propio report
        ss_files = list(Path(ss_dir).glob("*.png")) + list(Path(ss_dir).glob("*.jpg"))
        print(f"    {len(ss_files)} capturas guardadas en {ss_dir}/")

        # generar galeria HTML
        gallery = _build_gallery(alive, ss_dir, ss_files)
        return gallery or ss_dir

    # eyewitness
    if has("eyewitness"):
        log(f"eyewitness -- screenshots de {len(alive)} urls")
        targets = os.path.join(outdir, "_ss_targets.tmp")
        Path(targets).write_text("\n".join(alive))

        shell([
            "eyewitness", "-f", targets, "-d", ss_dir,
            "--timeout", "15", "--no-prompt",
        ], timeout=600)

        try:
            os.unlink(targets)
        except OSError:
            pass
        print(f"    capturas en {ss_dir}/")
        return ss_dir

    # fallback: cutycapt / wkhtmltoimage
    for tool in ("cutycapt", "wkhtmltoimage"):
        if has(tool):
            log(f"{tool} -- screenshots de {len(alive)} urls")
            for url in alive:
                hostname = urlparse(url).hostname or "unknown"
                out_file = os.path.join(ss_dir, f"{hostname}.png")
                if tool == "cutycapt":
                    shell(["cutycapt", f"--url={url}", f"--out={out_file}",
                           "--delay=3000"], timeout=30)
                else:
                    shell(["wkhtmltoimage", "--quality", "80", url, out_file],
                          timeout=30)
            ss_files = list(Path(ss_dir).glob("*.png"))
            print(f"    {len(ss_files)} capturas")
            gallery = _build_gallery(alive, ss_dir, ss_files)
            return gallery or ss_dir

    warn("sin herramienta de screenshots (instalar gowitness, eyewitness o cutycapt)")
    return ""


def _build_gallery(alive, ss_dir, ss_files):
    """genera un HTML simple con las capturas"""
    if not ss_files:
        return ""

    gallery_path = os.path.join(ss_dir, "gallery.html")
    imgs_html = ""
    for f in sorted(ss_files):
        name = f.stem
        imgs_html += f"""
        <div class="card">
            <h3>{html_mod.escape(name)}</h3>
            <a href="{html_mod.escape(f.name)}" target="_blank">
                <img src="{html_mod.escape(f.name)}" loading="lazy">
            </a>
        </div>"""

    html_content = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>MediWebScan Screenshots</title>
<style>
body {{ font-family: monospace; background: #1a1a2e; color: #e0e0e0; margin: 20px; }}
h1 {{ color: #00d4ff; }}
.grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 20px; }}
.card {{ background: #16213e; border-radius: 8px; padding: 15px; }}
.card h3 {{ color: #00d4ff; font-size: 14px; word-break: break-all; }}
.card img {{ width: 100%; border-radius: 4px; cursor: pointer; }}
</style></head><body>
<h1>MediWebScan -- Screenshots ({len(ss_files)})</h1>
<div class="grid">{imgs_html}</div>
</body></html>"""

    with open(gallery_path, "w") as fp:
        fp.write(html_content)
    return gallery_path


# ── reports ─────────────────────────────────────────────────────────────────

def write_report_txt(domain, outdir, data):
    rpt = os.path.join(outdir, "report.txt")
    with open(rpt, "w") as fp:
        fp.write(f"MediWebScan report -- {domain}\n")
        fp.write(f"date: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        fp.write(f"flags: {data.get('flags', '')}\n\n")
        fp.write(f"subdominios unicos: {data['total_subs']}\n")
        fp.write(f"vivos: {len(data['alive'])}\n\n")

        fp.write("-- alive --\n")
        for u in data["alive"]:
            fp.write(f"  {u}\n")

        for section, label in [
            ("waf_f", "WAF/CDN"), ("tech_f", "tech"), ("nmap_f", "puertos"),
            ("vuln_f", "vulns"), ("dirs_f", "directorios"), ("crawl_f", "crawl"),
            ("params_f", "params"), ("nuclei_f", "nuclei"), ("takeover_f", "takeover"),
        ]:
            fpath = data.get(section, "")
            if fpath and os.path.isfile(fpath):
                fp.write(f"\n-- {label} --\n")
                fp.write(Path(fpath).read_text())

        if data.get("hdr_f") and os.path.isfile(data["hdr_f"]):
            fp.write("\n-- security headers --\n")
            txt = Path(data["hdr_f"]).read_text()
            idx = txt.find("security headers")
            if idx >= 0:
                fp.write(txt[idx:])
    return rpt


def write_report_json(domain, outdir, data):
    rpt = os.path.join(outdir, "report.json")
    report = {
        "tool": "MediWebScan",
        "domain": domain,
        "date": datetime.now().isoformat(),
        "total_subdomains": data["total_subs"],
        "alive_count": len(data["alive"]),
        "alive": data["alive"],
        "flags": data.get("flags", ""),
    }

    # leer contenidos de cada archivo de resultados
    for key, label in [
        ("waf_f", "waf"), ("tech_f", "tech"), ("nmap_f", "nmap"),
        ("vuln_f", "vulns"), ("dirs_f", "directories"), ("crawl_f", "crawl"),
        ("params_f", "params"), ("nuclei_f", "nuclei"),
        ("takeover_f", "takeover"), ("hdr_f", "headers"),
    ]:
        fpath = data.get(key, "")
        if fpath and os.path.isfile(fpath):
            report[label] = Path(fpath).read_text()

    with open(rpt, "w") as fp:
        json.dump(report, fp, indent=2, ensure_ascii=False)
    return rpt


def write_report_html(domain, outdir, data):
    rpt = os.path.join(outdir, "report.html")

    sections_html = ""
    section_defs = [
        ("waf_f", "WAF / CDN", "🛡️"),
        ("hdr_f", "Cabeceras de Seguridad", "📋"),
        ("tech_f", "Tecnologías", "🔧"),
        ("takeover_f", "Subdomain Takeover", "⚠️"),
        ("nmap_f", "Puertos Abiertos", "🔌"),
        ("vuln_f", "Vulnerabilidades (nmap)", "🐛"),
        ("dirs_f", "Directorios", "📂"),
        ("crawl_f", "Crawl / Endpoints", "🕷️"),
        ("params_f", "Parámetros & URLs", "🔗"),
        ("nuclei_f", "Nuclei", "☢️"),
    ]

    for key, title, icon in section_defs:
        fpath = data.get(key, "")
        if fpath and os.path.isfile(fpath):
            content = Path(fpath).read_text()
            # colorear lineas criticas
            lines = []
            for l in content.splitlines():
                css = ""
                lu = l.upper()
                if any(k in lu for k in ("VULN", "CRITICAL", "[VULN]")):
                    css = "color:#ff4444;font-weight:bold"
                elif any(k in lu for k in ("HIGH", "WARNING", "[???]", "⚠")):
                    css = "color:#ffaa00"
                elif any(k in lu for k in ("MEDIUM",)):
                    css = "color:#ffdd57"
                elif any(k in lu for k in ("[+]", "OK", "limpio")):
                    css = "color:#44ff44"
                esc = html_mod.escape(l)
                if css:
                    lines.append(f'<span style="{css}">{esc}</span>')
                else:
                    lines.append(esc)
            body = "\n".join(lines)
            sections_html += f"""
            <div class="section" id="{key}">
                <h2>{icon} {title}</h2>
                <pre>{body}</pre>
            </div>"""

    # screenshots
    ss_dir = os.path.join(outdir, "screenshots")
    gallery_path = os.path.join(ss_dir, "gallery.html")
    if os.path.isfile(gallery_path):
        sections_html += f"""
        <div class="section" id="screenshots">
            <h2>📸 Screenshots</h2>
            <p><a href="screenshots/gallery.html" style="color:#00d4ff">Abrir galería de screenshots</a></p>
        </div>"""

    alive_rows = ""
    for u in data["alive"]:
        alive_rows += f"<tr><td><a href='{html_mod.escape(u)}' target='_blank'>{html_mod.escape(u)}</a></td></tr>\n"

    nav_links = ""
    for key, title, icon in section_defs:
        fpath = data.get(key, "")
        if fpath and os.path.isfile(fpath):
            nav_links += f'<a href="#{key}">{icon} {title}</a>\n'

    html_content = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>MediWebScan -- {html_mod.escape(domain)}</title>
<style>
:root {{
    --bg: #0a0a1a; --surface: #12122a; --surface2: #1a1a3e;
    --text: #e0e0e0; --dim: #888; --accent: #00d4ff; --green: #44ff44;
    --red: #ff4444; --orange: #ffaa00; --border: #2a2a4a;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: 'Courier New', monospace; background: var(--bg); color: var(--text); }}
header {{
    background: linear-gradient(135deg, var(--surface) 0%, var(--surface2) 100%);
    border-bottom: 2px solid var(--accent); padding: 30px; text-align: center;
}}
header h1 {{ color: var(--accent); font-size: 28px; }}
header p {{ color: var(--dim); margin-top: 8px; }}
.stats {{
    display: flex; gap: 30px; justify-content: center; margin-top: 20px; flex-wrap: wrap;
}}
.stat {{ text-align: center; }}
.stat .num {{ font-size: 36px; color: var(--accent); font-weight: bold; }}
.stat .label {{ color: var(--dim); font-size: 12px; text-transform: uppercase; }}
nav {{
    background: var(--surface); padding: 15px 30px; border-bottom: 1px solid var(--border);
    display: flex; gap: 15px; flex-wrap: wrap; position: sticky; top: 0; z-index: 100;
}}
nav a {{ color: var(--accent); text-decoration: none; font-size: 13px; white-space: nowrap; }}
nav a:hover {{ text-decoration: underline; }}
main {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
.section {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; margin: 20px 0; overflow: hidden;
}}
.section h2 {{
    background: var(--surface2); padding: 15px 20px; color: var(--accent);
    font-size: 16px; border-bottom: 1px solid var(--border);
}}
.section pre {{
    padding: 20px; overflow-x: auto; font-size: 13px; line-height: 1.6;
    max-height: 600px; overflow-y: auto;
}}
table {{ width: 100%; border-collapse: collapse; }}
td, th {{ padding: 8px 15px; text-align: left; border-bottom: 1px solid var(--border); }}
th {{ background: var(--surface2); color: var(--accent); font-size: 12px; text-transform: uppercase; }}
a {{ color: var(--accent); }}
footer {{ text-align: center; padding: 30px; color: var(--dim); font-size: 12px; }}
</style></head><body>

<header>
    <h1>🔍 MediWebScan</h1>
    <p>{html_mod.escape(domain)} — {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
    <div class="stats">
        <div class="stat"><div class="num">{data['total_subs']}</div><div class="label">subdominios</div></div>
        <div class="stat"><div class="num">{len(data['alive'])}</div><div class="label">vivos</div></div>
    </div>
</header>

<nav>{nav_links}</nav>

<main>
<div class="section">
    <h2>🌐 Hosts Vivos ({len(data['alive'])})</h2>
    <table>{alive_rows}</table>
</div>

{sections_html}
</main>

<footer>MediWebScan by medicineh — {datetime.now().strftime('%Y-%m-%d %H:%M')}</footer>
</body></html>"""

    with open(rpt, "w") as fp:
        fp.write(html_content)
    return rpt


# ── main ────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="MediWebScan -- full web recon",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ejemplos:
  %(prog)s example.com                     solo subdominios + fingerprint
  %(prog)s example.com -A                  TODO activado
  %(prog)s example.com -D -C -P            dirs + crawl + params
  %(prog)s example.com -A --stealth        todo con modo sigiloso
  %(prog)s example.com -p -v -D -N -S      puertos + vulns + dirs + nuclei + screenshots
        """)

    ap.add_argument("domain")

    # modulos
    ap.add_argument("-A", "--all", action="store_true",
                    help="activar TODO (ports, vuln, dirs, crawl, nuclei, screenshots, takeover, params)")
    ap.add_argument("-p", "--ports", action="store_true", help="nmap port scan")
    ap.add_argument("-v", "--vuln", action="store_true", help="nmap vuln scripts")
    ap.add_argument("-D", "--dirs", action="store_true", help="directory brute force")
    ap.add_argument("-C", "--crawl", action="store_true", help="crawl + JS endpoint discovery")
    ap.add_argument("-N", "--nuclei", action="store_true", help="nuclei vulnerability scan")
    ap.add_argument("-S", "--screenshots", action="store_true", help="screenshots de cada host vivo")
    ap.add_argument("-T", "--takeover", action="store_true", help="subdomain takeover check")
    ap.add_argument("-P", "--params", action="store_true", help="parameter & endpoint mining")

    # config
    ap.add_argument("-w", "--wordlist",
                    default="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
    ap.add_argument("--dir-wordlist",
                    default="/usr/share/seclists/Discovery/Web-Content/common.txt",
                    help="wordlist para dir brute")
    ap.add_argument("-t", "--threads", type=int, default=30)
    ap.add_argument("--no-color", action="store_true")

    # stealth
    ap.add_argument("--stealth", action="store_true",
                    help="modo sigiloso: User-Agent aleatorio + delays entre peticiones")
    ap.add_argument("--delay", type=float, default=None,
                    help="delay maximo entre peticiones en segundos (default: 2.0 en stealth)")

    args = ap.parse_args()

    # --all activa todo
    if args.all:
        args.ports = args.vuln = args.dirs = args.crawl = True
        args.nuclei = args.screenshots = args.takeover = args.params = True

    if args.no_color:
        global R, G, Y, C, B, D, Z
        R = G = Y = C = B = D = Z = ""

    # stealth config
    if args.stealth:
        STEALTH["enabled"] = True
        max_delay = args.delay if args.delay is not None else 2.0
        STEALTH["delay_min"] = max_delay * 0.3
        STEALTH["delay_max"] = max_delay
        log(f"Modo stealth activado: delay {STEALTH['delay_min']:.1f}-{STEALTH['delay_max']:.1f}s + UA aleatorio")

    domain = args.domain.lower().strip()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = f"recon_{domain}_{ts}"
    os.makedirs(outdir)

    flags_str = " ".join(f for f, v in [
        ("-p", args.ports), ("-v", args.vuln), ("-D", args.dirs),
        ("-C", args.crawl), ("-N", args.nuclei), ("-S", args.screenshots),
        ("-T", args.takeover), ("-P", args.params), ("--stealth", args.stealth),
    ] if v)

    print(f"""
{C}╔══════════════════════════════════════════════════════════╗
║  {B}MediWebScan{Z}{C}  --  full web recon                         ║
║  by medicineh                                            ║
╚══════════════════════════════════════════════════════════╝{Z}

  target:  {B}{domain}{Z}
  dir:     {outdir}/
  threads: {args.threads}
  flags:   {flags_str or '(basico)'}
""")

    # ── FASE 1: subdominios pasivos ─────────────────────────────────────────
    banner("FASE 1 — Enumeración pasiva de subdominios")
    subs = set()
    subs |= from_crtsh(domain)
    subs |= from_subfinder(domain)
    subs |= from_amass(domain)
    subs |= from_assetfinder(domain)

    # ── FASE 2: brute DNS ──────────────────────────────────────────────────
    banner("FASE 2 — Fuerza bruta DNS")
    subs |= brute_dns(domain, args.wordlist, args.threads)

    subs = {s for s in subs if s == domain or s.endswith(f".{domain}")}
    total = len(subs)
    log(f"Total: {total} subdominios unicos")
    Path(os.path.join(outdir, "subs_all.txt")).write_text("\n".join(sorted(subs)))

    # ── FASE 3: alive check ────────────────────────────────────────────────
    banner("FASE 3 — Alive check")
    alive = alive_check(subs, args.threads)
    Path(os.path.join(outdir, "subs_alive.txt")).write_text("\n".join(alive))

    # ── FASE 4: WAF / CDN ─────────────────────────────────────────────────
    banner("FASE 4 — Detección WAF / CDN")
    waf_f, waf_cache = waf_phase(alive, outdir, args.threads)

    # ── FASE 5: cabeceras ──────────────────────────────────────────────────
    banner("FASE 5 — Cabeceras HTTP + security headers")
    hdr_f = headers_phase(alive, outdir, args.threads)

    # ── FASE 6: tech ───────────────────────────────────────────────────────
    banner("FASE 6 — Fingerprinting de tecnologías")
    tech_f, tech_cache = tech_phase(alive, outdir, args.threads)

    # ── FASE 7: subdomain takeover ─────────────────────────────────────────
    takeover_f = ""
    if args.takeover:
        banner("FASE 7 — Subdomain Takeover check")
        takeover_f = takeover_phase(subs, alive, outdir, args.threads)
    else:
        banner("FASE 7 — Subdomain Takeover (saltado, usa -T)")

    # ── FASE 8: puertos ────────────────────────────────────────────────────
    nmap_f = ""
    if args.ports:
        banner("FASE 8 — Escaneo de puertos (nmap)")
        nmap_f = nmap_phase(alive, outdir, args.threads)
    else:
        banner("FASE 8 — Escaneo de puertos (saltado, usa -p)")

    # ── FASE 9: vulns ──────────────────────────────────────────────────────
    vuln_f = ""
    if args.vuln:
        if not args.ports:
            banner("FASE 8 — Escaneo de puertos (necesario para vulns)")
            nmap_f = nmap_phase(alive, outdir, args.threads)
        banner("FASE 9 — Vulnerabilidades (nmap scripts)")
        vuln_f = vuln_phase(outdir)
    else:
        banner("FASE 9 — Vulnerabilidades nmap (saltado, usa -v)")

    # ── FASE 10: dir brute ─────────────────────────────────────────────────
    dirs_f = ""
    if args.dirs:
        banner("FASE 10 — Fuerza bruta de directorios")
        dirs_f = dir_brute(alive, outdir, args.dir_wordlist, args.threads,
                           tech_cache, waf_cache)
    else:
        banner("FASE 10 — Directorios (saltado, usa -D)")

    # ── FASE 11: crawl ─────────────────────────────────────────────────────
    crawl_f = ""
    if args.crawl:
        banner("FASE 11 — Crawl + JS endpoint discovery")
        crawl_f = crawl_phase(alive, outdir, args.threads)
    else:
        banner("FASE 11 — Crawl (saltado, usa -C)")

    # ── FASE 12: params ────────────────────────────────────────────────────
    params_f = ""
    if args.params:
        banner("FASE 12 — Parameter & endpoint mining")
        params_f = params_phase(domain, alive, outdir, args.threads)
    else:
        banner("FASE 12 — Params (saltado, usa -P)")

    # ── FASE 13: nuclei ────────────────────────────────────────────────────
    nuclei_f = ""
    if args.nuclei:
        banner("FASE 13 — Nuclei vulnerability scan")
        nuclei_f = nuclei_phase(alive, outdir, args.threads)
    else:
        banner("FASE 13 — Nuclei (saltado, usa -N)")

    # ── FASE 14: screenshots ───────────────────────────────────────────────
    ss_f = ""
    if args.screenshots:
        banner("FASE 14 — Screenshots")
        ss_f = screenshot_phase(alive, outdir, args.threads)
    else:
        banner("FASE 14 — Screenshots (saltado, usa -S)")

    # ── reports ─────────────────────────────────────────────────────────────
    banner("Generando informes (TXT + JSON + HTML)")

    report_data = {
        "total_subs": total, "alive": alive, "flags": flags_str,
        "waf_f": waf_f, "hdr_f": hdr_f, "tech_f": tech_f,
        "takeover_f": takeover_f, "nmap_f": nmap_f, "vuln_f": vuln_f,
        "dirs_f": dirs_f, "crawl_f": crawl_f, "params_f": params_f,
        "nuclei_f": nuclei_f, "ss_f": ss_f,
    }

    rpt_txt = write_report_txt(domain, outdir, report_data)
    rpt_json = write_report_json(domain, outdir, report_data)
    rpt_html = write_report_html(domain, outdir, report_data)

    print(f"""
{G}{'═'*60}
  MediWebScan completado
{'═'*60}{Z}

  {B}{total}{Z} subdominios, {B}{len(alive)}{Z} vivos

  {C}Resultados:{Z}
    {outdir}/
    ├── report.txt
    ├── report.json
    ├── report.html    ← {B}abrir en navegador{Z}
    ├── subs_all.txt
    ├── subs_alive.txt""")
MediWebS
    if waf_f:
        print(f"    ├── waf.txt")
    if hdr_f:
        print(f"    ├── headers.txt")
    if tech_f:
        print(f"    ├── tech.txt")
    if takeover_f:
        print(f"    ├── takeover.txt")
    if nmap_f:
        print(f"    ├── nmap.txt / nmap.xml")
    if vuln_f:
        print(f"    ├── nmap_vuln.txt")
    if dirs_f:
        print(f"    ├── dirs.txt + dirs_per_host/")
    if crawl_f:
        print(f"    ├── crawl.txt")
    if params_f:
        print(f"    ├── params.txt + params_juicy.txt")
    if nuclei_f:
        print(f"    ├── nuclei.txt / nuclei.json")
    if ss_f:
        print(f"    └── screenshots/")

    print()


if __name__ == "__main__":
    main()
