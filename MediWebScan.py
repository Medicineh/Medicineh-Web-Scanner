#!/usr/bin/env python3
"""
subrecon -- subdomain recon + fingerprinting.

pip install requests dnspython
"""

import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

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

# paleta
R = "\033[31m"
G = "\033[32m"
Y = "\033[33m"
C = "\033[36m"
B = "\033[1m"
Z = "\033[0m"


def log(msg):
    print(f"{G}[+]{Z} {msg}")


def warn(msg):
    print(f"{Y}[-]{Z} {msg}")


def banner(msg):
    print(f"\n{C}>> {msg}{Z}")


def has(bin_name):
    return shutil.which(bin_name) is not None


def shell(cmd, timeout=300):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    except Exception:
        return ""


# -- crt.sh ----------------------------------------------------------------

def from_crtsh(domain):
    log("crt.sh ...")
    found = set()
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30
        )
        for row in r.json():
            for name in row.get("name_value", "").split("\n"):
                name = name.strip().lower().replace("*.", "")
                if name.endswith(f".{domain}") or name == domain:
                    found.add(name)
    except Exception:
        warn("crt.sh no respondio")
    print(f"    {len(found)}")
    return found


# -- herramientas externas (pasivas) ----------------------------------------

def from_subfinder(domain):
    if not has("subfinder"):
        return set()
    log("subfinder ...")
    out = shell(["subfinder", "-d", domain, "-silent"])
    s = {l.strip().lower() for l in out.splitlines() if l.strip()}
    print(f"    {len(s)}")
    return s


def from_amass(domain):
    if not has("amass"):
        return set()
    log("amass (pasivo, 5min max) ...")
    out = shell(["amass", "enum", "-passive", "-d", domain], timeout=300)
    s = {l.strip().lower() for l in out.splitlines() if l.strip()}
    print(f"    {len(s)}")
    return s


def from_assetfinder(domain):
    if not has("assetfinder"):
        return set()
    log("assetfinder ...")
    out = shell(["assetfinder", "--subs-only", domain])
    s = set()
    for l in out.splitlines():
        l = l.strip().lower()
        if l.endswith(f".{domain}") or l == domain:
            s.add(l)
    print(f"    {len(s)}")
    return s


# -- brute DNS --------------------------------------------------------------

def brute_dns(domain, wordlist, threads):
    found = set()

    if has("gobuster") and os.path.isfile(wordlist):
        log(f"gobuster ({os.path.basename(wordlist)}) ...")
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

    # sin gobuster: dnspython
    if dns is None or not os.path.isfile(wordlist):
        warn("ni gobuster ni dnspython para brute -- skip")
        return found

    log(f"brute dns con dnspython ({os.path.basename(wordlist)}) ...")
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


# -- alive check -------------------------------------------------------------

def alive_check(subs, threads):
    urls = []

    if has("httpx"):
        log("httpx ...")
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
        log("probe manual (requests) ...")

        def try_sub(sub):
            for scheme in ("https", "http"):
                try:
                    requests.head(f"{scheme}://{sub}",
                                  timeout=5, allow_redirects=True, verify=False)
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


# -- cabeceras ---------------------------------------------------------------

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
        r = requests.head(url, timeout=10, allow_redirects=True, verify=False)
        return dict(r.headers)
    except Exception:
        return {}


def headers_phase(alive, outdir, threads):
    if not alive:
        return ""

    log(f"cabeceras de {len(alive)} urls ...")
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

    # tabla de seguridad
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


# -- tech detection ----------------------------------------------------------

# firmas basicas en html
SIGS = {
    "wp-content": "WordPress", "wp-includes": "WordPress",
    "joomla": "Joomla", "drupal": "Drupal", "shopify": "Shopify",
    "__next": "Next.js", "nuxt": "Nuxt.js",
    "angular": "Angular", "vue.js": "Vue.js",
    "laravel": "Laravel", "django": "Django", "flask": "Flask",
    "rails": "Rails", "bootstrap": "Bootstrap",
    "tailwindcss": "Tailwind", "jquery": "jQuery",
    "cloudflare": "Cloudflare",
}


def fingerprint(url):
    info = {"url": url, "server": "", "via": "", "stack": []}
    try:
        r = requests.get(url, timeout=10, allow_redirects=True, verify=False)
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
    if not alive:
        return ""

    out_path = os.path.join(outdir, "tech.txt")

    # whatweb si esta
    if has("whatweb"):
        log(f"whatweb ({len(alive)} urls) ...")
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
            return out_path

    # fallback propio
    log(f"fingerprint ({len(alive)} urls) ...")
    results = []
    with ThreadPoolExecutor(max_workers=threads) as pool:
        futs = {pool.submit(fingerprint, u): u for u in alive}
        for f in as_completed(futs):
            results.append(f.result())

    with open(out_path, "w") as fp:
        for t in sorted(results, key=lambda x: x["url"]):
            parts = [t["url"]]
            if t["server"]:
                parts.append(t["server"])
            if t["via"]:
                parts.append(t["via"])
            if t["stack"]:
                parts.append(", ".join(t["stack"]))
            line = " | ".join(parts)
            fp.write(line + "\n")
            print(f"    {line}")

    return out_path


# -- nmap --------------------------------------------------------------------

def nmap_phase(alive, outdir, threads):
    if not has("nmap"):
        warn("nmap no instalado")
        return ""

    log("resolviendo IPs ...")
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

    if not ips:
        warn("0 IPs resueltas")
        return ""
    print(f"    {len(ips)} IPs")

    ip_file = os.path.join(outdir, "ips.txt")
    Path(ip_file).write_text("\n".join(sorted(ips)))

    nmap_txt = os.path.join(outdir, "nmap.txt")
    nmap_xml = os.path.join(outdir, "nmap.xml")

    log("nmap top-1000 + version detection ...")
    warn("puede tardar")
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


# -- report ------------------------------------------------------------------

def write_report(domain, outdir, total, alive, hdr_f, tech_f, nmap_f, do_ports):
    rpt = os.path.join(outdir, "report.txt")
    with open(rpt, "w") as fp:
        fp.write(f"recon report -- {domain}\n")
        fp.write(f"date: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        fp.write(f"port scan: {'yes' if do_ports else 'no'}\n\n")
        fp.write(f"unique subdomains: {total}\n")
        fp.write(f"alive: {len(alive)}\n\n")

        fp.write("-- alive --\n")
        for u in alive:
            fp.write(f"  {u}\n")

        if tech_f and os.path.isfile(tech_f):
            fp.write("\n-- tech --\n")
            fp.write(Path(tech_f).read_text())

        if nmap_f and os.path.isfile(nmap_f):
            fp.write("\n-- open ports --\n")
            for l in Path(nmap_f).read_text().splitlines():
                if "/tcp" in l and "open" in l:
                    fp.write(f"  {l}\n")
                elif "Nmap scan report" in l:
                    fp.write(f"\n{l}\n")

        if hdr_f and os.path.isfile(hdr_f):
            fp.write("\n-- sec headers --\n")
            txt = Path(hdr_f).read_text()
            idx = txt.find("security headers")
            if idx >= 0:
                fp.write(txt[idx:])
    return rpt


# -- main --------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="subdomain recon")
    ap.add_argument("domain")
    ap.add_argument("-p", "--ports", action="store_true", help="nmap scan")
    ap.add_argument("-w", "--wordlist",
                    default="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
    ap.add_argument("-t", "--threads", type=int, default=30)
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    if args.no_color:
        global R, G, Y, C, B, Z
        R = G = Y = C = B = Z = ""

    domain = args.domain.lower().strip()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = f"recon_{domain}_{ts}"
    os.makedirs(outdir)

    print(f"\n{C}subrecon{Z} -- {B}{domain}{Z}")
    print(f"  dir: {outdir}/  threads: {args.threads}  ports: {args.ports}\n")

    # pasivo
    banner("passive enum")
    subs = set()
    subs |= from_crtsh(domain)
    subs |= from_subfinder(domain)
    subs |= from_amass(domain)
    subs |= from_assetfinder(domain)

    # brute
    banner("dns brute")
    subs |= brute_dns(domain, args.wordlist, args.threads)

    # limpiar
    subs = {s for s in subs if s == domain or s.endswith(f".{domain}")}
    total = len(subs)
    log(f"{total} subs unicos")
    Path(os.path.join(outdir, "subs_all.txt")).write_text("\n".join(sorted(subs)))

    # vivos
    banner("alive check")
    alive = alive_check(subs, args.threads)
    Path(os.path.join(outdir, "subs_alive.txt")).write_text("\n".join(alive))

    # headers
    banner("http headers")
    hdr_f = headers_phase(alive, outdir, args.threads)

    # tech
    banner("tech fingerprint")
    tech_f = tech_phase(alive, outdir, args.threads)

    # puertos
    nmap_f = ""
    if args.ports:
        banner("port scan")
        nmap_f = nmap_phase(alive, outdir, args.threads)
    else:
        banner("port scan (skipped, use -p)")

    # informe
    rpt = write_report(domain, outdir, total, alive, hdr_f, tech_f, nmap_f, args.ports)

    print(f"\n{G}done.{Z}")
    print(f"  {total} subs, {len(alive)} alive")
    print(f"  {outdir}/")
    print(f"  {rpt}\n")


if __name__ == "__main__":
    main()
