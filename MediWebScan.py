#!/usr/bin/env python3


#######
# dev by medicineh
#######

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
    log("Consultando crt.sh -- busca certificados SSL emitidos para el dominio en registros publicos (CT logs)")
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
        warn("crt.sh no respondio (puede estar caido, es normal)")
    print(f"    {len(found)} subdominios sacados de certificados")
    return found


# -- herramientas externas (pasivas) ----------------------------------------

def from_subfinder(domain):
    if not has("subfinder"):
        warn("subfinder no instalado, saltando -- consulta APIs de VirusTotal, SecurityTrails, Shodan, etc.")
        return set()
    log("Lanzando subfinder -- consulta docenas de APIs publicas en paralelo (Shodan, VirusTotal, SecurityTrails...)")
    out = shell(["subfinder", "-d", domain, "-silent"])
    s = {l.strip().lower() for l in out.splitlines() if l.strip()}
    print(f"    {len(s)} subdominios de APIs publicas")
    return s


def from_amass(domain):
    if not has("amass"):
        warn("amass no instalado, saltando -- el mas completo para OSINT de subdominios")
        return set()
    log("Lanzando amass en modo pasivo -- recopila datos de DNS, scraping web y APIs (max 5 min)")
    out = shell(["amass", "enum", "-passive", "-d", domain], timeout=300)
    s = {l.strip().lower() for l in out.splitlines() if l.strip()}
    print(f"    {len(s)} subdominios via OSINT")
    return s


def from_assetfinder(domain):
    if not has("assetfinder"):
        warn("assetfinder no instalado, saltando")
        return set()
    log("Lanzando assetfinder -- busca subdominios en Facebook CT, Wayback Machine, VirusTotal, etc.")
    out = shell(["assetfinder", "--subs-only", domain])
    s = set()
    for l in out.splitlines():
        l = l.strip().lower()
        if l.endswith(f".{domain}") or l == domain:
            s.add(l)
    print(f"    {len(s)} subdominios")
    return s


# -- brute DNS --------------------------------------------------------------

def brute_dns(domain, wordlist, threads):
    found = set()

    if has("gobuster") and os.path.isfile(wordlist):
        log(f"Probando nombres de subdominios por fuerza bruta con gobuster ({os.path.basename(wordlist)})")
        log(f"Cada palabra de la lista se prepone al dominio y se consulta al DNS para ver si existe")
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
        log("Comprobando con httpx cuales de los subdominios encontrados responden a peticiones HTTP/HTTPS")
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
        log("httpx no disponible, probando cada subdominio manualmente con requests (HTTPS primero, luego HTTP)")

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

    log(f"Pidiendo las cabeceras HTTP de {len(alive)} urls -- revela servidor, tecnologia y si faltan cabeceras de seguridad")
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
        log(f"Lanzando whatweb sobre {len(alive)} urls -- identifica CMS, frameworks, librerias JS, servidores web...")
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
    log(f"whatweb no disponible, analizando {len(alive)} urls con motor propio -- busca firmas en HTML y cabeceras")
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

    log("Convirtiendo los hostnames vivos a direcciones IP para pasarselas a nmap")
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

    log(f"Escaneando los 1000 puertos mas comunes en {len(ips)} IPs con deteccion de version (-sV -sC)")
    warn("puede tardar unos minutos dependiendo del numero de IPs")
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


# -- nmap vuln ---------------------------------------------------------------

def vuln_phase(outdir):
    """segundo pase de nmap con scripts de vulnerabilidades sobre las IPs ya escaneadas"""
    ip_file = os.path.join(outdir, "ips.txt")
    if not os.path.isfile(ip_file):
        warn("no hay ips.txt -- ejecuta con -p primero")
        return ""
    if not has("nmap"):
        warn("nmap no instalado")
        return ""

    vuln_txt = os.path.join(outdir, "nmap_vuln.txt")
    vuln_xml = os.path.join(outdir, "nmap_vuln.xml")

    log("Segundo pase de nmap con scripts de vulnerabilidades (--script vuln)")
    log("Prueba exploits conocidos contra los servicios detectados: XSS, SQLi, CVEs de versiones antiguas, etc.")
    warn("esto tarda bastante, puede ser 5-15 min por IP")
    shell([
        "nmap", "--script", "vuln", "--top-ports", "200", "-T4", "--open",
        "-iL", ip_file, "-oN", vuln_txt, "-oX", vuln_xml
    ], timeout=1800)

    if os.path.isfile(vuln_txt):
        log("resultados vuln:")
        with open(vuln_txt) as fp:
            for l in fp:
                stripped = l.strip()
                # solo lineas con CVE, VULNERABLE, o estado de script
                if any(k in stripped.upper() for k in ("VULNERABLE", "CVE-", "STATE:", "| ", "|_")):
                    print(f"    {l.rstrip()}")
    return vuln_txt


# -- dir brute ---------------------------------------------------------------

def dir_brute(alive, outdir, dir_wordlist, threads):
    if not alive:
        warn("no hay urls vivas")
        return ""
    if not has("gobuster"):
        warn("gobuster no instalado")
        return ""
    if not os.path.isfile(dir_wordlist):
        warn(f"wordlist no encontrada: {dir_wordlist}")
        return ""

    out_path = os.path.join(outdir, "dirs.txt")
    log(f"Buscando directorios y archivos ocultos en {len(alive)} urls con gobuster modo dir")
    log(f"Wordlist: {os.path.basename(dir_wordlist)} -- prueba rutas como /admin, /login, /backup, /api, etc.")

    with open(out_path, "w") as fp:
        for url in alive:
            log(f"  {url}")
            fp.write(f"\n--- {url} ---\n")

            out = shell([
                "gobuster", "dir", "-u", url,
                "-w", dir_wordlist,
                "-t", str(threads),
                "--no-color", "-q",
                "-s", "200,204,301,302,307,401,403",
                "--timeout", "10s",
                "-k",  # skip tls verify
            ], timeout=300)

            if not out.strip():
                fp.write("  (nada)\n")
                print("      (nada)")
                continue

            count = 0
            for l in out.splitlines():
                l = l.strip()
                if l and not l.startswith("Error"):
                    fp.write(f"  {l}\n")
                    count += 1
                    if count <= 20:
                        print(f"      {l}")
            if count > 20:
                print(f"      ... +{count - 20} mas (ver {out_path})")

    return out_path


# -- report ------------------------------------------------------------------

def write_report(domain, outdir, total, alive, hdr_f, tech_f, nmap_f,
                  vuln_f, dirs_f, do_ports, do_vuln, do_dirs):
    rpt = os.path.join(outdir, "report.txt")
    with open(rpt, "w") as fp:
        fp.write(f"recon report -- {domain}\n")
        fp.write(f"date: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
        fp.write(f"port scan: {'yes' if do_ports else 'no'}")
        fp.write(f"  vuln: {'yes' if do_vuln else 'no'}")
        fp.write(f"  dirs: {'yes' if do_dirs else 'no'}\n\n")
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

        if vuln_f and os.path.isfile(vuln_f):
            fp.write("\n-- vulns --\n")
            for l in Path(vuln_f).read_text().splitlines():
                up = l.strip().upper()
                if any(k in up for k in ("VULNERABLE", "CVE-", "| ", "|_", "NMAP SCAN REPORT")):
                    fp.write(f"  {l}\n")

        if dirs_f and os.path.isfile(dirs_f):
            fp.write("\n-- directories --\n")
            fp.write(Path(dirs_f).read_text())

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
    ap.add_argument("-v", "--vuln", action="store_true", help="nmap vuln scripts")
    ap.add_argument("-D", "--dirs", action="store_true", help="directory brute on alive hosts")
    ap.add_argument("-w", "--wordlist",
                    default="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
    ap.add_argument("--dir-wordlist",
                    default="/usr/share/seclists/Discovery/Web-Content/common.txt",
                    help="wordlist para dir brute")
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
    print(f"  dir: {outdir}/  threads: {args.threads}")
    print(f"  ports: {args.ports}  vuln: {args.vuln}  dirs: {args.dirs}\n")

    # pasivo
    banner("FASE 1 -- Enumeracion pasiva (sin tocar el servidor, solo fuentes publicas)")
    subs = set()
    subs |= from_crtsh(domain)
    subs |= from_subfinder(domain)
    subs |= from_amass(domain)
    subs |= from_assetfinder(domain)

    # brute
    banner("FASE 2 -- Fuerza bruta DNS (se envian consultas DNS, deja rastro)")
    subs |= brute_dns(domain, args.wordlist, args.threads)

    # limpiar
    subs = {s for s in subs if s == domain or s.endswith(f".{domain}")}
    total = len(subs)
    log(f"Total tras juntar todas las fuentes y quitar duplicados: {total} subdominios unicos")
    Path(os.path.join(outdir, "subs_all.txt")).write_text("\n".join(sorted(subs)))

    # vivos
    banner("FASE 3 -- Comprobar cuales de esos subdominios tienen un servidor web activo")
    alive = alive_check(subs, args.threads)
    Path(os.path.join(outdir, "subs_alive.txt")).write_text("\n".join(alive))

    # headers
    banner("FASE 4 -- Cabeceras HTTP (que servidor usan, que cabeceras de seguridad faltan)")
    hdr_f = headers_phase(alive, outdir, args.threads)

    # tech
    banner("FASE 5 -- Que tecnologias corren detras (CMS, frameworks, librerias)")
    tech_f = tech_phase(alive, outdir, args.threads)

    # puertos
    nmap_f = ""
    if args.ports:
        banner("FASE 6 -- Escaneo de puertos con nmap (que servicios estan expuestos)")
        nmap_f = nmap_phase(alive, outdir, args.threads)
    else:
        banner("FASE 6 -- Escaneo de puertos (saltado, usa -p para activar)")

    # vulns
    vuln_f = ""
    if args.vuln:
        if not args.ports:
            banner("FASE 6 -- Escaneo de puertos (necesario antes de buscar vulns)")
            nmap_f = nmap_phase(alive, outdir, args.threads)
        banner("FASE 7 -- Busqueda de vulnerabilidades con nmap scripts (CVEs, misconfigs)")
        vuln_f = vuln_phase(outdir)
    else:
        banner("FASE 7 -- Busqueda de vulnerabilidades (saltado, usa -v para activar)")

    # directorios
    dirs_f = ""
    if args.dirs:
        banner("FASE 8 -- Fuerza bruta de directorios (busca rutas ocultas en cada web viva)")
        dirs_f = dir_brute(alive, outdir, args.dir_wordlist, args.threads)
    else:
        banner("FASE 8 -- Fuerza bruta de directorios (saltado, usa -D para activar)")

    # informe
    rpt = write_report(domain, outdir, total, alive, hdr_f, tech_f, nmap_f,
                       vuln_f, dirs_f, args.ports, args.vuln, args.dirs)

    print(f"\n{G}done.{Z}")
    print(f"  {total} subs, {len(alive)} alive")
    print(f"  {outdir}/")
    print(f"  {rpt}\n")


if __name__ == "__main__":
    main()
