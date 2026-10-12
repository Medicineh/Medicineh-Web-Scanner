# subrecon

Recon script that chains subdomain enumeration, alive checking, header analysis, tech fingerprinting, port scanning, vuln detection and directory bruteforce into one run. Drops everything into a timestamped folder with a summary report.

## Install

```bash
# deps
pip install requests dnspython

# external tools (optional, the script uses what it finds)
sudo pacman -S seclists nmap gobuster   # arch/cachyos
# or
sudo apt install seclists nmap gobuster # debian/ubuntu

# optional but recommended
# subfinder  -> go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# amass      -> go install github.com/owasp-amass/amass/v4/...@master
# assetfinder -> go install github.com/tomnomnom/assetfinder@latest
# httpx      -> go install github.com/projectdiscovery/httpx/cmd/httpx@latest
# whatweb    -> sudo apt install whatweb
```

## Usage

```bash
# basic recon (subdomain enum + alive check + headers + tech)
python subrecon.py target.com

# with port scanning
python subrecon.py target.com -p

# with vuln scripts (implies -p)
python subrecon.py target.com -v

# with directory bruteforce on alive hosts
python subrecon.py target.com -D

# everything
python subrecon.py target.com -p -v -D

# custom wordlists and threads
python subrecon.py target.com -p -v -D \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  --dir-wordlist /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -t 50
```

## Flags

```
domain              target domain
-p, --ports         nmap scan (top 1000, version detection)
-v, --vuln          nmap --script vuln (forces -p if not set)
-D, --dirs          gobuster dir on every alive url
-w, --wordlist      dns bruteforce wordlist (default: seclists top 5000)
--dir-wordlist      directory bruteforce wordlist (default: seclists common.txt)
-t, --threads       parallel threads (default: 30)
--no-color          disable terminal colors
```

## What each phase does

**Phase 1 -- Passive enum.** Pulls subdomains from public sources without touching the target. Uses crt.sh (certificate transparency logs), subfinder, amass and assetfinder. Each tool queries different APIs (Shodan, VirusTotal, SecurityTrails, Wayback Machine, etc). Skips whatever isn't installed.

**Phase 2 -- DNS bruteforce.** Takes a wordlist, prepends each word to the domain and queries DNS to see if it resolves. Uses gobuster dns mode, falls back to dnspython if gobuster isn't there. Runs with `--wildcard` so it doesn't abort on domains that respond to everything.

**Phase 3 -- Alive check.** Sends HTTP/HTTPS requests to every subdomain found to see which ones actually have a web server running. Uses httpx if available, otherwise does it with python requests.

**Phase 4 -- HTTP headers.** Grabs response headers from every alive url. Checks for missing security headers (HSTS, CSP, X-Frame-Options, XCTO, XSS-Protection, Permissions-Policy, Referrer-Policy) and prints a summary table.

**Phase 5 -- Tech fingerprint.** Identifies what's running behind each url: web server, CMS, framework, JS libraries. Uses whatweb if installed, otherwise parses headers and HTML looking for known signatures (WordPress, Django, Next.js, Cloudflare, etc).

**Phase 6 -- Port scan (-p).** Resolves alive hosts to IPs and runs nmap with `-sV -sC` on the top 1000 ports. Outputs both text and XML.

**Phase 7 -- Vuln scan (-v).** Second nmap pass with `--script vuln` against the same IPs. Tests for known CVEs, misconfigurations, XSS, SQLi, etc. Takes a while.

**Phase 8 -- Dir brute (-D).** Runs gobuster in dir mode against every alive url. Tries paths like `/admin`, `/login`, `/api`, `/backup` from the wordlist. Shows the first 20 hits per url on screen, full results go to the output file.

## Output

Everything goes into `recon_<domain>_<timestamp>/`:

```
subs_all.txt      all unique subdomains found
subs_alive.txt    subdomains that responded to HTTP
headers.txt       full headers + security header matrix
tech.txt          detected technologies per url
nmap.txt          port scan results (text)
nmap.xml          port scan results (xml, for tools like searchsploit)
nmap_vuln.txt     vulnerability scan results
nmap_vuln.xml     vulnerability scan results (xml)
dirs.txt          directory bruteforce results per url
ips.txt           resolved IPs
report.txt        summary of everything
```

## Tool priority

The script checks what's installed and picks the best available option. Nothing except python + requests is strictly required, but more tools = better coverage.

| Phase | Preferred | Fallback |
|---|---|---|
| Passive enum | subfinder + amass + assetfinder + crt.sh | crt.sh alone works |
| DNS brute | gobuster | dnspython |
| Alive check | httpx | python requests |
| Tech detect | whatweb | header + HTML parsing |
| Port/vuln scan | nmap | -- |
| Dir brute | gobuster | -- |

## Heads up

Only run this against domains you own or have written permission to test. Phases 2+ send real traffic to the target. The passive phase (1) doesn't touch the target at all.

## License

Do whatever you want with it.
