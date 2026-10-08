<div align="center">

<img src="https://readme-typing-svg.demolab.com/?font=Fira+Code&weight=700&size=34&pause=1000&color=F38020&center=true&vCenter=true&width=820&height=70&lines=Behind+The+Cloud;Find+the+real+IP+behind+Cloudflare;Discover+%E2%86%92+Filter+%E2%86%92+Prove" alt="Behind The Cloud" />

### `Behind The Cloud` — uncover the origin server hiding behind Cloudflare

<img src="https://img.shields.io/badge/python-3.9%2B-blue?logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/platform-Kali%20%7C%20Linux%20%7C%20Windows%20%7C%20macOS-success" />
<img src="https://img.shields.io/badge/license-MIT-green" />
<img src="https://img.shields.io/badge/sources-10%20(6%20key--less)-orange" />
<img src="https://img.shields.io/badge/false%20positives-none-brightgreen" />

<sub><b>Developed by Wasim Patel</b></sub>

</div>

---

```text
  ____       _     _           _   _____ _            ____ _                 _
 | __ )  ___| |__ (_)_ __   __| | |_   _| |__   ___  / ___| | ___  _   _  __| |
 |  _ \ / _ \ '_ \| | '_ \ / _` |   | | | '_ \ / _ \| |   | |/ _ \| | | |/ _` |
 | |_) |  __/ | | | | | | | (_| |   | | | | | |  __/| |___| | (_) | |_| | (_| |
 |____/ \___|_| |_|_|_| |_|\__,_|   |_| |_| |_|\___| \____|_|\___/ \__,_|\__,_|
```

When a site sits behind Cloudflare, a normal DNS lookup only ever returns a Cloudflare
edge IP — the real origin server stays hidden. **Behind The Cloud** automates the standard
techniques used in authorized penetration tests and bug-bounty recon to recover that
origin IP, then **proves** it by connecting to each candidate directly and comparing the
response to the live site. No guessing, no false positives.

> If it finds your own origin, so can an attacker — the fix is usually a firewall rule that
> only allows Cloudflare's IP ranges to reach the origin.

---

## 🚀 Quick start

```bash
# install (Kali / Linux)
git clone https://github.com/Cyberking0x1/behind-the-cloud.git
cd behind-the-cloud && bash install.sh

# find the origin
behindthecloud example.com            # one target
behindthecloud -f targets.txt         # many targets (one per line)
behindthecloud example.com -v         # verbose
```

Confirmed origins print in green with their IP; verify any hit with
`curl -sk --resolve example.com:443:<ORIGIN_IP> https://example.com/ -I`.
Only scan assets you own or are authorized to test.

---

## ⚡ One-step install

### 🐉 Kali / Linux / macOS

```bash
git clone <this-repo> behind-the-cloud && cd behind-the-cloud
bash install.sh
```

### 🪟 Windows (PowerShell)

```powershell
git clone <this-repo> behind-the-cloud; cd behind-the-cloud
powershell -ExecutionPolicy Bypass -File install.ps1
```

The installer puts the command on your PATH (via **pipx**, with safe fallbacks), so you can
run it **by name from any folder** — no need to `cd` into the project:

```bash
behindthecloud example.com
```

<sub>Prefer to do it yourself? `pipx install .` (recommended) or `pip install .` works too. On Kali, if pip complains about an "externally-managed environment", `install.sh` automatically falls back to a private virtualenv.</sub>

---

## 🚀 Usage

```bash
behindthecloud example.com                 # full scan (discover + prove)
behindthecloud api.example.com             # a subdomain — digs its whole parent zone
behindthecloud a.com b.com c.com           # several targets at once
behindthecloud -f targets.txt              # batch: one domain/URL per line
behindthecloud example.com -v              # show what every source found
behindthecloud example.com --json -o out.json   # machine-readable report (JSON array in batch)
behindthecloud example.com --no-validate   # list candidates, don't probe them
behindthecloud example.com --no-deep       # search only the exact host, not its zone
behindthecloud --setup                     # free API-key guide + status
```

**Single vs batch.** One target prints the full table; multiple targets (or `-f file`)
print a concise `domain → ORIGIN: ip,ip` line each, then a summary plus a flat,
copy-paste list of every confirmed origin IP. **Deep by default:** a subdomain is
searched across its whole registrable zone (`api.example.com` → the `example.com`
footprint) while the origin is still confirmed against the exact host you gave.

Run without installing at all:

```bash
python -m behindthecloud example.com
```

### Example output

```text
[>] Establishing baseline through the CDN edge
    edge IP(s): 104.18.x.x, 172.64.x.x
    fronting WAF/CDN: Cloudflare
    baseline: HTTP 200 | 161592B | title='Example Site'
[>] Collecting origin candidates from all sources
[+] 60 unique IP(s) gathered, 24 after removing Cloudflare edges
[>] Validating 24 candidate(s) by direct connection

[+] ORIGIN FOUND — 1 confirmed server(s):

  IP ADDRESS            CONF  VIA    SOURCES                     EVIDENCE
  --------------------------------------------------------------------------------
  203.0.113.47          100%  https  hackertarget,crt.sh         EXACT match | HTTP 200 | 161592B

[*] Verify manually, e.g.:
    curl -sk --resolve example.com:443:203.0.113.47 https://example.com/ -I
```

### Key options

| Option | Description |
|--------|-------------|
| `-t, --threads N`   | concurrent workers (default 40) |
| `--timeout S`       | per-HTTP-request timeout (default 10s) |
| `--dns-timeout S`   | per-DNS-lookup timeout (default 2s) |
| `--max-hosts N`     | cap on hostnames resolved per source (default 600) |
| `--budget S`        | hard wall-clock cap on the collection phase (default 90s) |
| `-w, --wordlist F`  | custom subdomain wordlist |
| `--no-validate`     | collect candidates only, skip direct probing |
| `-o, --output F`    | write a full JSON report |
| `--json`            | print JSON to stdout |
| `-v, --verbose`     | per-source detail |

Exit code is `0` when at least one origin is **confirmed**, otherwise `1`.

---

## 🧠 How it works

```text
  target domain
       │
       ▼
  ┌─────────────────────┐   Fetch the real site through Cloudflare, detect the
  │  1. Baseline + WAF   │   fronting CDN/WAF, and fingerprint the page
  │     fingerprint      │   (title, body hash, favicon hash, text tokens).
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐   crt.sh (+CertSpotter) · subdomain probing · MX/SPF DNS ·
  │  2. Candidate        │   HackerTarget · urlscan · Wayback · (Shodan/Censys/
  │     collection       │   SecurityTrails/OTX with free keys) — all concurrent.
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐   Drop every Cloudflare / CDN edge IP — those can
  │  3. Edge filtering   │   never be the origin.
  └─────────┬───────────┘
            ▼
  ┌─────────────────────┐   Connect to each candidate directly: compare its page
  │  4. Validation       │   to the baseline AND check its TLS certificate. A match
  │     (the proof)      │   = confirmed origin — even if the page is proxy-blocked.
  └─────────────────────┘
```

**Works through reverse proxies / WAFs.** Even when the real page can't be fetched to
build a baseline, a candidate that serves the target's **own TLS certificate** *and*
returns real content is confirmed as the origin. A server that only presents the cert
but rejects direct access (another CDN/SaaS edge) is surfaced as a *likely* lead, not a
false "confirmed".

### Discovery sources

| Source | API key | What it finds |
|--------|:-------:|---------------|
| `crt.sh` | no | Certificate Transparency hostnames (incl. pre-Cloudflare); falls back to **CertSpotter** |
| `subdomain-probe` | no | Operational subdomains (`ftp`, `cpanel`, `mail`, `direct`, `dev`…) that bypass the CDN |
| `dns-records` | no | MX hosts and SPF `ip4:` literals |
| `hackertarget` | no | Passive-DNS hostname→IP pairs |
| `urlscan` | no | IPs urlscan.io observed the site resolve to |
| `wayback` | no | Historical hostnames from the Internet Archive |
| `otx-passivedns` | free key | AlienVault OTX historical passive DNS |
| `securitytrails` | key | Historical A records — the most reliable pre-Cloudflare source |
| `shodan` | key | Raw IPs serving the target's TLS cert or an identical favicon |
| `censys` | key | Hosts presenting a certificate for the target domain |

**Six sources need no key** and are enough to crack many targets on their own.

---

## 🔑 Free API keys — set once, reused forever

The tool does **not** generate keys (that would violate the providers' terms) — every
provider below has a **free tier** you sign up for. `behindthecloud --setup` prints the
signup links and shows which keys you already have. Save them once:

```bash
behindthecloud --set-key OTX_API_KEY=xxxxxxxx
behindthecloud --set-key SHODAN_API_KEY=xxxxxxxx
behindthecloud --set-key CENSYS_API_ID=aaaa --set-key CENSYS_API_SECRET=bbbb
```

Keys are stored in `~/.behindthecloud/config.ini` (permissions `600`) and loaded
automatically. Priority: `--flag` > environment variable > saved config.

| Provider | Key(s) | Free tier |
|----------|--------|-----------|
| AlienVault OTX | `OTX_API_KEY` | Free — register, Settings → OTX API Key |
| Shodan | `SHODAN_API_KEY` | Free account gives a key; free academic upgrade with .edu |
| SecurityTrails | `SECURITYTRAILS_API_KEY` | Free plan includes DNS history (monthly quota) |
| Censys | `CENSYS_API_ID` + `CENSYS_API_SECRET` | Free/community tier (monthly quota) |

---

## 🎯 Accuracy — how a confirmation is earned (no false positives)

A candidate is reported as a **confirmed origin** only when the evidence is decisive —
by **either** of two independent methods:

- **Content match** — a *substantive* baseline **and** a real `2xx` from the candidate,
  with an **exact byte-for-byte body match** or several strong signals agreeing
  (favicon hash + title + body-text overlap).
- **TLS certificate match** — the candidate serves the target's own certificate (CN/SAN,
  wildcard-aware) **and** returns real content. This confirms the origin even when the
  page is blocked by a reverse proxy, so no baseline is available.
- **Likely (55–79%)** — e.g. an IP that serves the cert but rejects direct access
  (another CDN/SaaS edge, or a locked-down origin). A lead to verify, never a confirmation.
- Everything else is listed at its score but never called an origin.

Guards against the classic false positives:

- A candidate that **redirects to the public hostname** is not followed back through the
  CDN (pages *and* favicons), so it can't impersonate the origin.
- If the real homepage is a **tiny / generic / redirect** page, confirmations are
  downgraded to "likely".
- **Edge/CDN IPs** are removed before validation (Cloudflare by IP range, others by a
  time-bounded reverse-DNS check).

These rules are locked by an offline test suite:

```bash
python -m unittest discover -s tests -v
```

---

## 🛡️ Remediation (for defenders)

A discoverable origin is the finding. Lock it down:

- Allow inbound 80/443 **only** from [Cloudflare's IP ranges](https://www.cloudflare.com/ips/); drop everything else at the host/cloud firewall.
- Use **Cloudflare Tunnel** (`cloudflared`) so the origin has no public inbound exposure.
- Rotate the origin IP after locking down — old IPs live on in historical-DNS datasets.
- Don't serve the production TLS certificate from the origin on a public IP.

---

## ⚖️ Legal

Only run this against assets you **own or are explicitly authorized to test** (a signed
pentest engagement, an in-scope bug-bounty program, or your own infrastructure).
Validation makes direct HTTP requests to candidate servers. You are responsible for
staying within authorized scope.

---

<div align="center">
<sub>Behind The Cloud · MIT License · <b>Developed by Wasim Patel</b></sub>
</div>
