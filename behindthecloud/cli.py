"""Command-line interface for Behind The Cloud."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

from . import __version__, banner, config, console
from .engine import Config, Report, run

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
                        r"(\.[A-Za-z0-9-]{1,63})+$")


def _clean_domain(raw: str) -> str:
    # Strip BOM / zero-width chars (common on the first line of a Windows-saved file).
    raw = raw.replace("﻿", "").replace("​", "").strip().strip('"\'').lower()
    raw = re.sub(r"^https?://", "", raw)
    raw = raw.split("/")[0].split("?")[0].split(":")[0]
    if raw.startswith("www."):
        raw = raw[4:]
    return raw


def _collect_keys(args) -> dict:
    """Merge API keys. Priority: command-line flag > env var > saved config file."""
    keys = dict(config.load_keys())  # lowest priority: persisted config
    flags = {
        "SECURITYTRAILS_API_KEY": args.securitytrails_key,
        "SHODAN_API_KEY": args.shodan_key,
        "CENSYS_API_ID": args.censys_id,
        "CENSYS_API_SECRET": args.censys_secret,
        "OTX_API_KEY": args.otx_key,
    }
    for name in config.KEY_NAMES:
        env_val = os.environ.get(name)
        if env_val:
            keys[name] = env_val          # env overrides config
        if flags.get(name):
            keys[name] = flags[name]      # flag overrides env
    return keys


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="behindthecloud",
        description="Discover the origin server hiding behind Cloudflare.",
        epilog="API keys may also be supplied via the environment: "
               "SECURITYTRAILS_API_KEY, SHODAN_API_KEY, CENSYS_API_ID, "
               "CENSYS_API_SECRET, OTX_API_KEY.",
    )
    p.add_argument("domain", nargs="*",
                   help="one or more target domains/URLs, e.g. example.com api.example.com")
    p.add_argument("-f", "--file",
                   help="file with one domain/URL per line (batch mode)")
    p.add_argument("--no-deep", action="store_true",
                   help="search only the exact host, not its whole registrable zone")
    p.add_argument("-t", "--threads", type=int, default=40,
                   help="concurrent workers (default: 40)")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="per-HTTP-request timeout in seconds (default: 10)")
    p.add_argument("--dns-timeout", type=float, default=2.0,
                   help="per-DNS-lookup timeout in seconds (default: 2)")
    p.add_argument("--max-hosts", type=int, default=600,
                   help="cap on hostnames resolved per source (default: 600)")
    p.add_argument("--budget", type=float, default=90.0,
                   help="hard wall-clock cap for the collection phase (default: 90s)")
    p.add_argument("-w", "--wordlist",
                   help="custom subdomain wordlist (one name per line)")
    p.add_argument("--no-validate", action="store_true",
                   help="skip direct-connection validation (list candidates only)")
    p.add_argument("-o", "--output", help="write JSON report to this file")
    p.add_argument("--json", action="store_true",
                   help="print the report as JSON to stdout (implies --no-banner)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="show per-source detail")
    p.add_argument("--no-banner", action="store_true", help="suppress the banner")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("-V", "--version", action="version",
                   version=f"Behind The Cloud {__version__}")

    g = p.add_argument_group("API keys (optional, greatly improve results)")
    g.add_argument("--securitytrails-key", metavar="KEY")
    g.add_argument("--shodan-key", metavar="KEY")
    g.add_argument("--censys-id", metavar="ID")
    g.add_argument("--censys-secret", metavar="SECRET")
    g.add_argument("--otx-key", metavar="KEY")

    k = p.add_argument_group("key management")
    k.add_argument("--setup", action="store_true",
                   help="show where to get free API keys and which are configured")
    k.add_argument("--set-key", metavar="NAME=VALUE", action="append", default=[],
                   help="save a key to the config file, e.g. "
                        "--set-key SHODAN_API_KEY=abc123 (repeatable)")
    return p


def _baseline_dict(report: Report) -> dict:
    """JSON-safe view of the baseline fingerprint (drops the internal token set)."""
    b = report.baseline
    if not b:
        return None
    return {
        "ok": b.ok,
        "status": b.status,
        "title": b.title,
        "server": b.server,
        "body_len": b.body_len,
        "body_hash": b.body_hash,
        "favicon_hash": b.favicon_hash,
        "error": b.error,
    }


def _report_to_dict(report: Report) -> dict:
    return {
        "domain": report.domain,
        "behind_cloudflare": report.behind_cloudflare,
        "edge_waf": report.edge_waf,
        "edge_ips": report.edge_ips,
        "baseline": _baseline_dict(report),
        "candidate_count": report.candidate_count,
        "results": [
            {
                "ip": v.ip,
                "confidence": round(v.confidence, 3),
                "confirmed": v.confirmed,
                "likely": v.likely,
                "scheme": v.scheme,
                "sources": v.sources,
                "hostnames": v.hostnames,
                "cdn": v.cdn,
                "evidence": v.evidence,
            }
            for v in report.verdicts
        ],
    }


def _print_table(report: Report) -> None:
    print()
    confirmed = report.confirmed
    likely = report.likely

    if confirmed:
        console.good(f"ORIGIN FOUND — {len(confirmed)} confirmed server(s):")
    elif likely:
        console.warn("No confirmed origin, but likely candidate(s) below.")
    else:
        console.bad("No origin confirmed. For deeper coverage add free API keys — "
                    "run `behindthecloud --setup`.")

    shown = [v for v in report.verdicts if v.confidence > 0 or v.cdn] \
        or report.verdicts[:15]
    if not shown:
        return

    print()
    header = f"  {'IP ADDRESS':<20}{'CONF':>6}  {'VIA':<7}{'SOURCES':<32}EVIDENCE"
    print(console.c(header, "bold"))
    print(console.c("  " + "-" * 92, "grey"))
    for v in shown:
        pct = f"{int(v.confidence * 100)}%"
        if v.confirmed:
            style = ("green", "bold")
        elif v.likely:
            style = ("yellow",)
        elif v.cdn:
            style = ("grey",)
        else:
            style = ()
        src = ",".join(v.sources)[:30]
        ev = v.evidence[:34]
        if v.cdn:
            ev = f"[{v.cdn} edge] {ev}"[:34]
        line = f"  {v.ip:<20}{pct:>6}  {v.scheme or '-':<7}{src:<32}{ev}"
        print(console.c(line, *style))
    print()

    if confirmed:
        ips = " ".join(v.ip for v in confirmed)
        console.info("Verify manually, e.g.:")
        console.detail(f"curl -sk --resolve {report.domain}:443:{confirmed[0].ip} "
                       f"https://{report.domain}/ -I")
        console.detail(f"origin IP(s): {ips}")


def _print_setup(runtime_keys: dict) -> None:
    present = config.present_keys(runtime_keys)
    print(console.c("  Free API keys — set once, reused on every run", "bold"))
    print(console.c("  " + "-" * 64, "grey"))
    for prov in config.PROVIDERS:
        have = all(present.get(k) for k in prov["keys"])
        mark = console.c("configured", "green") if have else console.c("missing", "yellow")
        print(f"  {console.c(prov['name'], 'bold')}  [{mark}]")
        print(console.detail_str(f"signup : {prov['url']}"))
        print(console.detail_str(f"free   : {prov['free']}"))
        print(console.detail_str("env    : " + ", ".join(prov["keys"])))
        print()
    print(console.c("  Save a key (stored in " + str(config.CONFIG_FILE) + "):", "bold"))
    print(console.detail_str("behindthecloud --set-key SHODAN_API_KEY=xxxxxxxx"))
    print(console.detail_str("behindthecloud --set-key CENSYS_API_ID=xxxx "
                             "--set-key CENSYS_API_SECRET=yyyy"))
    print()
    console.info("The tool already works without any keys — these just widen coverage.")


def _gather_targets(args) -> list:
    """Collect, clean, validate and de-duplicate targets from args + optional file."""
    raw = list(args.domain or [])
    if args.file:
        try:
            with open(args.file, encoding="utf-8", errors="ignore") as fh:
                raw += [ln.strip() for ln in fh
                        if ln.strip() and not ln.lstrip().startswith("#")]
        except OSError as e:
            console.bad(f"could not read {args.file}: {e}")
    seen, out = set(), []
    for item in raw:
        d = _clean_domain(item)
        if not _DOMAIN_RE.match(d):
            console.warn(f"skipping invalid target: {item!r}")
            continue
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _write_json(path: str, data, as_json: bool) -> None:
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        if not as_json:
            console.good(f"JSON report written to {path}")
    except OSError as e:
        console.bad(f"could not write {path}: {e}")


def _print_batch_line(report: Report) -> None:
    name = report.domain
    if report.confirmed:
        ips = ", ".join(v.ip for v in report.confirmed[:8])
        extra = "" if len(report.confirmed) <= 8 else f" (+{len(report.confirmed) - 8} more)"
        print("  " + console.c(f"{name:38}", "bold")
              + console.c(f"ORIGIN: {ips}{extra}", "green", "bold"))
    elif report.likely:
        ips = ", ".join(v.ip for v in report.likely[:5])
        print("  " + f"{name:38}" + console.c(f"likely: {ips}", "yellow"))
    else:
        print("  " + f"{name:38}" + console.c("no origin confirmed", "grey"))


def _print_batch_summary(reports) -> None:
    found = [r for r in reports if r.confirmed]
    print()
    if found:
        console.good(f"{len(found)}/{len(reports)} target(s) with a confirmed origin")
    else:
        console.bad(f"0/{len(reports)} confirmed. Add free API keys (--setup) for depth.")
    # Flat, copy-paste-friendly list of every confirmed origin IP.
    all_ips = []
    for r in found:
        for v in r.confirmed:
            all_ips.append(v.ip)
    if all_ips:
        print()
        console.info("All confirmed origin IPs:")
        for ip in dict.fromkeys(all_ips):   # de-dup, keep order
            print(f"    {ip}")


def _apply_set_key(pairs) -> int:
    new = {}
    for pair in pairs:
        if "=" not in pair:
            console.bad(f"ignoring {pair!r} (expected NAME=VALUE)")
            continue
        name, _, value = pair.partition("=")
        name, value = name.strip().upper(), value.strip()
        if name not in config.KEY_NAMES:
            console.warn(f"ignoring unknown key {name!r}; known: "
                         + ", ".join(config.KEY_NAMES))
            continue
        if value:
            new[name] = value
    if not new:
        console.bad("no valid NAME=VALUE pairs given")
        return 2
    path = config.save_keys(new)
    console.good(f"saved {', '.join(new)} to {path}")
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    console.init_encoding()

    if args.no_color or args.json:
        console.set_color(False)
    as_json = args.json

    # Key-management modes run and exit before any scan.
    if args.set_key:
        return _apply_set_key(args.set_key)
    if args.setup:
        if not args.no_banner:
            print(banner.render(use_color=not args.no_color and sys.stdout.isatty()))
        _print_setup(_collect_keys(args))
        return 0

    if not as_json and not args.no_banner:
        print(banner.render(use_color=not args.no_color and sys.stdout.isatty()))

    targets = _gather_targets(args)
    if not targets:
        console.bad("no valid target given. Pass a domain (or -f file), or --setup.")
        return 2

    keys = _collect_keys(args)

    def make_cfg(domain: str) -> Config:
        return Config(
            domain=domain,
            threads=max(1, args.threads),
            timeout=args.timeout,
            dns_timeout=args.dns_timeout,
            max_hosts=max(1, args.max_hosts),
            collect_budget=max(5.0, args.budget),
            wordlist=args.wordlist,
            no_validate=args.no_validate,
            deep=not args.no_deep,
            keys=keys,
        )

    # ---- single target: full detailed output (unchanged behaviour) ----
    if len(targets) == 1:
        cfg = make_cfg(targets[0])
        if not as_json:
            console.info(f"Target: {console.c(targets[0], 'bold')}")
        try:
            report = run(cfg, verbose=args.verbose and not as_json)
        except KeyboardInterrupt:
            console.bad("interrupted")
            return 130
        data = _report_to_dict(report)
        if args.output:
            _write_json(args.output, data, as_json)
        if as_json:
            print(json.dumps(data, indent=2))
        else:
            _print_table(report)
        return 0 if report.confirmed else 1

    # ---- batch: many targets, one concise line each + summary ----
    if not as_json:
        console.info(f"Batch: {len(targets)} targets")
    reports = []
    for i, domain in enumerate(targets, 1):
        if not as_json:
            console.step(f"[{i}/{len(targets)}] {domain}")
        console.set_quiet(True)
        try:
            report = run(make_cfg(domain), verbose=False)
        except KeyboardInterrupt:
            console.set_quiet(False)
            console.bad("interrupted")
            break
        console.set_quiet(False)
        reports.append(report)
        if not as_json:
            _print_batch_line(report)

    if args.output:
        _write_json(args.output, [_report_to_dict(r) for r in reports], as_json)
    if as_json:
        print(json.dumps([_report_to_dict(r) for r in reports], indent=2))
    else:
        _print_batch_summary(reports)
    return 0 if any(r.confirmed for r in reports) else 1


if __name__ == "__main__":
    sys.exit(main())
