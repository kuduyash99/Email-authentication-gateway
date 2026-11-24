#!/usr/bin/env python3
"""Parse a raw email header and summarise its SPF, DKIM and DMARC results.

Reads the receiving server's Authentication-Results header (RFC 8601), falls
back to Received-SPF for SPF, and independently checks DMARC identifier
alignment between the From domain and the SPF / DKIM domains.

Alignment is relaxed (one domain equals, or is a subdomain of, the other).
No public-suffix list is used, so multi-part TLDs such as co.uk are not
special-cased.
"""
import argparse
import re
import sys
from email.parser import HeaderParser
from email.utils import parseaddr

COMMENT = re.compile(r"\(([^)]*)\)")
POLICY = re.compile(r"\bp=(\w+)", re.IGNORECASE)


def domain_of(address):
    """Return the lower-cased domain of an address or bare domain, or None."""
    domain = parseaddr(address or "")[1].rpartition("@")[2].lower()
    return domain or None


def is_aligned(auth_domain, from_domain):
    """Relaxed alignment per RFC 7489."""
    if not auth_domain or not from_domain:
        return False
    return (
        auth_domain == from_domain
        or auth_domain.endswith("." + from_domain)
        or from_domain.endswith("." + auth_domain)
    )


def parse_authentication_results(value):
    """Return (authserv_id, [{'method', 'result', 'props', 'comment'}, ...])."""
    parts = [p.strip() for p in " ".join(value.split()).split(";") if p.strip()]
    results = []
    for part in parts[1:]:
        comment = " ".join(COMMENT.findall(part))
        tokens = COMMENT.sub("", part).split()
        if not tokens or "=" not in tokens[0]:
            continue
        method, _, result = tokens[0].partition("=")
        props = dict(t.split("=", 1) for t in tokens[1:] if "=" in t)
        results.append(
            {"method": method.lower(), "result": result.lower(), "props": props, "comment": comment}
        )
    return parts[0] if parts else "", results


def analyze(msg):
    from_domain = domain_of(msg["From"])
    return_path = domain_of(msg["Return-Path"])
    summary = {"from_domain": from_domain, "return_path": return_path, "warnings": []}

    auth_header = msg["Authentication-Results"]  # topmost = added by the receiving server
    authserv, results = parse_authentication_results(auth_header) if auth_header else ("", [])
    if not auth_header:
        summary["warnings"].append("No Authentication-Results header found.")
    summary["authserv"] = authserv

    # SPF
    spf = next((r for r in results if r["method"] == "spf"), None)
    spf_result = spf["result"] if spf else None
    if not spf and msg["Received-SPF"]:
        spf_result = msg["Received-SPF"].split()[0].lower()
    spf_domain = return_path
    if spf:
        spf_domain = domain_of(spf["props"].get("smtp.mailfrom")) or domain_of(spf["props"].get("smtp.helo")) or return_path
    summary["spf"] = {
        "result": spf_result,
        "domain": spf_domain,
        "aligned": spf_result == "pass" and is_aligned(spf_domain, from_domain),
    }

    # DKIM (a message may carry several signatures)
    summary["dkim"] = [
        {
            "result": r["result"],
            "domain": (r["props"].get("header.d") or domain_of(r["props"].get("header.i")) or "").lower() or None,
            "selector": r["props"].get("header.s"),
            "aligned": r["result"] == "pass"
            and is_aligned(domain_of(r["props"].get("header.d") or r["props"].get("header.i")), from_domain),
        }
        for r in results
        if r["method"] == "dkim"
    ]
    if not summary["dkim"]:
        for sig in msg.get_all("DKIM-Signature", []):
            tags = dict(t.strip().split("=", 1) for t in sig.replace("\n", " ").split(";") if "=" in t)
            summary["dkim"].append(
                {"result": None, "domain": tags.get("d"), "selector": tags.get("s"), "aligned": False}
            )
        if summary["dkim"]:
            summary["warnings"].append("DKIM-Signature present but no verification result recorded.")

    # DMARC: what the receiver reported vs. what alignment implies
    dmarc = next((r for r in results if r["method"] == "dmarc"), None)
    policy = POLICY.search(dmarc["comment"]) if dmarc else None
    summary["dmarc"] = {
        "reported": dmarc["result"] if dmarc else None,
        "policy": policy.group(1).lower() if policy else None,
        "expected": "pass" if summary["spf"]["aligned"] or any(d["aligned"] for d in summary["dkim"]) else "fail",
    }
    if dmarc and dmarc["result"] != summary["dmarc"]["expected"]:
        summary["warnings"].append(
            f"Reported DMARC ({dmarc['result']}) differs from computed alignment ({summary['dmarc']['expected']})."
        )
    return summary


def render(s):
    yn = lambda b: "yes" if b else "no"
    lines = [
        f"From domain  : {s['from_domain']}",
        f"Return-Path  : {s['return_path']}",
        f"Checked by   : {s['authserv'] or 'unknown'}",
        "",
        f"SPF   : {s['spf']['result'] or 'none'}  (domain: {s['spf']['domain']}, aligned: {yn(s['spf']['aligned'])})",
    ]
    if not s["dkim"]:
        lines.append("DKIM  : none")
    for d in s["dkim"]:
        lines.append(
            f"DKIM  : {d['result'] or 'unverified'}  (d={d['domain']}, s={d['selector']}, aligned: {yn(d['aligned'])})"
        )
    m = s["dmarc"]
    lines.append(f"DMARC : {m['reported'] or 'none'}  (policy: {m['policy'] or 'n/a'}, alignment says: {m['expected']})")
    if s["warnings"]:
        lines += [""] + [f"WARNING: {w}" for w in s["warnings"]]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("file", nargs="?", help="file with the raw header/message (default: stdin)")
    args = parser.parse_args()

    raw = open(args.file, encoding="utf-8", errors="replace").read() if args.file else sys.stdin.read()
    print(render(analyze(HeaderParser().parsestr(raw, headersonly=True))))


if __name__ == "__main__":
    main()
