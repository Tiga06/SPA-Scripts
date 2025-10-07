#!/usr/bin/env python3
"""
dnssec_deep_audit.py
Single-domain, research-grade DNSSEC deep auditor.

Outputs (in ~/Downloads by default):
 - JSON: detailed machine-readable output
 - CSV: one-line summary (domain, validated_chain, reasons, timestamp)
 - TXT: human-readable audit report

Requirements:
  pip3 install dnspython colorama

Usage:
  python3 dnssec_deep_audit.py -d example.com
  python3 dnssec_deep_audit.py -d example.com --resolver 8.8.8.8
"""

from __future__ import annotations
import argparse
import csv
import json
import os
import sys
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import dns.name
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver
import dns.dnssec
import dns.rrset

# Optional coloring
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    C_OK = Fore.GREEN + Style.BRIGHT
    C_ERR = Fore.RED + Style.BRIGHT
    C_WARN = Fore.YELLOW + Style.BRIGHT
    C_RST = Style.RESET_ALL
except Exception:
    C_OK = C_ERR = C_WARN = C_RST = ""

# Config
RESOLVE_TIMEOUT = 6.0
DOWNLOADS = os.path.expanduser("~/Downloads")
FALLBACK_RESOLVERS = ["8.8.8.8", "1.1.1.1"]

def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

def hexify(x: Any) -> Optional[str]:
    if x is None:
        return None
    if isinstance(x, bytes):
        return x.hex().upper()
    try:
        return str(x).upper()
    except Exception:
        return None

def choose_resolvers(user_resolver: Optional[str] = None) -> List[str]:
    if user_resolver:
        return [user_resolver]
    try:
        sysr = dns.resolver.get_default_resolver()
        if sysr.nameservers:
            return list(sysr.nameservers)
    except Exception:
        pass
    return FALLBACK_RESOLVERS

def perform_query(qname: str, rdtype: int, resolver_ip: Optional[str] = None, want_dnssec: bool = True) -> Tuple[Optional[dns.message.Message], Optional[str], Optional[str]]:
    """
    Query qname for rdtype. Try UDP then TCP. Return (response, used_resolver_ip, error_str).
    """
    resolvers = choose_resolvers(resolver_ip)
    last_err = None
    for ip in resolvers:
        try:
            q = dns.message.make_query(qname, rdtype, want_dnssec=want_dnssec)
            try:
                resp = dns.query.udp(q, ip, timeout=RESOLVE_TIMEOUT)
                if resp.flags & dns.flags.TC:
                    resp = dns.query.tcp(q, ip, timeout=RESOLVE_TIMEOUT)
                return resp, ip, None
            except Exception:
                # try TCP
                resp = dns.query.tcp(q, ip, timeout=RESOLVE_TIMEOUT)
                return resp, ip, None
        except Exception as e:
            last_err = e
            continue
    return None, None, str(last_err)

def extract_rrset(resp: dns.message.Message, qname: str, rdtype: int) -> Optional[dns.rrset.RRset]:
    if resp is None:
        return None
    lname = dns.name.from_text(qname)
    for section in (resp.answer, resp.authority, resp.additional):
        for rr in section:
            if rr.name == lname and rr.rdtype == rdtype:
                return rr
    return None

def get_rrsets(zone: str, resolver_ip: Optional[str] = None) -> Dict[str, Any]:
    """
    Fetch several rrsets for zone (DNSKEY, RRSIG, DS, NSEC, NSEC3, CDS/CDNSKEY)
    Returns dictionary of rrsets (may be None) and resolver used / errors
    """
    out = {"resolver": None, "errors": []}
    # DNSKEY + RRSIG
    resp, used, err = perform_query(zone, dns.rdatatype.DNSKEY, resolver_ip=resolver_ip, want_dnssec=True)
    out["resolver"] = used
    if err:
        out["errors"].append(f"DNSKEY query error: {err}")
    out["dnskey_rrset"] = extract_rrset(resp, zone, dns.rdatatype.DNSKEY)
    out["rrsig_dnskey_rrset"] = extract_rrset(resp, zone, dns.rdatatype.RRSIG)

    # DS from parent (use parent zone query)
    resp_ds, used_ds, err_ds = perform_query(zone, dns.rdatatype.DS, resolver_ip=resolver_ip, want_dnssec=True)
    out["parent_ds_rrset"] = extract_rrset(resp_ds, zone, dns.rdatatype.DS) if resp_ds else None
    if err_ds:
        out["errors"].append(f"Parent DS query error: {err_ds}")

    # NSEC / NSEC3 (existence)
    resp_nsec, _, _ = perform_query(zone, dns.rdatatype.NSEC, resolver_ip=resolver_ip, want_dnssec=True)
    resp_nsec3, _, _ = perform_query(zone, dns.rdatatype.NSEC3, resolver_ip=resolver_ip, want_dnssec=True)
    resp_nsec3param, _, _ = perform_query(zone, dns.rdatatype.NSEC3PARAM, resolver_ip=resolver_ip, want_dnssec=True)
    out["nsec_rrset"] = extract_rrset(resp_nsec, zone, dns.rdatatype.NSEC) if resp_nsec else None
    out["nsec3_rrset"] = extract_rrset(resp_nsec3, zone, dns.rdatatype.NSEC3) if resp_nsec3 else None
    out["nsec3param_rrset"] = extract_rrset(resp_nsec3param, zone, dns.rdatatype.NSEC3PARAM) if resp_nsec3param else None

    # CDS and CDNSKEY (child-submission records)
    resp_cds, _, _ = perform_query(zone, dns.rdatatype.CDS, resolver_ip=resolver_ip, want_dnssec=True)
    resp_cdns, _, _ = perform_query(zone, dns.rdatatype.CDNSKEY, resolver_ip=resolver_ip, want_dnssec=True)
    out["cds_rrset"] = extract_rrset(resp_cds, zone, dns.rdatatype.CDS) if resp_cds else None
    out["cdnskey_rrset"] = extract_rrset(resp_cdns, zone, dns.rdatatype.CDNSKEY) if resp_cdns else None

    return out

def dnskey_list(rrset: Optional[dns.rrset.RRset]) -> List[Any]:
    if rrset is None:
        return []
    return list(rrset)

def build_keymap(dnskey_rrset: dns.rrset.RRset) -> Dict[dns.name.Name, Dict[int, Any]]:
    """
    Build the keymap expected by dns.dnssec.validate: {owner_name: {key_tag: dnskey_rdata, ...}}
    """
    keymap: Dict[dns.name.Name, Dict[int, Any]] = {}
    if dnskey_rrset is None:
        return keymap
    owner = dnskey_rrset.name
    inner: Dict[int, Any] = {}
    for r in dnskey_list(dnskey_rrset):
        try:
            kt = dns.dnssec.key_id(r)
        except Exception:
            kt = getattr(r, "key_tag", None)
        inner[int(kt) if kt is not None else 0] = r
    keymap[owner] = inner
    return keymap

def validate_rrsigs_over_rrset(rrset: dns.rrset.RRset, rrsig_rrset: Optional[dns.rrset.RRset], keymap: Dict[dns.name.Name, Dict[int, Any]]) -> List[Dict[str, Any]]:
    """
    Validate each RRSIG inside rrsig_rrset over rrset using keymap.
    Returns list with validity info per RRSIG.
    """
    results: List[Dict[str, Any]] = []
    if rrset is None:
        return results
    if rrsig_rrset is None:
        return results
    # rrsig_rrset contains RRSIG rdata objects; validate per-sig using a temp rrset with only that rrsig
    for rrsig in rrsig_rrset:
        info = {
            "signer": getattr(rrsig, "signer", None).to_text() if hasattr(rrsig, "signer") else str(getattr(rrsig, "signer", None)),
            "type_covered": getattr(rrsig, "type_covered", None),
            "key_tag": getattr(rrsig, "key_tag", None),
            "inception": getattr(rrsig, "inception", None),
            "expiration": getattr(rrsig, "expiration", None),
            "valid": False,
            "error": None
        }
        try:
            # build an RRset containing only the rrsig (same owner and rdclass/rdtype as rrsig_rrset)
            temp_rrsigset = dns.rrset.RRset(rrsig_rrset.name, rrsig_rrset.rdclass, rrsig_rrset.rdtype)
            temp_rrsigset.add(rrsig)
            dns.dnssec.validate(rrset, temp_rrsigset, keymap)
            info["valid"] = True
        except Exception as e:
            info["error"] = str(e)
        results.append(info)
    return results

def compute_ds_list(zone_name: dns.name.Name, dnskey_rrset: Optional[dns.rrset.RRset]) -> List[Dict[str, Any]]:
    """
    Compute DS (SHA-1 and SHA-256) for each DNSKEY rdata in dnskey_rrset.
    Returns list of dicts {key_tag, algorithm, digest_type, digest, error}
    """
    out: List[Dict[str, Any]] = []
    if dnskey_rrset is None:
        return out
    for r in dnskey_list(dnskey_rrset):
        # compute ds for types 1 and 2
        for dt in (1, 2):
            try:
                ds = dns.dnssec.make_ds(dns.name.from_text(zone_name.to_text() if zone_name != dns.name.root else ""), r, dt)
                out.append({
                    "key_tag": getattr(ds, "key_tag", None) or getattr(r, "key_tag", None) or None,
                    "algorithm": getattr(ds, "algorithm", getattr(r, "algorithm", None)),
                    "digest_type": getattr(ds, "digest_type", dt),
                    "digest": hexify(getattr(ds, "digest", None)),
                    "error": None
                })
            except Exception as e:
                # Some libraries/policies may refuse SHA-1; capture error text
                out.append({
                    "key_tag": getattr(r, "key_tag", None),
                    "algorithm": getattr(r, "algorithm", None),
                    "digest_type": dt,
                    "digest": None,
                    "error": str(e)
                })
    return out

def get_authoritative_ns(zone: str) -> Tuple[List[str], Optional[str]]:
    try:
        ans = dns.resolver.resolve(zone, "NS", lifetime=RESOLVE_TIMEOUT)
        if ans.rrset is None:
            return [], None
        return [str(x.target).rstrip('.') for x in ans.rrset], None
    except Exception as e:
        return [], str(e)

def resolve_name_ips(name: str) -> List[str]:
    ips: List[str] = []
    try:
        a = dns.resolver.resolve(name, "A", lifetime=RESOLVE_TIMEOUT)
        if a.rrset:
            ips.extend([x.to_text() for x in a.rrset])
    except Exception:
        pass
    try:
        a6 = dns.resolver.resolve(name, "AAAA", lifetime=RESOLVE_TIMEOUT)
        if a6.rrset:
            ips.extend([x.to_text() for x in a6.rrset])
    except Exception:
        pass
    return ips

def check_authoritative_ns_consistency(zone: str) -> Dict[str, Any]:
    ns_list, ns_err = get_authoritative_ns(zone)
    report = {"ns": [], "ns_error": ns_err, "consistent": True, "fingerprint_groups": {}}
    fingerprints = {}
    for ns in ns_list:
        ips = resolve_name_ips(ns)
        dnskey_tags: List[int] = []
        queried_ip = None
        error_text = None
        for ip in ips:
            got = get_rrsets(zone, resolver_ip=ip)
            rr = got.get("dnskey_rrset")
            if rr:
                dnskey_tags = []
                for r in dnskey_list(rr):
                    try:
                        kt = dns.dnssec.key_id(r)
                    except Exception:
                        kt = getattr(r, "key_tag", None)
                    if kt is not None:
                        dnskey_tags.append(int(kt))
                queried_ip = ip
                break
        if not dnskey_tags:
            error_text = f"No DNSKEY from NS {ns}"
            report["consistent"] = False
        report_entry = {"ns": ns, "ips": ips, "queried_ip": queried_ip, "dnskey_tags": dnskey_tags, "error": error_text}
        report["ns"].append(report_entry)
        key = tuple(sorted(dnskey_tags))
        fingerprints.setdefault(key, []).append(ns)
    # fingerprint groups
    report["fingerprint_groups"] = {",".join(map(str,k)) : v for k,v in fingerprints.items()}
    if len(fingerprints.keys()) > 1:
        report["consistent"] = False
    return report

# ---------- High level audit for one domain ----------
def analyze_domain(domain: str, resolver_override: Optional[str] = None, check_ns: bool = True) -> Dict[str, Any]:
    """
    Deep analysis for a single domain (research-grade). Returns a detailed dict ready for JSON serialization.
    """
    out: Dict[str, Any] = {
        "domain": domain,
        "timestamp": now_ts(),
        "zones": [],
        "ns_consistency": None,
        "errors": []
    }
    # Walk from domain up to root
    qname = dns.name.from_text(domain)
    cur = qname
    resolvers = choose_resolvers(resolver_override)

    while True:
        zone_text = cur.to_text() if cur != dns.name.root else "."
        zone_obj: Dict[str, Any] = {
            "zone": zone_text,
            "resolver_used": None,
            "dnskey_rdataset_text": None,
            "dnskey_entries": [],
            "dnskey_rrsigs": [],
            "computed_ds": [],
            "parent_ds": None,
            "parent_ds_resolver": None,
            "parent_ds_matches_computed": False,
            "nsec": None,
            "nsec3": None,
            "cds": None,
            "cdnskey": None,
            "error": None
        }

        # fetch rrsets (prefer system/resolver_override)
        try:
            got = get_rrsets(zone_text, resolver_ip=resolver_override)
            zone_obj["resolver_used"] = got.get("resolver")
            dnskey_rrset = got.get("dnskey_rrset")
            rrsig_rrset = got.get("rrsig_dnskey_rrset")
            zone_obj["dnskey_rdataset_text"] = [r.to_text() for r in dnskey_rrset] if dnskey_rrset else None
            # DNSKEY entries (detailed)
            if dnskey_rrset:
                for r in dnskey_list(dnskey_rrset):
                    try:
                        kt = dns.dnssec.key_id(r)
                    except Exception:
                        kt = getattr(r, "key_tag", None)
                    zone_obj["dnskey_entries"].append({
                        "key_tag": int(kt) if kt is not None else None,
                        "flags": int(getattr(r, "flags", -1)),
                        "protocol": int(getattr(r, "protocol", -1)),
                        "algorithm": int(getattr(r, "algorithm", -1)),
                        "pubkey_prefix": (str(r.to_text()).split()[-1][:64] if hasattr(r, "to_text") else None)
                    })
            # rrsig validation
            try:
                keymap = build_keymap(dnskey_rrset) if dnskey_rrset else {}
                rrsig_results = validate_rrsigs_over_rrset(dnskey_rrset, rrsig_rrset, keymap)
                zone_obj["dnskey_rrsigs"] = rrsig_results
            except Exception as e:
                zone_obj["dnskey_rrsigs_error"] = str(e)
            # compute DS
            try:
                zone_obj["computed_ds"] = compute_ds_list(cur, dnskey_rrset) if dnskey_rrset else []
            except Exception as e:
                zone_obj["computed_ds_error"] = str(e)
            # parent DS
            if cur != dns.name.root:
                parent_res = get_rrsets(cur.to_text(), resolver_ip=resolver_override)  # note: parent query uses same name but RDtype DS fetched earlier
                # We fetched parent DS earlier in get_rrsets called for zone - still use got["parent_ds_rrset"]
                parent_ds_rrset = got.get("parent_ds_rrset")
                zone_obj["parent_ds_resolver"] = got.get("resolver")
                if parent_ds_rrset:
                    pds_list = []
                    for d in parent_ds_rrset:
                        pds_list.append({
                            "key_tag": int(getattr(d, "key_tag", getattr(d, "keytag", -1))),
                            "algorithm": int(getattr(d, "algorithm", -1)),
                            "digest_type": int(getattr(d, "digest_type", -1)),
                            "digest": hexify(getattr(d, "digest", None))
                        })
                    zone_obj["parent_ds"] = pds_list
                    # compare computed vs parent
                    comp_digests = set([c.get("digest") for c in zone_obj.get("computed_ds", []) if c.get("digest")])
                    parent_digests = set([p.get("digest") for p in pds_list if p.get("digest")])
                    if comp_digests and parent_digests and (comp_digests & parent_digests):
                        zone_obj["parent_ds_matches_computed"] = True
                        zone_obj["parent_ds_match_details"] = list(comp_digests & parent_digests)
                else:
                    zone_obj["parent_ds"] = None
            else:
                zone_obj["parent_ds"] = None

            # nsec / nsec3 / cds / cdnskey
            zone_obj["nsec"] = True if got.get("nsec_rrset") else False
            zone_obj["nsec3"] = True if got.get("nsec3_rrset") or got.get("nsec3param_rrset") else False
            zone_obj["cds"] = [r.to_text() for r in (got.get("cds_rrset") or [])] if got.get("cds_rrset") else None
            zone_obj["cdnskey"] = [r.to_text() for r in (got.get("cdnskey_rrset") or [])] if got.get("cdnskey_rrset") else None

        except Exception as e:
            zone_obj["error"] = f"Exception fetching zone data: {e}\n{traceback.format_exc()}"

        out["zones"].append(zone_obj)
        # step upward
        if cur == dns.name.root:
            break
        cur = cur.parent()

    # authoritative NS consistency check
    if check_ns:
        try:
            out["ns_consistency"] = check_authoritative_ns_consistency(domain)
        except Exception as e:
            out["ns_consistency_error"] = str(e)

    # Enhanced summary with status differentiation
    domain_zone = next((z for z in out["zones"] if z["zone"].rstrip('.') == domain.rstrip('.')), None)
    
    has_dnskey = bool(domain_zone and domain_zone.get("dnskey_entries"))
    has_parent_ds = bool(domain_zone and domain_zone.get("parent_ds"))
    rrsig_valid = any(r.get("valid") for r in (domain_zone.get("dnskey_rrsigs") or [])) if domain_zone else False
    ds_matches = bool(domain_zone and domain_zone.get("parent_ds_matches_computed"))
    
    # Determine DNSSEC status
    if not has_dnskey and not has_parent_ds:
        status = "Unsigned"
        risk_level = "Medium"
        note = "Domain does not implement DNSSEC - responses cannot be cryptographically verified"
        validated = False
    elif has_dnskey and not rrsig_valid:
        status = "Broken"
        risk_level = "Critical"
        note = "DNSSEC implementation has validation errors - security compromised"
        validated = False
    elif has_dnskey and rrsig_valid and not ds_matches:
        status = "Broken"
        risk_level = "Critical"
        note = "Parent DS records do not match child DNSKEY - trust chain broken"
        validated = False
    elif has_dnskey and rrsig_valid and ds_matches:
        status = "Valid"
        risk_level = "Low"
        note = "DNSSEC properly implemented and validated"
        validated = True
    else:
        status = "Unknown"
        risk_level = "High"
        note = "Unable to determine DNSSEC status"
        validated = False
    
    out["summary"] = {
        "validated_chain": validated,
        "status": status,
        "risk_level": risk_level,
        "note": note,
        "has_dnskey": has_dnskey,
        "has_parent_ds": has_parent_ds,
        "rrsig_valid": rrsig_valid,
        "ds_matches": ds_matches
    }
    return out

# ---------- Output saving ----------
def save_json(obj: Dict[str, Any], folder: str, prefix: str = "dnssec_research") -> str:
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"{prefix}_{now_ts()}.json")
    with open(path, "w") as fh:
        json.dump(obj, fh, indent=2)
    return path

def save_csv(obj: Dict[str, Any], folder: str, prefix: str = "dnssec_research") -> str:
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"{prefix}_summary_{now_ts()}.csv")
    with open(path, "w", newline='') as fh:
        w = csv.writer(fh)
        w.writerow(["domain", "status", "validated_chain", "risk_level", "note", "timestamp"])
        summary = obj.get("summary", {})
        w.writerow([
            obj.get("domain"), 
            summary.get("status"), 
            summary.get("validated_chain"), 
            summary.get("risk_level"), 
            summary.get("note"), 
            obj.get("timestamp")
        ])
    return path

def save_txt(obj: Dict[str, Any], folder: str, prefix: str = "dnssec_research") -> str:
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, f"{prefix}_report_{now_ts()}.txt")
    with open(path, "w") as fh:
        fh.write("="*80 + "\n")
        fh.write(f"Domain: {obj.get('domain')}  timestamp: {obj.get('timestamp')}\n")
        fh.write("-"*80 + "\n")
        summary = obj.get("summary", {})
        fh.write("DNSSEC Summary:\n")
        fh.write(f" Status: {summary.get('status', 'Unknown')}\n")
        fh.write(f" Validated: {summary.get('validated_chain', False)}\n")
        fh.write(f" Risk Level: {summary.get('risk_level', 'Unknown')}\n")
        fh.write(f" Note: {summary.get('note', '')}\n\n")
        fh.write("Zones (child -> parent):\n")
        for z in obj.get("zones", []):
            fh.write(f"\nZone: {z.get('zone')}\n")
            if z.get("error"):
                fh.write(f"  Error: {z.get('error')}\n")
                continue
            fh.write(f"  Resolver used: {z.get('resolver_used')}\n")
            fh.write(f"  DNSKEY entries:\n")
            for k in z.get("dnskey_entries", []):
                fh.write(f"    - key_tag={k.get('key_tag')} alg={k.get('algorithm')} flags={k.get('flags')} proto={k.get('protocol')}\n")
            fh.write(f"  RRSIG validation results:\n")
            for r in z.get("dnskey_rrsigs", []):
                fh.write(f"    - signer={r.get('signer')} key_tag={r.get('key_tag')} valid={r.get('valid')} error={r.get('error')}\n")
            fh.write(f"  Computed DS:\n")
            for c in z.get("computed_ds", []):
                fh.write(f"    - dt={c.get('digest_type')} digest={c.get('digest')} error={c.get('error')}\n")
            fh.write("  Parent DS:\n")
            if z.get("parent_ds"):
                for p in z.get("parent_ds"):
                    fh.write(f"    - tag={p.get('key_tag')} digest={p.get('digest')}\n")
            else:
                fh.write("    - None\n")
        fh.write("\n\n")
        if obj.get("ns_consistency"):
            fh.write("Authoritative NS consistency:\n")
            nsinfo = obj.get("ns_consistency")
            fh.write(f"  consistent: {nsinfo.get('consistent')}\n")
            for n in nsinfo.get("ns", []):
                fh.write(f"    - {n.get('ns')} ips={n.get('ips')} tags={n.get('dnskey_tags')} error={n.get('error')}\n")
    return path

# ---------- CLI ----------
def main():
    ap = argparse.ArgumentParser(description="Research-grade DNSSEC deep audit (single domain)")
    ap.add_argument("-d", "--domain", required=True, help="Domain to analyze (apex), e.g. example.com")
    ap.add_argument("--resolver", help="Single resolver IP to use (overrides system resolvers)")
    ap.add_argument("--no-ns-check", action="store_true", help="Skip authoritative NS consistency checks")
    ap.add_argument("--out", default=DOWNLOADS, help=f"Output folder (default: {DOWNLOADS})")
    args = ap.parse_args()

    domain = args.domain.strip()
    resolver = args.resolver
    check_ns = not args.no_ns_check

    print(C_WARN + f"Starting deep DNSSEC audit for: {domain}" + C_RST)
    try:
        result = analyze_domain(domain, resolver_override=resolver, check_ns=check_ns)
    except Exception as e:
        print(C_ERR + f"Fatal error analyzing {domain}: {e}\n{traceback.format_exc()}" + C_RST)
        sys.exit(1)

    # Print enhanced summary with context
    summary = result.get("summary", {})
    status = summary.get("status", "Unknown")
    risk_level = summary.get("risk_level", "High")
    note = summary.get("note", "")
    
    print("\nDNSSEC STATUS:")
    
    if status == "Valid":
        print(C_OK + f"  Enabled: ✓ Yes (Domain properly signed)" + C_RST)
        print(C_OK + f"  Validation: ✓ Passed" + C_RST)
        print(C_OK + f"  Risk Level: {risk_level}" + C_RST)
    elif status == "Unsigned":
        print(C_WARN + f"  Enabled: ✗ No (Domain not signed)" + C_RST)
        print(C_WARN + f"  Validation: ✗ Failed (No DNSSEC implementation)" + C_RST)
        print(C_WARN + f"  Risk Level: {risk_level}" + C_RST)
    elif status == "Broken":
        print(C_ERR + f"  Enabled: ⚠ Partial (DNSSEC misconfigured)" + C_RST)
        print(C_ERR + f"  Validation: ✗ Failed (Configuration errors)" + C_RST)
        print(C_ERR + f"  Risk Level: {risk_level}" + C_RST)
    else:
        print(C_ERR + f"  Status: {status}" + C_RST)
        print(C_ERR + f"  Risk Level: {risk_level}" + C_RST)
    
    print(f"  Note: {note}")

    # Save outputs
    try:
        j = save_json(result, args.out, prefix="dnssec_deep")
        c = save_csv(result, args.out, prefix="dnssec_deep")
        t = save_txt(result, args.out, prefix="dnssec_deep")
        print(C_OK + f"\nSaved JSON -> {j}\nSaved CSV  -> {c}\nSaved TXT  -> {t}" + C_RST)
    except Exception as e:
        print(C_ERR + "Failed to save outputs: " + str(e) + C_RST)
        sys.exit(1)

if __name__ == "__main__":
    main()
