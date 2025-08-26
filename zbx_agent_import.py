#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CSV -> Zabbix 7.0 host upsert (Agent interface + OS-based templates)
- Auth: API Token (-t)
- Columns used (Korean headers):
  * 분류           -> host groups (allow multiple, separated by "," ";" "|")
  * 이름           -> host (technical) name
  * 개인 IP 주소    -> agent interface IP (port 10050)
  * 운영 체제       -> pick template: contains "Windows" -> Windows by Zabbix agent,
                                  contains "Linux"   -> Linux by Zabbix agent
- Additive behavior: groups/templates are ADDED, never removed. Existing settings are preserved.
- Inventory mode is set to Automatic.
- No external dependencies (stdlib only).

Usage examples:
  Dry-run:
    python3 zbx_agent_import.py -u https://zbx.example.com/api_jsonrpc.php -t $ZBX_TOKEN -f hosts.csv --dry-run --insecure
  Execute:
    python3 zbx_agent_import.py -u https://zbx.example.com/api_jsonrpc.php -t $ZBX_TOKEN -f hosts.csv --insecure

Notes:
  - If the OS string doesn't contain "Windows" or "Linux", the script will SKIP template linking for that row.
  - You can override the default template names via CLI flags --tpl-win / --tpl-linux.
  - A placeholder build_tags(row) is provided for future tag policy changes.
"""

import argparse
import csv
import json
import re
import sys
import ssl
import urllib.request
import urllib.error
from typing import Dict, List

JSONRPC_VER = "2.0"

#########################
# HTTP JSON-RPC wrapper #
#########################

def rpc(url: str, token: str, method: str, params: dict, insecure: bool = False, request_id: int = 1):
    payload = {
        "jsonrpc": JSONRPC_VER,
        "method": method,
        "params": params,
        "id": request_id,
        "auth": token,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})

    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, context=ctx) as resp:
            body = resp.read()
            res = json.loads(body.decode("utf-8"))
            if "error" in res:
                raise RuntimeError(f"API error: {res['error']}")
            return res["result"]
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTPError {e.code}: {e.read().decode(errors='ignore')}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"URLError: {e.reason}")

########################
# Small helper lookups #
########################

def find_host_by_host(url: str, token: str, host: str, insecure: bool = False):
    res = rpc(url, token, "host.get", {"filter": {"host": [host]}, "output": ["hostid", "host", "name"]}, insecure)
    return res[0] if res else None


def get_or_create_hostgroup(url: str, token: str, group_name: str, insecure: bool = False) -> str:
    res = rpc(url, token, "hostgroup.get", {"filter": {"name": [group_name]}}, insecure)
    if res:
        return res[0]["groupid"]
    created = rpc(url, token, "hostgroup.create", {"name": group_name}, insecure)
    return created["groupids"][0]


def template_ids_by_names(url: str, token: str, names: List[str], insecure: bool = False) -> Dict[str, str]:
    # Returns mapping template name -> id for found ones
    res = rpc(url, token, "template.get", {"filter": {"name": names}, "output": ["templateid", "name"]}, insecure)
    return {t["name"]: t["templateid"] for t in res}


##############################
# Ensure host interface (1=Agent)
##############################

def ensure_agent_interface(url: str, token: str, hostid: str, ip: str, insecure: bool = False):
    cur = rpc(url, token, "hostinterface.get", {"hostids": hostid, "output": "extend"}, insecure)
    agent_if = next((i for i in cur if int(i.get("type", 0)) == 1), None)
    params_base = {
        "useip": 1,
        "ip": ip,
        "dns": "",
        "port": "10050",
        "main": 1,
        "type": 1,
    }
    if agent_if:
        rpc(url, token, "hostinterface.update", {"interfaceid": agent_if["interfaceid"], **params_base}, insecure)
    else:
        rpc(url, token, "hostinterface.create", {"hostid": hostid, **params_base}, insecure)


##############################
# Additive groups & templates #
##############################

def massadd_groups(url: str, token: str, hostid: str, groupids: List[str], insecure: bool = False):
    if not groupids:
        return
    rpc(url, token, "host.massadd", {
        "hosts": [{"hostid": hostid}],
        "groups": [{"groupid": gid} for gid in groupids]
    }, insecure)


def massadd_templates(url: str, token: str, hostid: str, templateids: List[str], insecure: bool = False):
    if not templateids:
        return
    rpc(url, token, "host.massadd", {
        "hosts": [{"hostid": hostid}],
        "templates": [{"templateid": tid} for tid in templateids]
    }, insecure)


##############################
# Tag policy placeholder      #
##############################

def build_tags(row: dict) -> List[dict]:
    """Return list of tags like [{"tag": "env", "value": "prod"}, ...].
    Currently returns an empty list; update freely later as policy evolves.
    """
    return []


#########################################
# Main upsert (create or update) per row #
#########################################

def parse_groups(cell: str) -> List[str]:
    parts = [p.strip() for p in re.split(r"[;,|]", cell) if p.strip()]
    # de-duplicate while preserving order
    seen, uniq = set(), []
    for p in parts:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq


def resolve_os_templates(url: str, token: str, os_text: str, tpl_win: str, tpl_linux: str, insecure: bool = False) -> List[str]:
    s = (os_text or "").lower()
    wanted: List[str] = []
    if "windows" in s:
        wanted = [tpl_win]
    elif "linux" in s:
        wanted = [tpl_linux]
    else:
        return []  # unknown OS -> skip template linking

    found = template_ids_by_names(url, token, wanted, insecure)
    missing = [n for n in wanted if n not in found]
    if missing:
        raise RuntimeError(f"Templates not found by name: {missing}")
    return [found[n] for n in wanted]


def upsert_host(url: str, token: str, row: dict, tpl_win: str, tpl_linux: str, insecure: bool = False, dry_run: bool = False):
    required = ["분류", "이름", "개인 IP 주소", "운영 체제"]
    missing = [k for k in required if k not in row or str(row[k]).strip() == ""]
    if missing:
        raise ValueError(f"CSV missing columns/values: {missing}")

    groups = parse_groups(row["분류"].strip())
    host = row["이름"].strip()
    ip = row["개인 IP 주소"].strip()
    os_text = row["운영 체제"].strip()

    tags = build_tags(row)

    if dry_run:
        print(f"[DRY-RUN] host={host}, ip={ip}, groups={groups}, os='{os_text}', tags={tags}")
        return

    # Create or update host
    existing = find_host_by_host(url, token, host, insecure)

    if not existing:
        # ensure groups exist
        groupids = [get_or_create_hostgroup(url, token, g, insecure) for g in groups]
        params = {
            "host": host,
            "interfaces": [{
                "type": 1,
                "main": 1,
                "useip": 1,
                "ip": ip,
                "dns": "",
                "port": "10050"
            }],
            "groups": [{"groupid": gid} for gid in groupids],
            "inventory_mode": 1,  # Automatic
        }
        if tags:
            params["tags"] = tags
        created = rpc(url, token, "host.create", params, insecure)
        hostid = created["hostids"][0]
        print(f"[CREATE] host '{host}' (id={hostid})")
    else:
        hostid = existing["hostid"]
        # ensure groups exist then add membership additively
        groupids = [get_or_create_hostgroup(url, token, g, insecure) for g in groups]
        massadd_groups(url, token, hostid, groupids, insecure)
        # ensure agent interface IP
        ensure_agent_interface(url, token, hostid, ip, insecure)
        # add tags additively by merging (host.massadd does not support tags; so we must use host.update which REPLACES tags).
        # To avoid accidental replacement, we keep tags additive behavior OFF by default.
        # Update here later if your tag policy requires it.
        print(f"[UPDATE] host '{host}' (id={hostid})")

    # link OS-based template (additive)
    tpl_ids = resolve_os_templates(url, token, os_text, tpl_win, tpl_linux, insecure)
    if tpl_ids:
        massadd_templates(url, token, hostid, tpl_ids, insecure)
        print(f"[TEMPLATE] linked {tpl_ids} to host '{host}'")
    else:
        print(f"[TEMPLATE] skipped (unknown OS string: '{os_text}') for host '{host}'")


########################
# CLI entrypoint       #
########################

def main():
    ap = argparse.ArgumentParser(description="Import/Upsert Zabbix hosts (Agent) from CSV")
    ap.add_argument("-u", "--url", required=True, help="Zabbix API URL, e.g. https://zbx.example.com/api_jsonrpc.php")
    ap.add_argument("-t", "--token", required=True, help="Zabbix API token")
    ap.add_argument("-f", "--file", required=True, help="CSV file path (UTF-8/UTF-8-SIG)")
    ap.add_argument("--tpl-win", default="Windows by Zabbix agent", help="Template name for Windows (default: %(default)s)")
    ap.add_argument("--tpl-linux", default="Linux by Zabbix agent", help="Template name for Linux (default: %(default)s)")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    ap.add_argument("--dry-run", action="store_true", help="Print actions without calling API")
    args = ap.parse_args()

    try:
        with open(args.file, "r", encoding="utf-8-sig", newline="") as fp:
            reader = csv.DictReader(fp)
            line = 1
            for row in reader:
                line += 1
                try:
                    upsert_host(
                        url=args.url,
                        token=args.token,
                        row=row,
                        tpl_win=args.tpl_win,
                        tpl_linux=args.tpl_linux,
                        insecure=args.insecure,
                        dry_run=args.dry_run,
                    )
                except Exception as e:
                    print(f"[ERROR] line {line}: {e}", file=sys.stderr)
    except FileNotFoundError:
        print(f"[FATAL] CSV not found: {args.file}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
