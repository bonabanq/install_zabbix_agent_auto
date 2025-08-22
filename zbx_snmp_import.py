#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CSV -> Zabbix 7.0 host upsert (SNMP interface + {$SNMP_COMMUNITY})
- Auth: API Token (-t)
- No external deps (only stdlib)
"""

import argparse
import csv
import json
import sys
import urllib.request
import urllib.error
import ssl

JSONRPC_VER = "2.0"

def rpc(url, token, method, params, insecure=False, request_id=1):
    payload = {
        "jsonrpc": JSONRPC_VER,
        "method": method,
        "params": params,
        "id": request_id,
        "auth": token
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"}
    )
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

def get_or_create_hostgroup(url, token, group_name, insecure=False):
    res = rpc(url, token, "hostgroup.get", {"filter": {"name": [group_name]}}, insecure=insecure)
    if res:
        return res[0]["groupid"]
    created = rpc(url, token, "hostgroup.create", {"name": group_name}, insecure=insecure)
    return created["groupids"][0]

def find_host_by_host(url, token, host, insecure=False):
    res = rpc(url, token, "host.get", {"filter": {"host": [host]}, "output": ["hostid","name","host"]}, insecure=insecure)
    return res[0] if res else None

def build_snmp_interface(ip):
    # SNMP(v2) interface referencing host macro {$SNMP_COMMUNITY}
    return {
        "type": 2,           # 2 = SNMP
        "main": 1,
        "useip": 1,
        "ip": ip,
        "dns": "",
        "port": "161",
        "details": {
            "version": 2,           # 1=v1, 2=v2c, 3=v3
            "community": "{$SNMP_COMMUNITY}",
            "bulk": 1
        }
    }

def host_update_interfaces(url, token, hostid, ip, insecure=False):
    # Get existing interfaces
    cur = rpc(url, token, "hostinterface.get", {"hostids": hostid, "output": "extend"}, insecure=insecure)
    snmp_if = next((i for i in cur if int(i["type"]) == 2), None)
    if snmp_if:
        # Update existing SNMP interface
        params = {
            "interfaceid": snmp_if["interfaceid"],
            "ip": ip,
            "dns": "",
            "useip": 1,
            "port": "161",
            "main": 1,
            "type": 2,
            "details": {
                "version": 2,
                "community": "{$SNMP_COMMUNITY}",
                "bulk": 1
            }
        }
        rpc(url, token, "hostinterface.update", params, insecure=insecure)
    else:
        # Add SNMP interface
        rpc(url, token, "hostinterface.create", {
            "hostid": hostid,
            **build_snmp_interface(ip)
        }, insecure=insecure)

def upsert_macro_snmp(url, token, hostid, community_value, insecure=False):
    # Ensure {$SNMP_COMMUNITY} macro exists with desired value
    macros = rpc(url, token, "usermacro.get", {"hostids": hostid, "output": "extend"}, insecure=insecure)
    target = next((m for m in macros if m.get("macro") == "{$SNMP_COMMUNITY}"), None)
    if target:
        if target.get("value") != community_value:
            rpc(url, token, "usermacro.update", {
                "hostmacroid": target["hostmacroid"],
                "value": community_value
            }, insecure=insecure)
    else:
        rpc(url, token, "usermacro.create", {
            "hostid": hostid,
            "macro": "{$SNMP_COMMUNITY}",
            "value": community_value
        }, insecure=insecure)

def upsert_host(url, token, row, insecure=False, dry_run=False):
    # Required columns
    required = ["그룹", "시스템 명", "모니터링 등록이름", "IP 주소", "SNMPWALK"]
    missing = [c for c in required if c not in row or str(row[c]).strip() == ""]
    if missing:
        raise ValueError(f"CSV 누락 컬럼/값: {missing}")

    group_name = row["그룹"].strip()
    visible_name = row["시스템 명"].strip()
    host_name = row["모니터링 등록이름"].strip()
    ip_addr = row["IP 주소"].strip()
    snmp_comm = row["SNMPWALK"].strip()

    if dry_run:
        print(f"[DRY-RUN] host={host_name}, visible_name={visible_name}, group={group_name}, ip={ip_addr}, {{$SNMP_COMMUNITY}}={snmp_comm}")
        return

    groupid = get_or_create_hostgroup(url, token, group_name, insecure=insecure)
    existing = find_host_by_host(url, token, host_name, insecure=insecure)

    if not existing:
        # Create host with SNMP interface + group + macro
        params = {
            "host": host_name,
            "name": visible_name,
            "groups": [{"groupid": groupid}],
            "interfaces": [build_snmp_interface(ip_addr)],
            "macros": [{"macro": "{$SNMP_COMMUNITY}", "value": snmp_comm}],
            "inventory_mode": 1,        # << 인벤토리 Automatic
            "inventory": {}   
        }
        created = rpc(url, token, "host.create", params, insecure=insecure)
        hostid = created["hostids"][0]
        print(f"[CREATE] host '{host_name}' (id={hostid})")
    else:
        hostid = existing["hostid"]
        # Update visible name and groups (ensure membership)
        rpc(url, token, "host.update", {
            "hostid": hostid,
            "name": visible_name,
            "groups": [{"groupid": groupid}],
            "inventory_mode": 1
        }, insecure=insecure)
        # Upsert SNMP interface
        host_update_interfaces(url, token, hostid, ip_addr, insecure=insecure)
        # Upsert macro {$SNMP_COMMUNITY}
        upsert_macro_snmp(url, token, hostid, snmp_comm, insecure=insecure)
        print(f"[UPDATE] host '{host_name}' (id={hostid})")

def main():
    ap = argparse.ArgumentParser(description="Import/Upsert Zabbix hosts (SNMP) from CSV")
    ap.add_argument("-u", "--url", required=True, help="Zabbix API URL (e.g., https://zbx.example.com/api_jsonrpc.php)")
    ap.add_argument("-t", "--token", required=True, help="Zabbix API Token")
    ap.add_argument("-f", "--file", required=True, help="CSV file path (UTF-8/UTF-8-SIG)")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS verification")
    ap.add_argument("--dry-run", action="store_true", help="Print actions only, do not call API")
    args = ap.parse_args()

    # Read CSV (supports BOM)
    try:
        with open(args.file, "r", encoding="utf-8-sig", newline="") as fp:
            reader = csv.DictReader(fp)
            line = 1
            for row in reader:
                line += 1
                try:
                    upsert_host(args.url, args.token, row, insecure=args.insecure, dry_run=args.dry_run)
                except Exception as e:
                    print(f"[ERROR] line {line}: {e}", file=sys.stderr)
                    continue
    except FileNotFoundError:
        print(f"[FATAL] CSV not found: {args.file}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
