#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zabbix bulk host creator (v9)
- CHANGE: inventory_mode=1 (Automatic) on host.create
- CSV 헤더 견고 처리(UTF-8-SIG, 탭/콤마/세미콜론/파이프 자동 감지, 동의어 매핑)
- Host.description = CSV '용도'
- -s/--server 로 URL 자동 구성(https 강제 옵션 지원), -u 우선
- -i 로 호스트 인터페이스 IP 주입(single/ENV/@file/STDIN)
- 기존 인터페이스 IP 중복 시 스킵
- -t 토큰 필수, 명시적 에러
"""

import sys
import csv
import argparse
import os
import re
import ipaddress
from typing import Dict, List, Optional, Union
from zabbix_utils import ZabbixAPI

# ---- EDITABLE DEFAULTS -------------------------------------------------------
DEFAULT_URL = os.environ.get("ZABBIX_URL", "http://127.0.0.1")
GROUP_MAP = {"linux": "Linux servers", "windows": "Windows servers"}
TEMPLATE_MAP = {"linux": "Linux by Zabbix agent", "windows": "Windows by Zabbix agent"}
AGENT_PORT = "10050"
# -----------------------------------------------------------------------------


def err(msg: str, code: int = 1):
    print(f"[ERROR] {msg}", file=sys.stderr); sys.exit(code)

def warn(msg: str):
    print(f"[WARN] {msg}", file=sys.stderr)

def build_url_from_server(server: str, https: bool) -> str:
    s = (server or "").strip()
    if not s:
        err("서버 주소가 비어 있습니다. -s <SERVER_IP_OR_HOST> 또는 -u <URL>을 사용하세요.", 2)
    if s.startswith("http://") or s.startswith("https://"):
        return s
    return f"{'https' if https else 'http'}://{s}"

def resolve_base_url(args) -> str:
    if args.url:
        if args.server:
            warn("'-u/--url'이 지정되어 '-s/--server'보다 우선됩니다.")
        return args.url.strip()
    if args.server:
        return build_url_from_server(args.server, args.https)
    return DEFAULT_URL

def parse_args():
    p = argparse.ArgumentParser(
        description="Import hosts from CSV into Zabbix (inventory_mode=Automatic, robust CSV, host.description, duplicate-IP skip)."
    )
    p.add_argument("csv", help="Input CSV/TSV (utf-8/utf-8-sig). Columns: 서버명, hostname, OS 종류, 용도")
    p.add_argument("-t", "--token", required=True, help="Zabbix API token (required)")
    p.add_argument("-u", "--url", default=None, help="Zabbix base URL (e.g., https://zbx.example.com/zabbix)")
    p.add_argument("-s", "--server", default=None, help="Zabbix server IP/hostname (auto-build URL)")
    p.add_argument("--https", action="store_true", help="Force https when using -s/--server")
    p.add_argument("--print-url", action="store_true", help="Print resolved base URL (for debugging)")
    p.add_argument(
        "-i", "--ip",
        help=("Host interface IP source: single IP (e.g. 10.0.0.5) "
              "or ENV:VARNAME (hostname=ip or newline/comma separated), "
              "or @file (hostname,ip | hostname=ip | ip per line), or '-' (stdin)."),
        required=False
    )
    p.add_argument("--no-log-ip", action="store_true", help="Do not print IPs in output.")
    return p.parse_args()

def zbx_login(url: str, token: str) -> ZabbixAPI:
    api = ZabbixAPI(url=url)
    try:
        api.login(token=token)
    except Exception:
        err("접속이 거부되었습니다. 다른 토큰값을 넣어주세요.", 2)
    return api

# ---------------- CSV utilities (robust headers) ---------------- #
ALIASES = {
    "서버명": ["서버명", "서버 명", "서버이름", "서버 이름", "visiblename", "visible name", "name"],
    "hostname": ["hostname", "host name", "호스트명", "호스트 이름"],
    "os 종류": ["os 종류", "os종류", "ostype", "os-type", "os type", "os"],
    "용도": ["용도", "description", "설명", "desc"],
    "ip": ["ip", "addr", "address", "ip주소", "ip 주소"],
}
def norm(s: Optional[str]) -> str:
    if s is None: return ""
    s = s.replace("\ufeff", "")
    return re.sub(r"\s+", " ", s.strip().lower())

def sniff_dialect(sample: str) -> csv.Dialect:
    try:
        return csv.Sniffer().sniff(sample, delimiters=[",", "\t", ";", "|"])
    except Exception:
        if "\t" in sample:
            class _T(csv.excel_tab): pass
            return _T()
        class _C(csv.excel): pass
        _C.delimiter = ","
        return _C()

def map_headers(fieldnames: List[str]) -> Dict[str, str]:
    nmap = {norm(h): h for h in (fieldnames or [])}
    result: Dict[str, str] = {}
    for canonical, variants in ALIASES.items():
        for v in variants:
            if v in nmap:
                result[canonical] = nmap[v]; break
    return result
# ----------------------------------------------------------------- #

def find_template_id(api: ZabbixAPI, name: str) -> Optional[str]:
    if not name: return None
    items = api.template.get(filter={"host": name})
    if items: return items[0]["templateid"]
    items = api.template.get(filter={"name": name})
    if items: return items[0]["templateid"]
    return None

def get_or_create_group(api: ZabbixAPI, name: str) -> str:
    found = api.hostgroup.get(filter={"name": name})
    if found: return found[0]["groupid"]
    created = api.hostgroup.create(name=name)
    return created["groupids"][0]

def build_existing_ip_set(api: ZabbixAPI) -> set[str]:
    ips = set()
    hosts = api.host.get(output=["hostid"], selectInterfaces=["ip"])
    for h in hosts:
        for iface in h.get("interfaces", []):
            ip = iface.get("ip")
            if ip: ips.add(ip)
    return ips

def os_key(os_value: str) -> str:
    v = norm(os_value)
    if "win" in v or "윈도" in v:
        return "windows"
    return "linux"  # 그 외 전부 linux(CentOS/RHEL/Ubuntu 등)

def make_agent_interface(ip: str) -> dict:
    return {"type": 1, "main": 1, "useip": 1, "ip": ip, "dns": "", "port": AGENT_PORT}

def mask_ip(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            parts = ip.split(".")
            if len(parts) == 4: return ".".join(parts[:3] + ["xxx"])
        s = ip.split(":")
        if len(s) > 2: return ":".join(s[:-2] + ["xxxx", "xxxx"])
    except Exception: pass
    return "REDACTED"

def parse_ip_source(ip_arg: Optional[str]) -> Union[Dict[str, str], List[str], str, None]:
    if not ip_arg: return None
    if ip_arg == "-":
        data = sys.stdin.read(); return _parse_ip_text(data)
    if ip_arg.startswith("ENV:"):
        var = ip_arg[4:]; data = os.environ.get(var, "")
        if not data.strip(): err(f"환경변수 {var} 가 비어있습니다.", 4)
        return _parse_ip_text(data)
    if ip_arg.startswith("@"):
        path = ip_arg[1:]
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                return _parse_ip_text(f.read())
        except Exception as e:
            err(f"IP 매핑 파일을 열 수 없습니다: {e}", 4)
    _validate_ip(ip_arg); return ip_arg

def _parse_ip_text(text: str) -> Union[Dict[str, str], List[str]]:
    mapping: Dict[str, str] = {}; seq: List[str] = []
    cleaned = text.replace(",", "\n")
    for raw in cleaned.splitlines():
        line = norm(raw)
        if not line: continue
        if "=" in line:
            host, ip = [x.strip() for x in line.split("=", 1)]
            _validate_ip(ip); mapping[host] = ip
        elif ";" in line:
            host, ip = [x.strip() for x in line.split(";", 1)]
            _validate_ip(ip); mapping[host] = ip
        elif any(c in line for c in (" ", "\t")):
            parts = line.split()
            if len(parts) >= 2:
                host, ip = parts[0], parts[1]
                _validate_ip(ip); mapping[host] = ip
        elif _looks_like_ip(line):
            _validate_ip(line); seq.append(line)
        else:
            err(f"IP 매핑 구문을 해석할 수 없습니다: '{raw}'", 4)
    return mapping if mapping else seq

def _looks_like_ip(s: str) -> bool:
    try: ipaddress.ip_address(s); return True
    except Exception: return False

def _validate_ip(s: str):
    try: ipaddress.ip_address(s)
    except Exception: err(f"유효하지 않은 IP 형식: {s}", 4)

def resolve_ip_for_row(row_index: int, hostname: str,
    ip_source: Union[Dict[str, str], List[str], str, None], csv_ip: Optional[str]) -> Optional[str]:
    if isinstance(ip_source, dict):
        ip = ip_source.get(hostname); 
        if ip: _validate_ip(ip); return ip
        return None
    if isinstance(ip_source, list):
        idx = row_index - 1
        if 0 <= idx < len(ip_source):
            ip = ip_source[idx]; _validate_ip(ip); return ip
        return None
    if isinstance(ip_source, str):
        _validate_ip(ip_source); return ip_source
    if csv_ip:
        _validate_ip(csv_ip); return csv_ip
    return None

def create_host(api: ZabbixAPI, hostname: str, visible_name: str, ip: str, os_kind: str,
                groupid: str, templateid: Optional[str], description: str) -> str:
    payload = {
        "host": hostname,
        "name": visible_name,
        "description": description,        # Host-level description
        "groups": [{"groupid": groupid}],
        "interfaces": [make_agent_interface(ip)],
        "inventory_mode": 1,               # ★ Automatic (official: -1 disabled, 0 manual, 1 automatic)
        "status": 0,
    }
    if templateid:
        payload["templates"] = [{"templateid": templateid}]
    else:
        warn(f"OS={os_kind} 템플릿을 찾지 못해 템플릿 연결 없이 생성합니다.")
    result = api.host.create(**payload)
    return result["hostids"][0]

def main():
    args = parse_args()
    token = (args.token or "").strip()
    if not token:
        err("토큰값을 넣어달라는 에러: -t <TOKEN> 형태로 전달하세요.", 2)

    base_url = resolve_base_url(args)
    if args.print_url:
        print(f"[INFO] Using URL: {base_url}", file=sys.stderr)

    api = zbx_login(base_url, token)

    existing_ips = build_existing_ip_set(api)
    ip_source = parse_ip_source(args.ip)

    created = 0; skipped = 0

    with open(args.csv, "r", encoding="utf-8-sig", newline="") as f:
        sample = f.read(4096); f.seek(0)
        dialect = sniff_dialect(sample)
        reader = csv.reader(f, dialect)
        try:
            raw_headers = next(reader)
        except StopIteration:
            err("빈 CSV입니다.", 3)

        header_map = map_headers(raw_headers)
        required_keys = ["서버명", "hostname", "os 종류", "용도"]
        missing = [k for k in required_keys if k not in header_map]
        if missing:
            present = ", ".join(raw_headers)
            err(f"CSV 헤더 누락: {missing}. 파일 내 헤더: [{present}]", 3)

        ip_header = header_map.get("ip")

        row_idx = 0
        for row in reader:
            row_idx += 1
            data = {raw_headers[i]: (row[i].strip() if i < len(row) else "") for i in range(len(raw_headers))}
            hostname = data.get(header_map["hostname"], "").strip()
            visible  = data.get(header_map["서버명"], "").strip()
            os_str   = data.get(header_map["os 종류"], "").strip()
            desc     = data.get(header_map["용도"], "").strip()
            csv_ip   = (data.get(ip_header, "").strip() if ip_header else "")

            if not hostname or not visible:
                warn(f"[row {row_idx}] 필수값 누락(hostname/서버명). 건너뜀."); skipped += 1; continue

            oskind = os_key(os_str)  # windows 또는 linux
            ip_candidate = resolve_ip_for_row(row_idx, hostname, ip_source, csv_ip or None)
            if not ip_candidate:
                warn(f"[row {row_idx}] IP 미지정 (-i 옵션 또는 매핑 필요). 건너뜀."); skipped += 1; continue

            if ip_candidate in existing_ips:
                msg_ip = "" if args.no_log_ip else f" ({mask_ip(ip_candidate)})"
                print(f"[SKIP] {hostname}{msg_ip} - 기존 인터페이스 IP와 중복"); skipped += 1; continue

            group_name = GROUP_MAP[oskind]
            groupid = get_or_create_group(api, group_name)
            templateid = find_template_id(api, TEMPLATE_MAP.get(oskind))

            try:
                hostid = create_host(api, hostname, visible, ip_candidate, oskind, groupid, templateid, desc)
                msg_ip = "" if args.no_log_ip else f", ip={mask_ip(ip_candidate)}"
                print(f"[OK] Host '{hostname}' created (id={hostid}{msg_ip}, group='{group_name}')")
                created += 1; existing_ips.add(ip_candidate)
            except Exception as e:
                warn(f"[row {row_idx}] 생성 실패: {e}"); skipped += 1

    print(f"\nSummary: created={created}, skipped={skipped}")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        err(str(e), 99)
