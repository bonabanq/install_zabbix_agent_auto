from zabbix_utils import ZabbixAPI
import sys
import csv

api = ZabbixAPI(url="192.168.226.62")
api.login(token="")

# host group
def get_group_id(group_name):
    """호스트 그룹 ID 가져오기 (없으면 생성)"""
    groups = api.hostgroup.get(filter={"name": group_name})
    if groups:
        return groups[0]['groupid']
    else:
        new_group = api.hostgroup.create(name=group_name)
        return new_group['groupids'][0]

def create_host(data):
    """새로운 호스트 등록"""
    group_id = get_group_id(data['group'])
    
    # SNMP 인터페이스 정보 설정
    interfaces = []
    if data['snmp_ip']:
        interfaces.append({
            "type": 2,  # SNMP 인터페이스
            "main": 1,
            "useip": 1,
            "ip": data['snmp_ip'],
            "dns": "",
            "port": "161",
            "details": {
                "version": 2,  # SNMP v2
                "community": data['snmp_info']
            }
        })

    # 호스트 태그 설정
    tags = [
        {"tag": "asset_id", "value": data['asset_id']},
        {"tag": "service_grade", "value": data['service_grade']},
    ]

    # 호스트 데이터 생성
    host_data = {
        "host": data['hostname'],
        "name": data['visible_name'],  # Visible name (CSV의 "용도" 값)
        "interfaces": interfaces,
        "groups": [{"groupid": group_id}],
        "status": 1,  # 호스트를 비활성화 상태로 생성 (0: 활성, 1: 비활성)
        "tags": tags,
        "inventory_mode": 1,  # 자동 인벤토리 활성화
        "inventory": {
            "location": data['location'],  # 위치(Location) 필드에 저장
            "deployment_status": data['deployment_status'],  # Deployment status 필드에 저장
            "os": data['os_version'],
            "contact": data['contact_info']
        }
    }

    result = api.host.create(**host_data)
    print(f"✅ Host '{data['hostname']}' created with ID {result['hostids'][0]}")

def import_hosts_from_csv(csv_file):
    """CSV에서 호스트 가져오기 및 등록"""
    with open(csv_file, newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            host_data = {
                "group": row["구분"],
                "asset_id": row["자산번호"],
                "hostname": row["Hostname"],
                "visible_name": row["용도"],  # CSV의 "용도" 값을 Visible name으로 설정
                "service_grade": row["서비스등급"],
                "deployment_status": row["개발/운영구분"],
                "location": row["위치"],  # 위치를 인벤토리로 저장
                "os_version": row["OS 버전"],
                "snmp_ip": row["내부IP"],
                "snmp_info": row["SNMP 연결 정보"],
                "contact_info": f"운영부서: {row['운영부서']} {row['운영담당자']} / "
                                f"서비스부서: {row['서비스부서']} {row['서비스담당자']} / "
                                f"관리부서: {row['관리부서']} {row['관리책임자']}"
            }
            create_host(host_data)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python import_hosts.py hosts.csv")
        sys.exit(1)
    
    csv_filename = sys.argv[1]
    import_hosts_from_csv(csv_filename)