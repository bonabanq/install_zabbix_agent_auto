## windows 설치 관련 ##

- install_zabbix_agent.ps1

해당 github의 주소를 복사합니다.
```
Invoke-WebRequest "https://raw.githubusercontent.com/bonabanq/install_zabbix_agent_auto/main/install_zabbix_agent.ps1" -OutFile install_zabbix_agent.ps1
```

- 설치를 진행합니다.
  ```
  powershell -ExecutionPolicy Bypass -File install_zabbix.ps1
  ```

- 다운로드+설치 올인원
```
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest 'https://raw.githubusercontent.com/bonabanq/install_zabbix_agent_auto/main/install_zabbix_agent.ps1' -OutFile install_zabbix_agent.ps1; powershell -ExecutionPolicy Bypass -File install_zabbix_agent.ps1"
```

- 스크립트 삭제
```
Remove-Item install_zabbix_agent.ps1
```


---
## Redhat 설치 관련 ##


- 다운로드를 진행합니다.(권한 추가까지)
```
curl -O https://raw.githubusercontent.com/bonabanq/install_zabbix_agent_auto/main/install_zabbix_agent_redhat.sh && chmod +x install_zabbix_agent_redhat.sh
```

- 설치 진행
```
./install_zabbix_agent_redhat.sh
```

- 스크립트 삭제
```
unlink install_zabbix_agent_redhat.sh
```


+ 예외 사항)
1. 리포지토리 오류가 나는 경우
```
Could not retrieve mirrorlist http://mirrorlist.centos.org/?release=7&arch=x86_64&repo=os&infra=stock error was
14: curl#6 - "Could not resolve host: mirrorlist.centos.org; Unknown error"  
```

: 저장소를 수정합니다.

기존 서버 백업
```
cp /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.old
```

리포지토리 주석처리
```
sudo sed -i 's|^mirrorlist=|#mirrorlist=|g' /etc/yum.repos.d/CentOS-Base.repo
sudo sed -i 's|^#baseurl=http://mirror.centos.org/centos/\$releasever|baseurl=http://vault.centos.org/7.9.2009|g' /etc/yum.repos.d/CentOS-Base.repo
```


---

zabbix host 추가 실행코드
```
python3 zbx_agent_import.py -u https://<zabbix-domain>/api_jsonrpc.php -t <token> -f add_host.csv --insecure
```