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

다운로드+설치 올인원
```
powershell -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest 'https://raw.githubusercontent.com/bonabanq/install_zabbix_agent_auto/main/install_zabbix_agent.ps1' -OutFile install_zabbix_agent.ps1; powershell -ExecutionPolicy Bypass -File install_zabbix_agent.ps1"

```
