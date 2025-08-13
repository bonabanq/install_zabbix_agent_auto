#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

try {
    Write-Host "==[1/7] Stop & Delete existing Agent"
    sc.exe stop "Zabbix Agent" | Out-Null
    sc.exe delete "Zabbix Agent" | Out-Null

    Write-Host "==[2/7] Remove existing MSI via wmic"
    wmic product where "name like 'Zabbix%'" call uninstall /nointeractive | Out-Null

    Write-Host "==[3/7] Download MSI"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $msiPath = "C:\Users\Administrator\Downloads\zabbix_agent-7.0.17.msi"
    Invoke-WebRequest "https://cdn.zabbix.com/zabbix/binaries/stable/7.0/7.0.17/zabbix_agent-7.0.17-windows-amd64-openssl.msi" -OutFile $msiPath

    Write-Host "==[4/7] Install MSI (Silent)"
    $hostname = $env:COMPUTERNAME
    $msiArgs = '/i "{0}" /qn SERVER=10.99.3.36,10.99.3.37 HOSTNAME={1} /norestart' -f $msiPath, $hostname
    $p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
    if ($p.ExitCode -ne 0) {
        throw "MSI installation failed (ExitCode=$($p.ExitCode))."
    }

    # Verify installation: Check service status
    Write-Host "==[Verification] Checking if service exists"
    $null = sc.exe query "Zabbix Agent" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Installation was not completed successfully. 'Zabbix Agent' service does not exist. (sc.exe return code=$LASTEXITCODE) · Possible causes: Wrong MSI parameters (SERVER/HOSTNAME), insufficient privileges, antivirus blocking."
    }

    # Path to configuration file
    $confPath = "C:\Program Files\Zabbix Agent\zabbix_agentd.conf"

    Write-Host "==[5/7] Add UserParameters"
    @'
UserParameter=system.serial,powershell -NoProfile -Command "(Get-WmiObject Win32_BIOS).SerialNumber"
UserParameter=system.mb_model,powershell -NoProfile -Command "(Get-WmiObject Win32_BaseBoard).Product"
UserParameter=system.vendor,powershell -NoProfile -Command "(Get-WmiObject Win32_BaseBoard).Manufacturer"
UserParameter=system.osver,powershell -NoProfile -Command "(Get-CimInstance Win32_OperatingSystem).Caption"
UserParameter=top10.cpu,powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$cores=(Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors; Get-Counter '\Process(*)\% Processor Time' | Select-Object -ExpandProperty CounterSamples | Where-Object { $_.InstanceName -notmatch '^(_Total|Idle|System)$' } | Sort-Object CookedValue -Descending | Select-Object -First 10 @{n='ProcessName';e={$_.InstanceName}},@{n='CPU%';e={[math]::Round($_.CookedValue / $cores, 2)}} | ConvertTo-Json -Compress"
UserParameter=top10.mem,powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$total=(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory; Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 @{n='ProcessName';e={$_.ProcessName}},@{n='Memory%';e={[math]::Round(($_.WorkingSet64 / $total) * 100, 2)}} | ConvertTo-Json -Compress"
'@ | Add-Content -Path $confPath -Encoding UTF8

    Write-Host "==[6/7] Restart Zabbix Agent service"
    sc.exe stop "Zabbix Agent" | Out-Null
    sc.exe start "Zabbix Agent" | Out-Null

    # ---- Output requirements ----
    Write-Host "`n[zabbix_agentd.conf - Server/Hostname]"
    Get-Content -Path $confPath | Select-String -Pattern '^(Server|Hostname)='

    Write-Host "`n[zabbix_agentd.conf - Last 6 lines]"
    Get-Content -Path $confPath | Select-Object -Last 6

    Write-Output $hostname

    # ---- Final step: Permanently delete the MSI file ----
    Write-Host "==[7/7] Delete MSI file permanently"
    if (Test-Path $msiPath) {
        Remove-Item -Path $msiPath -Force
        Write-Host "MSI file deleted: $msiPath"
    } else {
        Write-Host "MSI file not found: $msiPath"
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
