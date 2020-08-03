---
title: PORT SCANNING
category: enum
order: 1
---


## nmap
---

* vpn necesita full connect scan:
```
nmap -sT -p- --min-rate=1000 -vvvvv 10.10.10.116 -T4 -oA nmap-ipsec2
```

* quick:
```
nmap  -O -sV -Pn -oA nmap/host-quick.txt -v -T4 10.10.10.10
```
* complete:
```
nmap -Pn -p-  -oA nmap/full.txt -v -T4 10.10.10.10.
```
* correrle script default
```
nmap -Pn -p 139 -sC -sV  -v -T4 -oA nmap/puerto.txt
```
```
nmap -Pn -p- -sV --script "vuln and safe" -vvv -T4 -oA sarasa  10.10.10.135
```

* quick through proxy (no and SYN)
```
nmap  -O -sT -Pn -oA nmap/host-quick.txt -v -T4 10.10.10.10
```


## **ex 00**

```
root@kali:# nmap -v -p 80 --scripts all 192.168.31.210  
```

## **ex1:**
scan cold fusion web server for a directory traversal vulnerability\\
```
nmap -v -p 80 --script=http-vuln-cve2010-2861 --scripts-args vulns.showall 192.168.1.210
```

## **ex2:**
check for anonymous ftp
```
nmap -v -p 21 --script=ftp-anon.nse 192.168.1.200-254
```

## **ex3:**
check smb server
```
nmap -v -p 139, 445 --script=smb-security-mode 192.168.1.100
```
## **ex4:**
verify  if servers are patched
```
nmap -v -p 80 --script=http-vuln-cve2011-3192  --scripts-args vulns.showall  192.168.11.205-210
```



## unicorn scan
---
```
uniscan -u 10.10.10.10. -qweds
```
```
unicornscan -i tap0 -I -mT $IP:a
db_nmap -e tap0 -n -v -Pn -sV -sC --version-light -A -p
```
```
unicornscan -i tap0 -Iv -mU $IP
db_nmap -e tap0 -n -v -Pn -sV -sC --version-light -A -sU -p
```

## netcat
---
**banner grabbing**
```
nc 192.168.1.2 <port>
```
**tcp scan**
```
nc -vvn -z 10.10.10.10 1-9000
```
**udp  scan**
```
nc -vvn -u -z 10.10.10.10 1-9000
```
