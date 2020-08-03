---
title: UAC bypass
category: win privesc
order: 1
---


If this setting is enabled, we could craft an MSI file and run it to elevate our privileges.
Similarly, on Linux-based systems we can search for SUID 489 files.

we can switch to a high integrity level (if we are admin)
```
powershell.exe Start-Process cmd.exe -Verb runAs
```

# example with fodhelper.exe
---
we can check forthis fodhelpers  permissions inside its manifest
```
sigcheck.exe -a -m C:\Windows\System32\fodhelper.exe
```

lanzamos procmon.exe  filtramos por reg  y vemos si busca algun registro que no existe en HKEY_CURRENT_USER

CAMBIAMOS EL REGISTRO Y LE MANDAMOS UN cmd.exe  con high integrity level
