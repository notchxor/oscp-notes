---
title: Kernel Vulns
category: win privesc
order: 1
---


[WPE-02 - Windows Kernel](https://pentestlab.blog/2017/04/24/windows-kernel-exploits/)


try to search for third party drivers exploits before kernel ones.
example: USBPcap

##  discover patches
```
wmic qfe get Caption,Description,HotFixID,InstalledOn
```
##  exploit suggester

#### | watson
https://github.com/rasta-mouse/Watson
```
C:> Watson.exe
```

#### | Windows Exploit Suggester - Next Generation  
https://github.com/bitsadmin/wesng

```
wes.py --update
wes.py systeminfo.txt
wes.py arctic-systeminfo.txt  --muc-lookup  --exploits-only  -i "Elevation of Privilege"
```

#### | Windows Exploit Suggester
https://github.com/AonCyberLabs/Windows-Exploit-Suggester
```
python /home/nikhil/scripts/windows-exploit-suggester.py -d 2016-07-02-mssb.xls -i systeminfo -l
```
 -l : show only local exploits


## compiling in windows
```
C:\Program Files\mingw-w64\i686-7.2.0-posix-dwarf-rt_v5-rev1> mingw-w64.bat

C:\> gcc 41542.c -o exploit.exe
```


##  list
* MS16-135 		
* MS16-032
* MS15-051
* MS14-058 	
* MS16-016 		
* MS14-040 	
* MS14-002
* MS10-092 	
* MS10-015 	
* MS14-002 	
* MS15-061 	
* MS11-062	
* MS11-080 	
* MS15-076
* MS16-075 		
* MS15-010 		
* MS11-046 	
