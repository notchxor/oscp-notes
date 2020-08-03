---
title: LLMNR and NBT-NS poisoning
category: win privesc
order: 1
---


---
Link-Local Multicast Name Resolution (LLMNR) and Netbios Name Service (NBT-NS) are two components of Microsoft Windows machines.  LLLMNR was introduced in Windows Vista and is the successor to NBT-NS.

If one machine tries to resolve a particular host, but DNS resolution fails, the machine will then attempt to ask all other machines on the local network for the correct address via LLMNR or NBT-NS.

## Vulnerability
1. The victim machine wants to go the print server at \\printserver, but mistakenly types in \\pintserver.  
2. The DNS server responds to the victim saying that it doesn’t know that host.
3. The victim then asks if there is anyone on the local network that knows the location of \\pintserver
4. The attacker responds to the victim saying that it is the \\pintserver
5. The victim believes the attacker and sends its own username and NTLMv2 hash to the attacker.
6. The attacker can now crack the hash to discover the password


  https://github.com/lgandx/Responder
