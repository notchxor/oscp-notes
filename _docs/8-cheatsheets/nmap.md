---
title: nmap
category: cheatsheets
order: 1
---


-   Nmap stealth scan using SYN
    `nmap -sS $ip`

-   Nmap stealth scan using FIN
    `nmap -sF $ip`

-   Nmap Banner Grabbing
    `nmap -sV -sT $ip`

-   Nmap OS Fingerprinting
    `nmap -O $ip`

-   Nmap Regular Scan:
    `nmap $ip/24`

-   Enumeration Scan
    `nmap -p 1-65535 -sV -sS -A -T4 $ip/24 -oN nmap.txt`

-   Enumeration Scan All Ports TCP / UDP and output to a txt file
    `nmap -oN nmap2.txt -v -sU -sS -p- -A -T4 $ip`

-   Nmap output to a file:
    `nmap -oN nmap.txt -p 1-65535 -sV -sS -A -T4 $ip/24`

-   Quick Scan:
    `nmap -T4 -F $ip/24`

-   Quick Scan Plus:
    `nmap -sV -T4 -O -F --version-light $ip/24`

-   Quick traceroute
    `nmap -sn --traceroute $ip`

-   All TCP and UDP Ports
    `nmap -v -sU -sS -p- -A -T4 $ip`

-   Intense Scan:
    `nmap -T4 -A -v $ip`

-   Intense Scan Plus UDP
    `nmap -sS -sU -T4 -A -v $ip/24`

-   Intense Scan ALL TCP Ports
    `nmap -p 1-65535 -T4 -A -v $ip/24`

-   Intense Scan - No Ping
    `nmap -T4 -A -v -Pn $ip/24`

-   Ping scan
    `nmap -sn $ip/24`

-   Slow Comprehensive Scan
    `nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" $ip/24`

-   Scan with Active connect in order to weed out any spoofed ports designed to troll you
    `nmap -p1-65535 -A -T5 -sT $ip`
