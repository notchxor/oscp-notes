---
title: network basics  
category: basics
order: 1
---

# WIRESHARK
---

## Intro

use libpcap (linux) or winpcap(win) libraries.


## capture and display filters

capture: to capture only that  
display: to display only what i want  


## Follow tcp stream
right click and " follow tcp stream"


# TCPDump
---

* read:
```
tcpdump -r password.pcap
```
* filtering:
```
 tcpdump -n -r password.pcap | awk -F " " '{print $3}' | sort -u | head
```

* filtering for src:
```
tcpdump -n src host 172.16.40.10 -r password.pcap
```
* filtering for host:
```
tcpdump -n dst host 172.16.40.10 -r password.pcap
```
* filtering  for port:
```
tcpdum -n port 81 -r password.pcap
```

* Dumping in hex:
```
 tcpdump -nX -r password.pcap
```

## Advance header filtering
we want to display only the data packets which have the psh and ack flags turned on, these are defined in the 14th byte in the tcp header
CEUAPRSF -> A and P are ack y push, the binary would be 00011000 which is 24 in decimal.

```
root@kali: tcpdump -A -n ' tcp[13]=24' -r password.pcap
```

## 2.0 Listen to your interface

listening for outgoing info
```
tcpdump -i eth0

```

 Discover active IPs usign ARP on the network:
```
arp-scan $ip/24
```


Netcat port Scanning

```
nc -nvv -w 1 -z $ip 3388-3390
```

```
 nc -v -z 10.0.3.1 1-65000 > file.txt 2>&1
```
Discover active IPs usign ARP on the network:
```
arp-scan $ip/24

```

Discover who else is on the network

``` 
netdiscover
```

Discover IP Mac and Mac vendors from ARP
```
netdiscover -r $ip/24
```

## 2.4 Internal Infrastructure Mapping

### ping gateway
```
nmap -sn -v -PE 192.168.\*.1
```

### Net discover
```
   netdiscover -i eth0  -r 10.10.10.0/24 -c 20
```
