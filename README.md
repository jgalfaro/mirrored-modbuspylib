Traditional control systems are being upgraded with novel computing, communication and interconnection capabilities. This opens new threats that must be handled both in terms of functional and operational security. The recently coined cyber-physical security term has come to address such a challenge. In this context, we are currently preparing some [SCADA](http://en.wikipedia.org/wiki/SCADA) testbeds using [Lego Mindstorms EV3](http://en.wikipedia.org/wiki/Lego_Mindstorms_EV3) bricks and [Raspberry Pi boards](https://en.wikipedia.org/wiki/Raspberry_Pi). The testbeds aim at validating the security of existing [SCADA](http://en.wikipedia.org/wiki/SCADA) protocols, such as the [Modbus](http://en.wikipedia.org/wiki/Modbus) and [DNP3](http://en.wikipedia.org/wiki/DNP3) protocols. 

This library extends some [Scapy] (http://www.secdev.org/projects/scapy/doc/) functionality to work with the aforementioned testbed. More info available at [LegoSCADA](http://www-public.tem-tsp.eu/~garcia_a/web/prototypes/legoscada/)

Requirements:
* Scapy 2.2.0-dev (latest release)
* python netaddr (Debian pkg : python-netaddr)

Files:
* modbus.py : define the messages for scapy
* attack.py : implementation of different tools and attacks for Modbus
```
-t target IP address (e.g., IP address of an RTU)
-m atatck mode, such as:

1. TCP/IP
   SYN Flood attack
   # ./attack.py -m SYN_flood -t 10.0.1.1

2. Discovery/disclosure
   2.1 Network discovery:
      Port scanning of subnetwork
      > sudo ./attack.py -m scanNetwork -t 10.0.1.0/24
   2.2 Opcodes discover
      -c disable writting mode. The scan may need to write some registers to verify the existence of  a given functionality
      > ./attack.py -m scanDeviceCode -t 10.0.1.1
      E.g., ./attack.py -m scanDeviceCode -t 10.0.1.1 -c
   2.3 Discover registers and identifiers
      > ./attack.py -m scanDevice -t 10.0.1.1
   2.4 Monitoring of register values 
      Active: # ./attack.py -m activeMonitor -t 10.0.1.1
      Passive: # ./attack.py -m passiveMonitor -t 10.0.1.1

3. MITM attacks
```
