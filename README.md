
These python library are used for working easily with Modbus (SCADA Network Protocol)
It defines an extension of Scapy ( http://www.secdev.org/projects/scapy/doc/ )
Project original : https://www.scadaforce.com/modbus

Requirements :
* Scapy 2.2.0-dev (latest release)
* python netaddr (Debian pkg : python-netaddr)

Files :
* modbus.py : define the messages for scapy
* attack.py : implementation of different tools and attacks for Modbus


HOW TO...
-t désigne l'IP cible (RTU)
-m designe le mode d'attaque


1. TCP/IP
   Attaque SYN Flood (innondation de demande de connexion)
   # ./attack.py -m SYN_flood -t 10.0.1.1
2. Confidentialité / Découverte
   2.1 Découverte du réseau :
      Scan de port sur une plage réseau
      > sudo ./attack.py -m scanNetwork -t 10.0.1.0/24
   2.2 Découverte des codes de fonction
      -c évite les fonctions d'écriture. Le scan devant écrire dans des registres pour vérifier l'existance de la fonction
      > ./attack.py -m scanDeviceCode -t 10.0.1.1
      Intrusif : ./attack.py -m scanDeviceCode -t 10.0.1.1 -c
   2.3 Découverte des registres et Identification
      > ./attack.py -m scanDevice -t 10.0.1.1
   2.4 Monitoring des valeurs
      Série de requête read des registres
      Actif : > ./attack.py -m activeMonitor -t 10.0.1.1
      Sniff du traffic réseau
      Passif : # ./attack.py -m passiveMonitor -t 10.0.1.1

