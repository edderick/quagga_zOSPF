#Quagga zOSPF

This repository contains an implemenation of zeroconfiguration OSPF based on Quagga. 

To run zOSPF first run the zebra daemon found in the the zebra folder. To tun in daemon mode, call with the "-d" flag. 

Next run the OSPFv3 daemon, ospf6d found in the ospf6d folder. This daemon must be called with the "-a" flag to indicate that it should run in autoconfiguration mode. The "-d" flag is currently broken so, the process should be run in the background with "&".
