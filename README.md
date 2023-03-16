# wpcap-for-delphi
The wpcap.wrapper Delphi package provides a wrapper for the WinPcap (wpcap) library, which is a low-level packet capture library for Windows.

![image](https://user-images.githubusercontent.com/11525545/221328217-04db309c-c45f-4d33-a297-beff01e0f1c2.png)

It enables the capture and analysis of network packets, making it useful for a wide range of applications, including network analysis, security testing, and network monitoring.

# GeoLite2 by MaxMind
In this project, I use the GeoLite2 database provided by MaxMind for geodecoding addresses and displaying them on a map. The GeoLite2 database is a free, open-source database that maps IP addresses to their geographic locations. It includes data such as the country, city, and latitude/longitude coordinates of each IP address.

I'd like to thank MaxMind for providing this valuable resource. If you're interested in using the GeoLite2 database, you can download it for free from their website at the following link: https://www.maxmind.com/en/home/maxmind-db/geoip2-geolite2.

Please note that while the GeoLite2 database is free to use, it is subject to MaxMind's Terms of Use, which can be found on their website.

   ![image](https://user-images.githubusercontent.com/11525545/222990137-523eca8a-9a36-4b2e-9185-5d0ee95b5faf.png)
![image](https://user-images.githubusercontent.com/11525545/222990179-f5e0688e-6f10-40d6-90f2-073040547694.png)


# Service Name and Transport Protocol Port Number Registry by IANA 
I am using the Service Name and Transport Protocol Port Number Registry provided by IANA. The Internet Assigned Numbers Authority (IANA) is a department of the Internet Corporation for Assigned Names and Numbers (ICANN) that is responsible for maintaining various Internet-related registries. This includes assigning unique identifiers to devices, protocols, and services, as well as managing the allocation of IP addresses and domain names. The Service Name and Transport Protocol Port Number Registry is a comprehensive list of standardized port numbers and their associated services, which helps ensure that network traffic is properly routed between devices. By using this registry, I can ensure that my software is compatible with the protocols and services used across the Internet.

# TCP and UPD Flow stream

![image](https://user-images.githubusercontent.com/11525545/223887025-799aa3c9-8dc3-463c-9364-8cc118554e76.png)


# Package unit detail

The package contains several units including: 

+ **wpcap.Wrapper.pas:**  which wraps the functions of the wpcap DLL.
+ **wpcap.Conts.pas:**   which contains constants used in the library. 
+ **wpcap.Types.pas:**    which contains structures used by the library. 
+ **wpcap.Protocol.pas:** which contains functions for managing protocols.
+ **wpcap.BufferUtils.pas:** which contains functions for managing buffer data.
+ **wpcap.StrUtils.pas:** which contains string manipulation functions.
+ **wpcap.IOUtils.pas:**  which contains functions for filesystem.
+ **wpcap.Pcap.pas:**  which contains abstract function for load and save PCAP.
+ **wpcap.PCAP.SQLite.pas:**  which contains abstract function for create SQLiteDB.
+ **wpcap.PCAP.SQLite.Packet.pas:**  which contains abstract function for create SQLiteDB with packet of PCAP.
+ **wpcap.DB.Base:**  which contains base class for managing database.
+ **wpcap.DB.SQLite.pas:**  which contains function SQLiteDB.
+ **wpcap.Filter.pas:**  which contains function for filter PCAP.
+ **wpcap.NetDevice:**  which contains function for managing network inteface.
+ **wpcap.Protocol.Base:**  which contains base class engine for protocol detection
+ **wpcap.Graphics:**  which contains function for colors
+ **wpcap.Level.Eth:**  which contains class for Ethernet level
+ **wpcap.Level.IP:**  which contains class for IP level
+ **wpcap.IANA.DBPort:**  which contains databse of IANA Db Port to Protocol name
+ **wpcap.Packet.pas:** witch contains internal structure for packet analisys
+ **wpcap.GEOLite2:** Import Database GeoLite2 by MaxMind and IP enrichment
+ **wpcap.Geometry:** GrantCircle implementation for Delphi
+ **wpcap.IPUtils:** which contains class for IP conversion


# DEMO

The demo project uses DevExpress libraries at moment only Database demo is supported

# TODO LIST

+ Query bulder 
+ Packet detail 
  + DETECTED -->
    +  L2TP TO COMPLEATE
    +  TLS TO COMPLEATE
    +  ICMP TO COMPLEATE
    +  NBNS TO COMPLEATE
    +  HTTP TODO
    +  FTP TODO
    +  POP3 TODO
    +  SIP TODO
  + OTHERS --> TODO
+ DETAIL INFO FOR DATABASE
+ Whois online ??
+ DNS For Host resolution

# TODO LIST FOR REALTIME

+ OPTION REALTIME
  + MAX SIZE AND TIME FOR PCAP
  + HUMAN NAME LIST CARD INTERFACE
 
# TODO LIST FOR DEMO
+ ChartStatistics by protocol

# TODO Other protocols for packet detail

+ STUN
+ HTTPS
+ IMAP
+ IMAPS
+ POP3S
+ SMTP
+ SMTPS
+ FTP-DATA
+ DHCP
+ OpenVPN
+ Wiregurad
+ TELNET
+ OTHERS...



