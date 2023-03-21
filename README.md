# wpcap-for-delphi
The wpcap.wrapper Delphi package provides a wrapper for the WinPcap (wpcap) library, which is a low-level packet capture library for Windows.

![image](https://user-images.githubusercontent.com/11525545/221328217-04db309c-c45f-4d33-a297-beff01e0f1c2.png)

It enables the capture and analysis of network packets, making it useful for a wide range of applications, including network analysis, security testing, and network monitoring.

# Protocol detection info

I use the IANA PROTOCOL database to identify protocols based on the port (as listed in the IANA PROTOCOL column). 

However, I also have an internal protocol recognition engine that allows me to identify protocols directly within the library.

For protocols that are recognized directly by my library, I provide additional packet details and information directly in the grid (as listed in the INFO column). This helps to provide a more comprehensive and detailed understanding of the protocols being used.

| Protocol | Packet Detail | Info on Grid |
|----------|--------------|--------------|
| ARP      | OK    | TODO   |
| DHCP      | OK    | TODO   |
| DNS      | OK    | TODO   |
| FTP      | TODO    | TODO   |
| HTTP     | TODO | TODO|
| ICMP     | OK | TODO |
| IGMP     | OK | TODO |
| L2TP     | PARTIAL | TODO |
| LLMNR     | OK | TODO |
| MDNS     | OK | TODO |
| MQTT     | OK | TODO |
| NBNS     | OK | TODO |
| NTP     | OK | TODO |
| POP3     | TODO | TODO |
| QUIC     | PARTIAL | TODO |
| RTP     | OK | TODO |
| SIP     | TODO | TODO |
| TELNET   | OK    | TODO   |
| TCP      | OK    | TODO   |
| TFTP      | OK    | TODO   |
| TLS     | PARTIAL | TODO |
| UDP      | OK   | TODO|

# Service Name and Transport Protocol Port Number Registry by IANA 

I am using the Service Name and Transport Protocol Port Number Registry provided by IANA. 
The Internet Assigned Numbers Authority (IANA) is a department of the Internet Corporation for Assigned Names and Numbers (ICANN) that is responsible for maintaining various Internet-related registries. 

This includes assigning unique identifiers to devices, protocols, and services, as well as managing the allocation of IP addresses and domain names. 
The Service Name and Transport Protocol Port Number Registry is a comprehensive list of standardized port numbers and their associated services, which helps ensure that network traffic is properly routed between devices. 

By using this registry, I can ensure that my software is compatible with the protocols and services used across the Internet.

# RTP to Wave

Ability to export RTP session payloads and play them back as audio files using SOX(https://sox.sourceforge.net/Main/HomePage).

Currently, thee library only supports the G711 a-law codec, but we are working to expand our codec compatibility in the near future. 
With this new feature, you can now easily export your RTP session payloads and play them back as audio files, making it easier to analyze and debug your audio streams.

# GeoLite2 by MaxMind
In this project, I use the GeoLite2 database provided by MaxMind for geodecoding addresses and displaying them on a map. 

The GeoLite2 database is a free, open-source database that maps IP addresses to their geographic locations. It includes data such as the country, city, and latitude/longitude coordinates of each IP address.

I'd like to thank MaxMind for providing this valuable resource. If you're interested in using the GeoLite2 database, you can download it for free from their website at the following link: https://www.maxmind.com/en/home/maxmind-db/geoip2-geolite2.

Please note that while the GeoLite2 database is free to use, it is subject to MaxMind's Terms of Use, which can be found on their website.

   ![image](https://user-images.githubusercontent.com/11525545/222990137-523eca8a-9a36-4b2e-9185-5d0ee95b5faf.png)
![image](https://user-images.githubusercontent.com/11525545/222990179-f5e0688e-6f10-40d6-90f2-073040547694.png)

# TCP and UPD Flow stream

I'd like to take a moment to explain the concept of TCP and UDP flow stream in my library.

In networking, a flow stream refers to a sequence of packets that are transmitted between two devices. The flow stream is characterized by a unique combination of source and destination IP addresses, as well as source and destination port numbers.

TCP and UDP are two of the most commonly used transport protocols in networking. TCP is a connection-oriented protocol, which means that a session is established between two devices before any data is transmitted. TCP flow streams are identified by the combination of the source and destination IP addresses, as well as source and destination port numbers, and a sequence number that is used to keep track of the packets in the stream.

UDP, on the other hand, is a connectionless protocol, which means that data can be transmitted without first establishing a session. UDP flow streams are identified by the combination of the source and destination IP addresses, as well as source and destination port numbers. However, unlike TCP, UDP does not use sequence numbers to keep track of packets in a flow stream.

In my library, I provide information on TCP and UDP flow streams as part of the network analysis features. This allows users to gain a better understanding of the flow of data between devices on their network, and to identify any potential issues or areas for optimization.

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
