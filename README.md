# wpcap-for-delphi
The wpcap.wrapper Delphi package provides a wrapper for the WinPcap (wpcap) library, which is a low-level packet capture library for Windows.

It enables the capture and analysis of network packets, making it useful for a wide range of applications, including network analysis, security testing, and network monitoring.

# Pre-compiled Demo available in Bin folder.

The "Bin" folder in this repository contains the Demo already compiled and ready to use. This means that you don't need to compile the source code to run the program. Just download the "Bin" folder and run the Demo.

![image](https://user-images.githubusercontent.com/11525545/228578940-4be9a840-eb49-43f7-9077-d6d0cc3f18e1.png)

# Protocol detection info

I use the IANA PROTOCOL database to identify protocols based on the port (as listed in the IANA PROTOCOL column). 

However, I also have an internal protocol recognition engine that allows me to identify protocols directly within the library.

For protocols that are recognized directly by my library, I provide additional packet details and information directly in the grid (as listed in the INFO column). This helps to provide a more comprehensive and detailed understanding of the protocols being used.

[Info protocol supported](https://github.com/amancini/wpcap-for-delphi/wiki/Table-protocol-supported)

# Service Name and Transport Protocol Port Number Registry by IANA 

I am using the Service Name and Transport Protocol Port Number Registry provided by IANA. 
The Internet Assigned Numbers Authority (IANA) is a department of the Internet Corporation for Assigned Names and Numbers (ICANN) that is responsible for maintaining various Internet-related registries. 

This includes assigning unique identifiers to devices, protocols, and services, as well as managing the allocation of IP addresses and domain names. 
The Service Name and Transport Protocol Port Number Registry is a comprehensive list of standardized port numbers and their associated services, which helps ensure that network traffic is properly routed between devices. 

By using this registry, I can ensure that my software is compatible with the protocols and services used across the Internet.

# RTP to Wave

![image](https://user-images.githubusercontent.com/11525545/231596717-2e590617-2bb1-41d7-8346-1bfd0fd1a04e.png)


Ability to export RTP session payloads and play them back as audio files using SOX(https://sox.sourceforge.net/Main/HomePage) or FFMPEG.

[Info codec supported](https://github.com/amancini/wpcap-for-delphi/wiki/RTP-table-codec-supported)

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

# Whois

Whois service provided by IANA has been integrated into wpcap-for-delphi! This will definitely come in handy when searching for domain information.

# DEMO

The demo project uses DevExpress libraries at moment only Database demo is supported
