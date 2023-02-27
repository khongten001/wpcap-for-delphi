# wpcap-for-delphi
The wpcap.wrapper Delphi package provides a wrapper for the WinPcap (wpcap) library, which is a low-level packet capture library for Windows.

![image](https://user-images.githubusercontent.com/11525545/221328217-04db309c-c45f-4d33-a297-beff01e0f1c2.png)


The package contains several units including: 

+ **wpcap.Wrapper.pas:**  which wraps the functions of the wpcap DLL.
+ **wpcap.Conts.pas:**   which contains constants used in the library. 
+ **wpcap.Types.pas:**    which contains structures used by the library. 
+ **wpcap.Protocol.pas:** which contains functions for managing protocols.
+ **wpcap.BufferUtils.pas:** which contains functions for managing buffer data.
+ **wpcap.StrUtils.pas:** which contains string manipulation functions.
+ **wpcap.IOUtils.pas:**  which contains functions for filesystem.
+ **wpcap.Pcap.pas:**  which contains abstract function for load and save PCAP.
+ **wpcap.PCAP.SQLite.pas:**  which contains abstract function for create SQLiteDB with packet of PCAP.
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



It enables the capture and analysis of network packets, making it useful for a wide range of applications, including network analysis, security testing, and network monitoring.

# DEMO

The demo project uses DevExpress libraries at moment only Database demo is supported

# TODO LIST

+ Thread with syncronize
+ Abort loading ( at moment only in RT)
+ Query bulder 
+ Packet detail 
  + DETECTED -->
    +  L2TP COMPLEATE
    +  TLS TODO
  + OTHERS --> TODO
+ TcpFlow 
+ UdpFlow
+ ORIGINAL IPPROTO LAYER IP IN DATABASE (IP,UDP,SCTP,NETWORK)
+ DETAIL INFO FOR DATABASE
+ geoIp with map
+ Whois online ??
+ DNS For Host resolution

# TODO LIST FOR REALTIME

+ OPTION REALTIME
  + DATE STOP RECORDING
  + MAX SIZE PACKET
  + TIME OUT 
  + MAX SIZE AND TIME FOR PCAP
+ HUMAN NAME LIST CARD INTERFACE
 

# TODO LIST FOR DEMO
+ ChartStatistics by protocol

# TODO Other protocols

+ STUN
+ HTTP
+ HTTPS
+ IMAP
+ IMAPS
+ POP3
+ POP3S
+ SMTP
+ SMTPS
+ FTP
+ FTP-DATA
+ TFTP
+ DHCP
+ NETBIOS
+ OpenVPN
+ Wiregurad
+ TELNET
+ ICMP
+ OTHERS...



