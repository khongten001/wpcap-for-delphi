# wpcap-for-delphi
The wcap.wrapper Delphi package provides a wrapper for the Windows Capture (WCap) library, which is a low-level packet capture library for Windows.

The package contains several units including: 

+ **wpcap.Wrapper.pas:**  which wraps the functions of the WCap DLL.
+ **wpcap.Conts.pas:**   which contains constants used in the library. 
+ **wpcap.Types.pas:**    which contains structures used by the library. 
+ **wpcap.Protocol.pas:** which contains functions for managing protocols.
+ **wpcap.StrUtils.pas:** which contains string manipulation functions.
+ **wpcap.IOUtils.pas:**  which contains functions for filesystem.
+ **wpcap.Offline.pas:**  which contains abstract function for load PCAP offline.

It enables the capture and analysis of network packets, making it useful for a wide range of applications, including network analysis, security testing, and network monitoring.

# DEMO

The demo project uses DevExpress libraries


# TODO LIST

+ Thread with syncronize
+ Database SQLLIte
+ Query bulder 
+ Filter WIncap
+ Packet detail
+ TcpFlow 
+ UdpFlow
+ Document on function for wcap.wrapper.pas
+ Test wrapper for realtime analyze 
+ geoIp with map

# TODO LIST FOR DEMO
+ ChartStatistics by protocol
+ Grid with port
+ Color for grid



