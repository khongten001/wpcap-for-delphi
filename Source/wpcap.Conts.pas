//*************************************************************
//                        WPCAP FOR DELPHI                    *
//				                                        			      *
//                     Freeware Library                       *
//                       For Delphi 10.4                      *
//                            by                              *
//                     Alessandro Mancini                     *
//				                                        			      *
//*************************************************************
{LICENSE:
THIS SOFTWARE IS PROVIDED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND,
EITHER EXPRESSED OR IMPLIED INCLUDING BUT NOT LIMITED TO THE APPLIED
WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
YOU ASSUME THE ENTIRE RISK AS TO THE ACCURACY AND THE USE OF THE SOFTWARE
AND ALL OTHER RISK ARISING OUT OF THE USE OR PERFORMANCE OF THIS SOFTWARE
AND DOCUMENTATION. PRODUCTIONS DOES NOT WARRANT THAT THE SOFTWARE IS ERROR-FREE
OR WILL OPERATE WITHOUT INTERRUPTION. THE SOFTWARE IS NOT DESIGNED, INTENDED
OR LICENSED FOR USE IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE CONTROLS,
INCLUDING WITHOUT LIMITATION, THE DESIGN, CONSTRUCTION, MAINTENANCE OR
OPERATION OF NUCLEAR FACILITIES, AIRCRAFT NAVIGATION OR COMMUNICATION SYSTEMS,
AIR TRAFFIC CONTROL, AND LIFE SUPPORT OR WEAPONS SYSTEMS. PRODUCTIONS SPECIFICALLY
DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF FITNESS FOR SUCH PURPOSE.

You may use/change/modify the component under 1 conditions:
1. In your application, add credits to "WPCAP FOR DELPHI"
{*******************************************************************************}

unit wpcap.Conts;

interface

const
   //The constants MODE_CAPT, MODE_STAT and MODE_MON are used as an argument for the PacketSetModeEx function
   //to set the packet capture mode to a specific network adapter.
  MODE_CAPT = $0000;  // capture packets arriving on the physical side of the network adapter.
  MODE_STAT = $0001;  // capture packets passing through the network stack, but not packets arriving on the physical side of the network adapter.
  MODE_MON  = $0002;  // monitor mode, used to capture traffic in promiscuous mode.

  
  ADAPTER_NAME_LENGTH = 256; //This constant is used to define the maximum size of the Name field of the ADAPTER_INFO structure. 
                             //In this case, the Name field is an AnsiChar array of length 256.
  ADAPTER_DESC_LENGTH = 128; //This constant is also used to define the maximum size of the Description field of the ADAPTER_INFO structure.
                             // In this case, the Description field is an AnsiChar array of length 128.

  WPCAP_MAX_MCAST_LIST = 32;

  PCAP_ERRBUF_SIZE = 256;



  DLT_EN10MB = 1; // Ethernet (10Mb) link type identifier
  
  MAX_PACKET_SIZE = 65535; // Maximum size of the packets to be captured

  
  {IPPROTO IPV4}
  IPPROTO_GRE        = 47;
  IPPROTO_ESP        = 50;    // Encapsulation Security Payload
  IPPROTO_AH         = 51;    // Authentication header
  IPPROTO_ROUTING    = 42;    // Routing header
  IPPROTO_PGM        = 113;
  IPPROTO_SCTP       = 132;

  {IPPROTO IPV6}  
  IPPROTO_IPV6       = 41;   // IPv6 header
  IPPROTO_ROUTINGV6  = 43;   // IPv6 routing header
  IPPROTO_FRAGMENT   = 44;   // IPv6 fragmentation header
  IPPROTO_ICMPV6     = 58;   // ICMPv6
  IPPROTO_NONE       = 59;   // IPv6 no next header
  IPPROTO_DSTOPTS    = 60;   // IPv6 destination options
  IPPROTO_MH         = 135;  // Mobility header
 // IPPROTO_ICMPV62    = 128;  
   {ETHERNET TYPE}
  ETH_P_LOOP      = $0060;  // Ethernet Loopback packet
  ETH_P_PUP       = $0200;  // Xerox PUP packet
  ETH_P_PUPAT     = $0201;  // Xerox PUP Addr Trans packet
  ETH_P_TSN       = $22F0;  // TSN (IEEE 1722 Audio/Video Bridging)
  ETH_P_IP        = $0800;  // Internet Protocol packet
  ETH_P_IP_P2P    = $21;     
  ETH_P_X25       = $0805;  // CCITT X.25
  ETH_P_ARP       = $0806;  // Address Resolution packet
  ETH_P_BPQ       = $08FF;  // G8BPQ AX.25 Ethernet Packet [ NOT AN OFFICIALLY REGISTERED ID ]
  ETH_P_IEEEPUP   = $0a00;  // Xerox IEEE802.3 PUP packet
  ETH_P_IEEEPUPAT = $0a01;  // Xerox IEEE802.3 PUP Addr Trans packet
  ETH_P_DEC       = $6000;  // DEC Assigned proto
  ETH_P_DNA_DL    = $6001;  // DEC DNA Dump/Load
  ETH_P_DNA_RC    = $6002;  // DEC DNA Remote Console
  ETH_P_DNA_RT    = $6003;  // DEC DNA Routing
  ETH_P_LAT       = $6004;  // DEC LAT
  ETH_P_DIAG      = $6005;  // DEC Diagnostics
  ETH_P_CUST      = $6006;  // DEC Customer use
  ETH_P_SCA       = $6007;  // DEC Systems Comms Arch
  ETH_P_RARP      = $8035;  // Reverse Addr Res packet
  ETH_P_ATALK     = $809B;  // Appletalk DDP
  ETH_P_AARP      = $80F3;  // Appletalk AARP
  ETH_P_8021Q     = $8100;  // 802.1Q VLAN Extended Header
  ETH_P_IPX       = $8137;  // IPX over DIX
  ETH_P_IPV6      = $86DD;  // IPv6 over bluebook
  ETH_P_PAUSE     = $8808;  // IEEE Pause frames. See 802.3 31B
  ETH_P_SLOW      = $8809;  // Slow Protocol. See 802.3ad 43B
  ETH_P_WCCP      = $883E;  // Web-cache coordination protocol (WCCP)
  ETH_P_MPLS_UC   = $8847;  // MPLS Unicast traffic
  ETH_P_MPLS_MC   = $8848;  // MPLS Multicast traffic
  ETH_P_ATMMPOA   = $884c;  // MultiProtocol Over ATM AAL5
  ETH_P_PPP_DISC  = $8863;  // PPPoE discovery messages
  ETH_P_PPP_SES   = $8864;  // PPPoE session messages
  ETH_P_LINK_CTL  = $886c;  // HPNA, wlan link local tunnel
  ETH_P_ATMFATE   = $8884;  // Frame-based ATM Transport over Ethernet
  ETH_P_PAE       = $888E;  // Port Access Entity (IEEE 802.1X)
  ETH_P_AOE       = $88A2;  // ATA over Ethernet
  ETH_P_BRIDGE    = $6559;  // Ethernet Bridging
  ETH_P_IEEE1588  = $88F7;  // Precision Time Protocol
  ETH_P_ECP       = $88E5;  // Ethernet Configuration Protocol
  ETH_P_PROFINET  = $8892;  // PROFINET protocol
  ETH_P_HSR       = $892F;  // High-availability Seamless Redundancy (HSR)
  ETH_P_MRP       = $88E3;  // Media Redundancy Protocol (MRP)
  ETH_P_LLDP      = $88CC;  // Link Layer Discovery Protocol (LLDP)
  ETH_P_SERCOS3   = $88CD;  // SErial Realtime COmmunication System 3 (SERCOS III)
  ETH_P_CESoE     = $8100;  // Circuit Emulation Services over Ethernet (CEoE)
  ETH_P_MACSEC    = $88E5;  // MAC security standard (IEEE 802.1AE)  
  ETH_P_8021AD    = $88A8;  // IEEE 802.1ad Service VLAN tag
  ETH_P_8021D     = $88F7;  // IEEE 802.1D Ethernet Bridge
  ETH_P_802_2     = $0004;  // 802.2 frames
  ETH_P_802_3     = $0001;  // Standard Ethernet (802.3)
  ETH_P_AF_IUCV   = $DB00;  // IBM IUCV
  ETH_P_ALL       = $0003;  // All protocols
  ETH_P_ARCNET    = $0608;  // ARCNET
  ETH_P_AX25      = $0002;  // AX.25 packet radio network
  ETH_P_CAIF      = $83E0;  // ST-Ericsson CAIF protocol
  ETH_P_CAN       = $000C;  // Controller Area Network
  ETH_P_CONTROL   = $0161;  // HPNA, wlan-av
  ETH_P_DSA       = $001B;  // Distributed Switch Architecture
  ETH_P_ECONET    = $0018;  // Acorn Econet
  ETH_P_EDSA      = $0012;  // Ethernet for DAMA Service Access Point
  ETH_P_EFC       = $8808;  // 802.1Qat ECP (Ethernet Configuration Protocol)
  ETH_P_FCOE      = $8906;  // Fibre Channel over Ethernet
  ETH_P_FC        = $0800;  // Fibre Channel
  ETH_P_FIP       = $8914;  // FCoE Initialization Protocol
  ETH_P_HDLC      = $0019;  // HDLC frames
  ETH_P_IPXNEW    = $5734;  // IPX over DIX (Novell Netware)
  ETH_P_IRDA      = $0009;  // IrDA
  ETH_P_LOCALTALK = $9B;    // Apple LocalTalk
  ETH_P_MOBITEX   = $0017;  // Mobitex wireless network
  ETH_P_PHONET    = $00F5;  // Nokia Phonet
  ETH_P_PPPTALK   = $0010;  // PPPoE Discovery Stage
  ETH_P_PPPOEDISC = $8863;  // PPPoE Discovery Stage
  ETH_P_PPPOE     = $8864;  // PPPoE Session Stage
  ETH_P_SNAP      = $05Cc;  // SNAP
  ETH_P_TEB       = $6558;  // Transparent Ethernet Bridging
  ETH_P_TIPC      = $88ca;  // TIPC
  ETH_P_TRAILER   = $001A;  // Trailer encapsulation
  ETH_P_TR_802_2  = $0011;  // Token Ring
  ETH_P_WAN_PPP   = $7;     // WAN PPP   

 {PROTOCOLS PORT}
 PROTO_FTP_PORT     = 21;

 PROTO_SSH_PORT     = 22;
 PROTO_TELNET_PORT  = 23; 
 PROTO_SMTP_PORT    = 25;
 PROTO_DNS_PORT     = 53;
 PROTO_DHCP_PORT_S  = 67; 
 PROTO_DHCP_PORT_C  = 68;  
 PROTO_TFTP_PORT    = 69;
 PROTO_HTTP_PORT_1  = 80;
 PROTO_POP3_PORT    = 110;
 PROTO_NTP_PORT     = 123;
 PROTO_NBNS_PORT    = 137;
 PROTO_IMAP_PORT    = 143;
 PROTO_TLS_PORT     = 443; 
 PROTO_SMTPS_PORT   = 465; 
 PROTO_SMTPS_PORT_2 = 587; 
 PROTO_IMAPS_PORT   = 993; 
 PROTO_POP3S_PORT   = 995;
 PROTO_L2TP_PORT    = 1701;
 PROTO_MQTT_PORT    = 1883;
 PROTO_GTP_C_PORT   = 2123 ; 
 PROTO_GTP_U_PORT   = 2152 ;  
 PROTO_GTP_PORT     = 3386;
 PROTO_SSDP_PORT    = 1900; 
 PROTO_RTP_PORT     = 5000;//5004;
 PROTO_LLMNR_PORT   = 5355;
 PROTO_MDNS_PORT    = 5353;  
 PROTO_SIP_PORT     = 5060; 
 PROTO_GNUTELLA_PORT= 6346;
 PROTO_HTTP_PORT_2  = 8080;
 PROTO_MQTT_PORT_S  = 8883;

 {ID DETECTED PROTO}
 DETECT_PROTO_UDP      = 1;
 DETECT_PROTO_TCP      = 2;
 DETECT_PROTO_DNS      = 3; 
 DETECT_PROTO_NTP      = 4;  
 DETECT_PROTO_L2TP     = 5;   
 DETECT_PROTO_DROPBOX  = 6;  
 DETECT_PROTO_MDNS     = 7;    
 DETECT_PROTO_LLMNR    = 8;     
 DETECT_PROTO_TLS      = 9; 
 DETECT_PROTO_ICMP     = 10; 
 DETECT_PROTO_ARP      = 11; 
 DETECT_PROTO_NBNS     = 12; 
 DETECT_PROTO_HTTP     = 13;
 DETECT_PROTO_POP3     = 14;   
 DETECT_PROTO_POP3S    = 15;  
 DETECT_PROTO_IMAP     = 16;   
 DETECT_PROTO_IMAPS    = 17; 
 DETECT_PROTO_SMTP     = 18; 
 DETECT_PROTO_SMTPS    = 19;  
 DETECT_PROTO_FTP      = 20; 
 DETECT_PROTO_SFTP     = 21;  
 DETECT_PROTO_STUN     = 22; 
 DETECT_PROTO_SIP      = 23;  
 DETECT_PROTO_RTP      = 24;   
 DETECT_PROTO_TFTP     = 25; 
 DETECT_PROTO_SSH      = 26;  
 DETECT_PROTO_TELNET   = 27;   
 DETECT_PROTO_QUIC     = 28;
 DETECT_PROTO_MQTT     = 29;
 DETECT_PROTO_DHCP     = 30; 
 DETECT_PROTO_IGMP     = 31; 
 DETECT_PROTO_GTP      = 32; 
 DETECT_PROTO_SSDP     = 33;
 DETECT_PROTO_GNUTELLA = 34;
 
 SRC_MAC_RAW_DATA = '41:41:41:41:41:41';
 DST_MAC_RAW_DATA = '4D:4D:4D:4D:4D:4D';


implementation

end.
