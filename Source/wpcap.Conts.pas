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
  IPPROTO_ICMPV62    = 128;  
  
  {ETHERNET TYPE}
  ETH_P_LOOP      = $0060;  // Ethernet Loopback packet
  ETH_P_PUP       = $0200;  // Xerox PUP packet
  ETH_P_PUPAT     = $0201;  // Xerox PUP Addr Trans packet
  ETH_P_TSN       = $22F0;  // TSN (IEEE 1722 Audio/Video Bridging)
  ETH_P_IP        = $0800;  // Internet Protocol packet
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
 PROTO_DNS_PORT   = 53;
 PROTO_LLMNR_PORT = 5355;
 PROTO_MDNS_PORT  = 5353;   
 PROTO_NTP_PORT   = 123;
 PROTO_L2TP_PORT  = 1701;
 PROTO_TLS_PORT   = 443;

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

  {DNS QUESTION TYPE}
  TYPE_DNS_QUESTION_A			      = 1;
  TYPE_DNS_QUESTION_NS		     	= 2;
  TYPE_DNS_QUESTION_MD		     	= 3;
  TYPE_DNS_QUESTION_MF		     	= 4;
  TYPE_DNS_QUESTION_CNAME	     	= 5;
  TYPE_DNS_QUESTION_SOA		     	= 6;
  TYPE_DNS_QUESTION_MB		     	= 7;
  TYPE_DNS_QUESTION_MG		     	= 8;
  TYPE_DNS_QUESTION_MR		     	= 9;
  TYPE_DNS_QUESTION_NULL	     	= 10;
  TYPE_DNS_QUESTION_WKS		     	= 11;
  TYPE_DNS_QUESTION_PTR		     	= 12;
  TYPE_DNS_QUESTION_HINFO	     	= 13;
  TYPE_DNS_QUESTION_MINFO	     	= 14;
  TYPE_DNS_QUESTION_MX		     	= 15;
  TYPE_DNS_QUESTION_TXT		     	= 16;
  TYPE_DNS_QUESTION_RP		     	= 17;
  TYPE_DNS_QUESTION_AFSDB	     	= 18;
  TYPE_DNS_QUESTION_X25		     	= 19;
  TYPE_DNS_QUESTION_ISDN	     	= 20;
  TYPE_DNS_QUESTION_RT		     	= 21;
  TYPE_DNS_QUESTION_NSAP	     	= 22;
  TYPE_DNS_QUESTION_NSAP_PTR    = 23;
  TYPE_DNS_QUESTION_SIG		     	= 24;
  TYPE_DNS_QUESTION_KEY		     	= 25;
  TYPE_DNS_QUESTION_PX		     	= 26;
  TYPE_DNS_QUESTION_GPOS	     	= 27;
  TYPE_DNS_QUESTION_AAAA	     	= 28;
  TYPE_DNS_QUESTION_LOC		     	= 29;
  TYPE_DNS_QUESTION_NXT		     	= 30;
  TYPE_DNS_QUESTION_EID		     	= 31;
  TYPE_DNS_QUESTION_NIMLOC     	= 32;
  TYPE_DNS_QUESTION_SRV		     	= 33;
  TYPE_DNS_QUESTION_ATMA	     	= 34;
  TYPE_DNS_QUESTION_NAPTR	     	= 35;
  TYPE_DNS_QUESTION_KX		     	= 36;
  TYPE_DNS_QUESTION_CERT	     	= 37;
  TYPE_DNS_QUESTION_A6		     	= 38;
  TYPE_DNS_QUESTION_DNAME	     	= 39;
  TYPE_DNS_QUESTION_SINK	     	= 40;
  TYPE_DNS_QUESTION_OPT		     	= 41;
  TYPE_DNS_QUESTION_APL		     	= 42;
  TYPE_DNS_QUESTION_DS		     	= 43;
  TYPE_DNS_QUESTION_SSHFP	     	= 44;
  TYPE_DNS_QUESTION_IPSECKEY    = 45;
  TYPE_DNS_QUESTION_RRSIG	     	= 46;
  TYPE_DNS_QUESTION_NSEC	     	= 47;
  TYPE_DNS_QUESTION_DNSKEY     	= 48;
  TYPE_DNS_QUESTION_DHCID	     	= 49;
  TYPE_DNS_QUESTION_NSEC3	     	= 50;
  TYPE_DNS_QUESTION_NSEC3PARAM	= 51;
  TYPE_DNS_QUESTION_TLSA		   	= 52;
  TYPE_DNS_QUESTION_SMIMEA			= 53;
  TYPE_DNS_QUESTION_HIP		    	= 55;
  TYPE_DNS_QUESTION_NINFO	   		= 56;
  TYPE_DNS_QUESTION_RKEY	   		= 57;
  TYPE_DNS_QUESTION_TALINK			= 58;
  TYPE_DNS_QUESTION_CDS		    	= 59;
  TYPE_DNS_QUESTION_CDNSKEY			= 60;
  TYPE_DNS_QUESTION_OPENPGPKEY	= 61;
  TYPE_DNS_QUESTION_CSYNC			  = 62;
  TYPE_DNS_QUESTION_SPF			    = 99;
  TYPE_DNS_QUESTION_UINFO			  = 100;
  TYPE_DNS_QUESTION_UID		     	= 101;
  TYPE_DNS_QUESTION_GID		     	= 102;
  TYPE_DNS_QUESTION_UNSPEC			= 103;
  TYPE_DNS_QUESTION_NID		     	= 104;
  TYPE_DNS_QUESTION_L32		     	= 105;
  TYPE_DNS_QUESTION_L64		     	= 106;
  TYPE_DNS_QUESTION_LP		     	= 107;
  TYPE_DNS_QUESTION_EUI48	     	= 108;
  TYPE_DNS_QUESTION_EUI64	     	= 109;
  TYPE_DNS_QUESTION_ALL         = 255;
  TYPE_DNS_QUESTION_URI		     	= 256;
  TYPE_DNS_QUESTION_CAA		     	= 257;

  TYPE_DNS_QUESTION_TA		     	= 32768;
  TYPE_DNS_QUESTION_DLV		     	= 32769; 

  {L2TP FLAG}
  L2TP_HDR_FLAG_OFFSET_SIZE_INCLUDED = $1000; // Indicates whether the Offset Size field is present in the L2TP header
  L2TP_HDR_FLAG_SEQUENCE             = $2000; // Indicates whether the Sequence Number field is present in the L2TP header
  L2TP_HDR_FLAG_PRIORITY             = $4000; // Indicates whether the Priority field is present in the L2TP header
  L2TP_HDR_FLAG_LENGTH_INCLUDED      = $8000; // Indicates whether the Length field is present in the L2TP header
  L2TP_HDR_FLAG_D_BIT                = $0800; // Delivery Notification Request bit
  L2TP_HDR_FLAG_S_BIT                = $0400; // Strict-Source bit
  L2TP_HDR_FLAG_L_BIT                = $0200; // Length-Change bit
  L2TP_HDR_FLAG_T_BIT                = $0100; // TTL-Present bit
  L2TP_HDR_FLAG_F_BIT                = $0080; // Firmware-Version bit
  L2TP_HDR_FLAG_S_RESERVED           = $007F; // Reserved bits in the Flags field (must be set to 0)  


implementation

end.
