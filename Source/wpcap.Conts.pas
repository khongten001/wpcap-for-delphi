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

  ETH_HEADER_LEN = 14;


  DLT_EN10MB = 1; // Ethernet (10Mb) link type identifier
  
  MAX_PACKET_SIZE = 65535; // Maximum size of the packets to be captured


  {IPPROTO}
  IPPROTO_IPV6    = 41;    // IPv6 header
  IPPROTO_ICMPV6  = 58;    // ICMPv6  
  IPPROTO_GRE     = 47;
  IPPROTO_ESP     = 50;
  IPPROTO_AH      = 51;
  IPPROTO_ROUTING = 42;    // Routing
  IPPROTO_PGM     = 113;
  IPPROTO_SCTP    = 132;

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


  
  


  

implementation

end.
