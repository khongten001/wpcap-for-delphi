unit wpcap.Types;

interface

uses Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,wpcap.Conts,WinSock;


type

  bpf_u_int32 = LongWord;  
  Ppcap_t = Pointer;


  // PACKET_OID_STATISTICS is a structure defined in the WinPcap library that contains information related to statistics
  // of a network adapter. PPACKET_OID_STATISTICS is a pointer to this structure. The structure contains the following fields:
  //
  //Oid   : OID object identifier.
  //Length: length of the data.
  //Data  : buffer that contains the adapter statistics data.
  //
  //Note that Data is a byte array of size 2, but the actual size of the buffer may vary depending on the type of object OID.
  PPACKET_OID_STATISTICS = ^PACKET_OID_STATISTICS;
  PACKET_OID_STATISTICS = record
    Oid   : ULONG;
    Length: ULONG;
    Data  : array [0..1] of UCHAR;
  end;
  
  //PacketBurst is a structure defined in the WinPcap library that represents a burst of packets to be sent via PacketSendPackets.
  //The structure contains the following fields:
  //
  //Count   : the number of packets to send.
  //Mask    : a bitmask value indicating which packets should be sent. If bit i of Mask is set to 1, packet i will be sent.
  //pBuffers: a pointer to an array of pointers to buffers, each of which contains a packet to send.
  //pLengths: a pointer to an array of lengths, one for each packet in pBuffers. These values indicate the length of the packets to be sent.
  PPacketBurst = ^PacketBurst;
  PacketBurst = record
    Count   : ULONG;
    Mask    : ULONG;
    pBuffers: PPAnsiChar;
    pLengths: PULONG;
  end;
  
  //TMacAddress is a structure defined in the WinPcap library that represents a 6-byte Media Access Control (MAC) address.
  //The structure has an Integer of case field that can be used to access the bytes of the address as a 6-byte array (Byte) or as a single dword (DWord).
  TMacAddress = record
    case Integer of
      0: (Byte: array[0..5] of Byte);
      1: (DWord: DWORD);
  end;  
  
  //TNetInfoEx is a structure defined in the WinPcap library that contains information about the network configuration of a network adapter.
  //The structure contains the following fields:
  //
  //LinkSpeed             : Network link data rate (in bits per second).
  //TramsmitLinkSpeed     : Network link send data rate (in bits per second).
  //ReceiveLinkSpeed      : Network link receive data rate (in bits per second).
  //mtu                   : maximum transmission unit supported by the adapter.
  //MediaState            : adapter media state (connected or disconnected).
  //PhysicalMediaType     : Physical media type of the adapter (for example, Ethernet).
  //PhysicalMediumSubtype : adapter physical media subtype.
  //CurrentMacAddress     : Current MAC address of the adapter.
  //PermanentMacAddress   : Permanent MAC address of the adapter.
  //SupportedPacketFilters: Packet filters supported by the adapter.
  //MaxMulticastListSize  : maximum size of the list of multicast addresses supported by the adapter.
  //CurMulticastListSize  : current size of the list of multicast addresses supported by the adapter.
  TNetInfoEx = record
    LinkSpeed             : Int64;
    TramsmitLinkSpeed     : Int64;
    ReceiveLinkSpeed      : Int64;
    mtu                   : ULONG;
    MediaState            : DWORD;
    PhysicalMediaType     : DWORD;
    PhysicalMediumSubtype : DWORD;
    CurrentMacAddress     : TMacAddress;
    PermanentMacAddress   : TMacAddress;
    SupportedPacketFilters: ULONG;
    MaxMulticastListSize  : ULONG;
    CurMulticastListSize  : ULONG;
  end;
  
  //PACKET_STATS is a structure defined in the WinPcap library which is used to store the statistics of a network adapter or packet capture session.
  //The structure contains the following fields:
  //
  //ps_recv  : number of packets received.
  //ps_drop  : Number of packets dropped due to a full receive buffer.
  //ps_ifdrop: Number of packets dropped due to a full network adapter receive buffer.
  //bs_capt  : number of bytes captured.
  //bs_drop  : Number of bytes dropped due to a full receive buffer.
  PPACKET_STATS = ^PACKET_STATS;
  PACKET_STATS = record
    ps_recv  : ULONG;
    ps_drop  : ULONG;
    ps_ifdrop: ULONG;
    bs_capt  : Int64;
    bs_drop  : Int64;
  end;

  //PACKET is a structure defined in the WinPcap library which is used to represent a network packet.
  //The structure contains the following fields:
  //
  //Buffer   : pointer to the buffer containing the packet.
  //Length   : size of the buffer in bytes.
  //ulWireLen: packet size in bytes.
  //TimeStamp: timestamp of the package.
  //sb       : source MAC address of the packet.
  //db       : destination MAC address of the packet.
  //Flags    : flags associated with the package.
  //Reserved : field reserved for future use.           
  PPACKET = ^PACKET;
  PACKET = packed record
    Buffer   : PAnsiChar;
    Length   : ULONG;
    ulWireLen: ULONG;
    TimeStamp: TTimeStamp;
    sb       : TMacAddress;
    db       : TMacAddress;
    Flags    : ULONG;
    Reserved : ULONG;
  end;

  //The RMON_STATS structure is used to return the RMON statistics of a network interface.
  //The structure has three array-type fields of ULONGs: rx, tx, and alarms, which represent RMON statistics for the receiver, transmitter, and alarms, respectively.
  //The structure is defined as a record with the rx field of 16 elements, the tx field of 16 elements and the alarms field of 2 elements.
  //
  //The PRMON_STATS pointer is used as a data type to pass a pointer to an RMON_STATS structure to a function that requires this parameter type.
  PRMON_STATS = ^RMON_STATS;
  RMON_STATS = packed record
    rx    : array[0..15] of ULONG;   // RMON statistics for the receiver
    tx    : array[0..15] of ULONG;   // RMON statistics for the transmitter
    alarms: array[0..1] of ULONG;    // RMON statistics for alarms
  end;

  //The ADAPTER_INFO structure is used to return information about the network adapter, such as the name, description, MAC address,
  //the maximum lookahead buffer size, adapter driver version, working mode, filter driver name, i
  //l number of times the adapter has been opened, and so on.
  //
  //The structure also contains a Network field of type TNetInfoEx, which provides detailed information about the network.
  //The PADAPTER_INFO pointer is used as a data type to pass a pointer to an ADAPTER_INFO structure to a function that requires this parameter type.
  PADAPTER_INFO = ^ADAPTER_INFO;
  ADAPTER_INFO = packed record
    Name            : array[0..ADAPTER_NAME_LENGTH - 1] of AnsiChar;  // network adapter name
    Description     : array[0..ADAPTER_DESC_LENGTH - 1] of AnsiChar;  // description of the network adapter
    Flags           : ULONG;                                          // flags indicating the properties of the adapter
    MacAddress      : TMACAddress;                                    // MAC address of the network adapter
    MaxLookaheadData: ULONG;                                          // maximum size of the lookahead buffer
    Len             : ULONG;                                          // size of the structure in bytes
    Version         : array[0..7] of AnsiChar;                        // adapter driver version
    WorkingMode     : ULONG;                                          // adapter working mode
    FilterDriver    : AnsiString;                                     // filter driver name (if any)
    NumOfOpens      : ULONG;                                          // number of times the adapter has been opened
    Reserved        : array[0..5] of ULONG;                           // reserved fields
    Handle          : THandle;                                        // network adapter handle
    Network         : TNetInfoEx;                                     // network information
  end;
  
  //The PACKET_OID_DATA structure is used to represent data related to an Object IDentifier (OID).
  //The Oid field represents the OID in question, the Length field represents the length of the data contained in the Data field, while the Data field represents the data itself.
  //Declaring the Data field as an array of UCHARs of length 0 dynamically allocates the space needed for the actual data based on the size specified by the Length field.
  //The PPACKET_OID_DATA pointer is used to refer to the PACKET_OID_DATA structure.
  PPACKET_OID_DATA = ^PACKET_OID_DATA;
  PACKET_OID_DATA = packed record
    Oid   : ULONG;
    Length: ULONG;
    Data  : array [0..0] of UCHAR;
  end;
  
  //The BPF_insn structure represents an instruction of the Berkeley Packet Filter (BPF) program. code represents the code of the operation to be performed, jt and jf
  // are the positions of the statement to be executed if the test succeeds or fails respectively, while k represents a constant value used by the operation.
  //PBPF_insn is a pointer to this structure and is often used as a parameter for building a BPF program using the pcap_compile() function.
  PBPF_insn = ^BPF_insn;
  BPF_insn = packed record
    code: USHORT;
    jt  : BYTE;
    jf  : BYTE;
    k   : ULONG;
  end;
  
  //The BPF_program structure is used to represent a compiled Berkeley Packet Filter (BPF) program, which can be passed to the PacketSetBPF() function
  //to set a BPF filter for a network card. The bf_len field represents the number of BPF instructions in the program, while the bf_insns field is a pointer to
  //an array of BPF instructions (BPF_insn) that make up the program. The PBPF_program pointer is used to refer to the BPF_program structure.
  PBPF_program = ^BPF_program;
  BPF_program = packed record
    bf_len  : UINT;
    bf_insns: PBPF_insn;
  end;
    
  //In general, this enumeration is used to specify the type of dump file to be generated by the PacketDumpOpen() function.
  Packet_Dump_File_Type = (
    PACKET_DUMP_TYPE_STANDARD,      // Standard dump files
    PACKET_DUMP_TYPE_TCPDUMP,       // Dump file in tcpdump format
    PACKET_DUMP_TYPE_TCPDUMP_LONG,  // Dump file in extended tcpdump format
    PACKET_DUMP_TYPE_NLANR,         // Dump file in NLANR format
    PACKET_DUMP_TYPE_NTAR           // Dump file in NTAR format
  );
  
  //the TMulticastList structure represents a list of multicast addresses which can be used with the PacketSetMulticastList() function to set
  //list of multicast addresses for a specific network adapter. The structure contains an array of WPCAP_MAX_MCAST_LIST (usually 32) addresses of type 
  //TMacAddress and a McAddressCount field indicating the actual number of multicast addresses in the array.
  TMulticastList = record
    McAddress     : array [0..WPCAP_MAX_MCAST_LIST-1] of TMacAddress;
    McAddressCount: Integer;
  end;
  
  //bf_len represents the length in bytes of the list of BPF instructions contained in bf_insns,
  //while bf_insns represents a pointer to the BPF instruction list itself.
  TPacketFilter = record
    bf_len  : UInt32;
    bf_insns: PBPF_insn;
  end;


  //eader of a packet in the dump file.
  //Each packet in the dump file is prepended with this generic header. 
  //This gets around the problem of different headers for different packet interfaces.
  Tpcap_pkthdr = record
    ts     : timeval;      //Time stamp
    caplen : bpf_u_int32;  //length of portion present
    len    : bpf_u_int32;  //length this packet (off wire)
  end;
  PTpcap_pkthdr = ^Tpcap_pkthdr;

  
  TIPAddrBytes = array [0 .. 3] of Byte;
  TIPAddress = record
      case Integer of
        0: (Bytes: TIPAddrBytes);
        1: (Addr: Cardinal);
    end;


  // equivalent to the Internet Protocol Version 4 section of wireshark in the package detail
  PIPHeader = ^TIPHeader;
  TIPHeader = packed record
    VerLen  : Byte;        // Version and length
    TOS     : Byte;        // of service
    TotalLen: Word;        // Length
    ID      : Word;        // Identification
    FlagsOff: Word;        // Flags and fragment offset
    TTL     : Byte;        // Time to live
    Protocol: Byte;        // Protocol
    Checksum: Word;        // Checksum
    SrcIP   : TIPAddress;  // Source IP address
    DestIP  : TIPAddress;  // Destination IP address
  end;

 //In this structure for UPD packet, the fields are:
 //
 //uh_sport: the source port (2 bytes)
 //uh_dport: the destination port (2 bytes)
 //uh_ulen : the length of the UDP datagram, header included (2 bytes)
 //uh_sum  : the UDP datagram checksum (2 bytes)
 PUDPHdr = ^TUDPHdr;
  TUDPHdr = packed record
    SrcPort   : Word;    // UDP source port
    DstPort   : Word;    // UDP destination port
    Lenght    : Word;    // UDP length
    CheckSum  : Word;    // UDP checksum
  end;  
  
  // This structure contains three fields:
  //
  // DestAddr : 6 byte array containing destination MAC address
  // SrcAddr  : 6 byte array that contains the source MAC address
  // EtherType: 16-bit field indicating the type of higher protocol (for example, IPv4 or ARP).
  PETHHdr = ^TETHHdr;
  TETHHdr = packed record
    DestAddr : array [0..5] of Byte; // Indirizzo MAC di destinazione
    SrcAddr  : array [0..5] of Byte;  // Indirizzo MAC di origine
    EtherType: Word;                // Tipo di protocollo superiore
  end;  

  // The structure contains the following fields:
  //
  // Version           : indicates the version of the IPv6 protocol (fixed 6-bit value equal to 0110);
  // TrafficClass      : indicates the traffic class, divided into 6 bits of DSCP (Differentiated Services Code Point) and 2 bits of ECN (Explicit Congestion Notification);
  // FlowLabel         : it is a 20-bit value which is used to identify the data flow, so as to be able to apply quality of service policies;
  // PayloadLength     : indicates the length of the packet payload (excluding headers and any trailers);
  // NextHeader        : indicates the type of header following the IPv6 header; it can assume values defined in the IANA "Protocol Numbers" register;
  // HopLimit          : indicates the maximum number of hops that the packet can go through before being dropped;
  // SourceAddress 
  // DestinationAddress: contain the source and destination IPv6 addresses of the packet.
  //
  // The constant TIPv6AddrBytes indicates an array of 16 bytes representing an IPv6 address,
  // where each pair of bytes is represented in hexadecimal format, separated by a colon.
  TIPv6AddrBytes = array [0..15] of Byte;

  TIPv6Header = packed record
    Version           : Byte;
    TrafficClass      : Byte;
    FlowLabel         : Word;
    PayloadLength     : Word;
    NextHeader        : Byte;
    HopLimit          : Byte;
    SourceAddress     : TIPv6AddrBytes;
    DestinationAddress: TIPv6AddrBytes;
  end;
  PIPv6Header = ^TIPv6Header;
  

implementation

end.
