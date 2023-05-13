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

unit wpcap.Packet;

interface

Type 

  /// <summary>
  /// This record defines an internal Ethernet packet. It has four fields: the destination MAC address, the source MAC address, the Ethernet type, and an acronym.
  /// </summary>
  TIntenalETH = record
    DestAddr  : string; // The destination MAC address.
    SrcAddr   : string; // The source MAC address.
    EtherType : Uint16;   // The Ethernet type.
    Acronym   : string; // An acronym.
  end;
  PTIntenalETH = ^TIntenalETH;

 
  PTRecordGeoIP = ^TRecordGeoIP;
  TRecordGeoIP = record
    ASNumber      : String;
    ASOrganization: string;
    Location      : String;
    Latitude      : Double;
    Longitude     : Double;    
  end;
  
  /// <summary>
  /// This record defines an internal IP packet. It has several fields: the source IP address, the destination IP address, the source port, the destination port, the IP protocol, an acronym for the IP protocol, a flag indicating whether the IP is IPv6, a byte that represents the detected IP protocol, and a string that represents the IANA protocol.
  /// </summary>
  TInternalIP = record
    Src            : string;   // The source IP address.
    Dst            : string;   // The destination IP address.
    PortSrc        : Uint16;     // The source port.
    PortDst        : Uint16;     // The destination port.
    IpProto        : Uint16;     // The IP protocol.
    IpPrototr      : string;     // The IP protocol.
    ProtoAcronym   : string;   // An acronym for the IP protocol.
    IsIPv6         : Boolean;  // A flag indicating whether the IP is IPv6.
    DetectedIPProto: Uint8;     // A byte that represents the detected IP protocol.
    IANAProtoStr   : string;   // A string that represents the IANA protocol.
    SrcGeoIP       : TRecordGeoIP;
    DestGeoIP      : TRecordGeoIP;
  end;
  PTInternalIP = ^TInternalIP;
  
  TTCPParameter = record
    AcknowledgmentNumber  : Uint32;
    TimeStamp             : Integer;
    Retrasmission         : Boolean;    
    RetrasmissionFn       : Integer;
  end;
  
  TAdditionalInfo = record
    SequenceNumber    : Uint32;
    TCP               : TTCPParameter;        
    Info              : String;
    FlowID            : Integer;
    EnrichmentPresent : Boolean;
    ContentExt        : String;
    CompressType      : Integer;    
  end;
  PTAdditionalInfo = ^TAdditionalInfo;


  /// <summary>
  /// This record defines an internal packet. It has five fields: a pointer to the packet data, the packet size, the packet date, an Ethernet packet, and an IP packet.
  /// </summary>
  TInternalPacket = record
    Index          : Integer;
    PacketData     : PByte;       // A pointer to the packet data.
    PacketSize     : Integer;     // The packet size.
    PacketDate     : TDateTime;   // The packet date.
    IsMalformed    : Boolean;
    AdditionalInfo : TAdditionalInfo;
    Eth            : TIntenalETH; // An Ethernet packet.
    IP             : TInternalIP; // An IP packet.  
    XML_Detail     : String;
    RAW_Text       : AnsiString;
  end;
  PTInternalPacket = ^TInternalPacket;

 

implementation



end.
