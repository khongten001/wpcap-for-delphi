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

unit wpcap.Level.IP;

interface

uses
  System.Generics.Collections, wpcap.Packet,  wpcap.StrUtils,wpcap.Protocol.ICMP,wpcap.Protocol.IGMP,
  wpcap.Conts, System.SysUtils, wpcap.Level.Eth, wpcap.IANA.DbPort,Variants,wpcap.IpUtils,idGlobal,
  wpcap.Protocol.UDP, wpcap.Protocol.TCP,wpcap.BufferUtils,wpcap.Types,winsock2,System.Diagnostics;


type  
  {https://www.rfc-editor.org/rfc/rfc791}

  {
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  }

  

  
  // equivalent to the Internet Protocol Version 4 section of wireshark in the package detail
  PTIPHeader = ^TIPHeader;
  TIPHeader = packed record
    VerLen  : Uint8;        // Version and length
    TOS     : Uint8;        // of service
    TotalLen: Uint16;       // Length
    ID      : Uint16;       // Identification
    FlagsOfF: Uint16;       // Flags and fragment offset
    TTL     : Uint8;        // Time to live
    Protocol: Uint8;        // Protocol
    Checksum: Uint16;       // Checksum
    SrcIP   : TIPAddress;   // Source IP address
    DestIP  : TIPAddress;   // Destination IP address
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
  
  {https://www.rfc-editor.org/rfc/rfc2460}

  {
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version| Traffic Class |           Flow Label                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Payload Length        |  Next Header  |   Hop Limit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                         Source Address                        +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                      Destination Address                      +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  }
  
  TIPv6Header = packed record
    Version           : Byte;              // IP version number, should be 6 for IPv6
    TrafficClass      : Byte;              // Traffic class, includes priority and flow label
    FlowLabel         : Word;              // Label for a sequence of packets in a flow
    PayloadLength     : Word;              // Length of the payload (data) following the header, in bytes
    NextHeader        : Byte;              // Identifies the type of the next header after this IPv6 header
    HopLimit          : Byte;              // Decremented by 1 at each node that forwards the packet, until it reaches 0 and is dropped
    SourceAddress     : TIPv6AddrBytes;    // Source IPv6 address
    DestinationAddress: TIPv6AddrBytes;    // Destination IPv6 address
  end;
  PIpv6Header = ^TIPv6Header;  

  TDifferentiatedServices = record
    Precedence : String;
    Delay      : Boolean;
    Throughput : Boolean;
    Reliability: Boolean;
  end;

  {
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Next Header  |  Hdr Ext Len  |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    |                                                               |
    .                                                               .
    .                            Options                            .
    .                                                               .
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Next Header          8-bit selector.  Identifies the type of header
                        immediately following the Hop-by-Hop Options
                        header.  Uses the same values as the IPv4
                        Protocol field [RFC-1700 et seq.].

   Hdr Ext Len          8-bit unsigned integer.  Length of the Hop-by-
                        Hop Options header in 8-octet units, not
                        including the first 8 octets.

   Options              Variable-length field, of length such that the
                        complete Hop-by-Hop Options header is an integer
                        multiple of 8 octets long.  Contains one or more
                        TLV-encoded options.
  }  
  THopByHopOption = packed record
    NextHeader  : Byte;
    HdrExtLen   : Byte;
  end;
  PTHopByHopOption = ^THopByHopOption;


  {
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
    |  Option Type  |  Opt Data Len |  Option Data
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - - -
  }  
  TOptionHeader = packed record
    OptType    : Byte;
    OptDataLen : Byte;
  end;
  PTOptionHeader = ^TOptionHeader;  

  {

    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    .                                                               .
    .                       type-specific data                      .
    .                                                               .
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

     Next Header          8-bit selector.  Identifies the type of header
                          immediately following the Routing header.  Uses
                          the same values as the IPv4 Protocol field
                          [RFC-1700 et seq.].

     Hdr Ext Len          8-bit unsigned integer.  Length of the Routing
                          header in 8-octet units, not including the first
                          8 octets.

     Routing Type         8-bit identifier of a particular Routing header
                          variant.

     Segments Left        8-bit unsigned integer.  Number of route
                          segments remaining, i.e., number of explicitly
                          listed intermediate nodes still to be visited
                          before reaching the final destination.

     type-specific data   Variable-length field, of format determined by
                          the Routing Type, and of length such that the
                          complete Routing header is an integer multiple
                          of 8 octets long.

  }

  TRoutingHeader = packed record
    NextHeader  : Byte;
    HdrExtLen   : Byte;
    RoutingType : Byte;
    SegmentsLeft: Byte;
  end;
  PTRoutingHeader = ^TRoutingHeader;

  

  TWpcapIPHeader = class(TWPcapEthHeader) 
  Strict private
    
  private
    /// <summary>
    ///   Determines if the given packet size is valid for an Ethernet frame with an IPv4 or IPv6 header.
    /// </summary>
    /// <param name="aPacketSize">The size of the packet in bytes.</param>
    /// <returns>
    ///   True if the packet size is valid, False otherwise.
    /// </returns>
    class function isValidSizeIP(const aPacketData: PByte;aPacketSize: Integer;aIsIpV6:Boolean): Boolean;static;

    /// <summary>
    ///   Analyzes the IP protocol of the packet data and populates the provided internal IP record with the appropriate data.
    ///   If the protocol is not UDP or TCP, the protocol acronym is left empty and the detected IP protocol value is set to 0.
    /// </summary>
    /// <param name="aPacketData">A pointer to the start of the packet data.</param>
    /// <param name="aPacketSize">The size of the packet data in bytes.</param>
    /// <param name="aInternalIP">A pointer to the internal IP record to be populated with the analysis results.</param>
    class procedure AnalyzeIPProtocol(const aPacketData: PByte; aPacketSize: Integer; aInternalIP: PTInternalIP;aLogging:Boolean);
    class function DecodeDifferentiatedServices(TOS: Byte): TDifferentiatedServices; static;
    class function GetIpFlag(aFlags: byte;AListDetail:TListHeaderString;aStartLevel:Integer): string;
    class function HeaderLenConvert(const aVerLen: Word): Word; static;
    class function ExtentionHeader(const aPacketData: PByte;aStartLevel:integer;var aCurrentPos: Integer; var aIpProto: word;AListDetail: TListHeaderString): Boolean; static;
    class function ExtentionHeaderOptions(const aPacketData: PByte;aStartLevel:Integer;var aCurrentPos: Integer; var aIpProto: word;AListDetail: TListHeaderString): Boolean; static;
  protected
     
  public
    /// <summary>
    ///   Returns a pointer to the IPv4 header in the provided packet data.
    /// </summary>
    /// <param name="aPacketData">A pointer to the start of the packet data.</param>
    /// <param name="aPacketSize">The size of the packet data in bytes.</param>
    /// <returns>A pointer to the IPv4 header in the packet data.</returns>
    class function HeaderIPv4(const aPacketData: PByte; aPacketSize: Integer): PTIPHeader; static;

    /// <summary>
    ///   Returns a pointer to the IPv6 header in the provided packet data.
    /// </summary>
    /// <param name="aPacketData">A pointer to the start of the packet data.</param>
    /// <param name="aPacketSize">The size of the packet data in bytes.</param>
    /// <returns>A pointer to the IPv6 header in the packet data.</returns>
    class function HeaderIPv6(const aPacketData: PByte; aPacketSize: Integer): PIpv6Header; static;

    /// <summary>
    ///   Returns the size of the IP header in bytes based on whether the provided packet data represents an IPv4 or IPv6 packet.
    /// </summary>
    /// <returns>The size of the IP header in bytes.</returns>
    class function HeaderIPSize(const aPacketData: PByte; aPacketSize: Integer;aCheckNextHeader:Boolean=True): Word; static;

    /// <summary>
    ///   Returns the size of the IP header and Eth Header in bytes based on whether the provided packet data represents an IPv4 or IPv6 packet.
    /// </summary>
    /// <returns>The size of the IP header in bytes.</returns>
    class function EthAndIPHeaderSize(const aPacketData: PByte; aPacketSize: Integer;aCheckNextHeader:Boolean=True): Word;static;

    /// <summary>
    ///   Returns a dictionary containing the string representation of each field in the IP header, as well as its value in the provided packet data.
    /// </summary>
    /// <returns>A dictionary containing the string representation of each field in the IP header, as well as its value in the provided packet data.</returns>
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer;AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;override;

    ///  <summary>
    ///  Analyzes the IP header of the packet data and stores the result in the given InternalIP record.
    ///  The IP header can be of either IPv4 or IPv6. This function determines the IP version and reads the appropriate fields.
    ///  The IANA dictionary is used to translate the protocol number to an acronym, which is stored in the InternalIP record.
    ///  Returns true if the analysis is successful, false otherwise.
    ///  </summary>
    ///  <param name="aPacketData">A pointer to the packet data buffer</param>
    ///  <param name="aPacketSize">The size of the packet data buffer</param>
    ///  <param name="aIANADictionary">A dictionary containing IANA protocol information</param>
    ///  <param name="aInternalIP">A pointer to the InternalIP record to be filled with the analysis result</param>
    ///  <returns>True if the IP header analysis is successful, False otherwise</returns>
    class function InternalIP(const aPacketData: PByte; aPacketSize: Integer; aIANADictionary: TDictionary<String, TIANARow>; aInternalIP: PTInternalIP;aFallowIpLevel,aLogging:Boolean): Boolean;static;

    /// <summary>
    /// This function takes a 16-bit IPv6 protocol number and returns its name as a string. 
    /// The function checks if the protocol number matches one of the well-known protocols defined by IANA and returns the corresponding name, 
    //  otherwise it returns the hexadecimal representation of the protocol number. 
    ///
    /// The well-known protocols include ICMP, TCP, UDP, and more.
    /// </summary>
    class function GetIPv6ProtocolName(aProtocol: Word): string;static;

    /// <summary>
    /// This function takes a 16-bit IPv4 protocol number and returns its name as a string. 
    /// The function checks if the protocol number matches one of the well-known protocols defined by IANA and returns the corresponding name, 
    //  otherwise it returns the hexadecimal representation of the protocol number. 
    ///
    /// The well-known protocols include ICMP, TCP, UDP, and more.
    /// </summary>
    class function GetIPv4ProtocolName(aProtocol: Word): string;static;
    class function GetNextBufferHeader(const aPacketData: PByte; aPacketSize,aHeaderPrevLen,aNewIpProto: Integer; var aNewPacketLen: Integer;aCheckNextHeader:Boolean): PByte; static;    
  end;

implementation

uses wpcap.protocol;

class function TWpcapIPHeader.GetIpFlag(aFlags: byte;AListDetail: TListHeaderString;aStartLevel:Integer): string;
begin
  {
    Various Control Flags.

      Bit 0: reserved, must be zero
      Bit 1: (DF) 0 = May Fragment,  1 = Don't Fragment.
      Bit 2: (MF) 0 = Last Fragment, 1 = More Fragments.

          0   1   2
        +---+---+---+
        |   | D | M |
        | 0 | F | F |
        +---+---+---+
  }

	                                            
  AListDetail.Add(AddHeaderInfo(aStartLevel+2,'IP.IPv4.MayFragment','May Fragment:',GetBitValue(aFlags,2)=1,nil,0)); 
  AListDetail.Add(AddHeaderInfo(aStartLevel+2,'IP.IPv4.LastFragment','Last Fragment:',GetBitValue(aFlags,3)=1,nil,0));    
end;

class function TWpcapIPHeader.DecodeDifferentiatedServices(TOS: Byte): TDifferentiatedServices;
var LPrecedenceId : Byte;
begin
  begin
    {
             0     1     2     3     4     5     6     7
          +-----+-----+-----+-----+-----+-----+-----+-----+
          |                 |     |     |     |     |     |
          |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
          |                 |     |     |     |     |     |
          +-----+-----+-----+-----+-----+-----+-----+-----+
    }
  
    LPrecedenceId      := TOS shr 5;
    Result.Delay       := GetBitValue(TOS,4)=1;
    Result.Throughput  := GetBitValue(TOS,5)=1;
    Result.Reliability := GetBitValue(TOS,6)=1;
    {
       Precedence

          111 - Network Control
          110 - Internetwork Control
          101 - CRITIC/ECP
          100 - Flash Override
          011 - Flash
          010 - Immediate
          001 - Priority
          000 - Routine
     }

      case LPrecedenceId of
        7: Result.Precedence := 'Network Control';
        6: Result.Precedence := 'Internetwork Control';
        5: Result.Precedence := 'CRITIC/ECP';
        4: Result.Precedence := 'Flash Override';
        3: Result.Precedence := 'Flash';
        2: Result.Precedence := 'Immediate';
        1: Result.Precedence := 'Priority';
        0: Result.Precedence := 'Routine';
      end;
  end;
end;

{ TIPHeaderClas }
class function TWpcapIPHeader.isValidSizeIP(const aPacketData: PByte;aPacketSize: Integer;aIsIpV6:Boolean): Boolean;
begin
  if aIsIpV6 then
     result := aPacketSize >HeaderEthSize(aPacketData,aPacketSize)+SizeOf(TIPv6Header)
  else
     result := aPacketSize >HeaderEthSize(aPacketData,aPacketSize)+SizeOf(TIPHeader);
end;

class function TWpcapIPHeader.HeaderIPv4(const aPacketData: PByte;aPacketSize: Integer): PTIPHeader;
var lHeaderSize : integer;
begin
  Result := nil;
  if not isValidSizeIP(aPacketData,aPacketSize,False) then exit;
  
  lHeaderSize:= HeaderEthSize(aPacketData,aPacketSize);
  Result := PTIPHeader(aPacketData + lHeaderSize);
  
  if  aPacketSize < lHeaderSize+HeaderLenConvert(Result.VerLen) then   
    Result := nil;
end;

class function TWpcapIPHeader.HeaderIPv6(const aPacketData: PByte;aPacketSize: Integer): PIpv6Header;
begin
  Result := nil;
  if not isValidSizeIP(aPacketData,aPacketSize,True) then exit;

  Result := PIPv6Header(aPacketData + HeaderEthSize(aPacketData,aPacketSize));
end;

class function TWpcapIPHeader.HeaderIPSize(const aPacketData: PByte;aPacketSize: Integer;aCheckNextHeader:Boolean=True): Word;
var LCurrentPos      : Integer;
    LHeaderV6        : PIpv6Header;  
    LIpProto         : word; 
    LHeaderV4        : PTIPHeader;  
    LNewPacketLen    : Integer;
    LNewPacketData   : PByte;
    LHeaderSize      : Integer;
begin
  Result := 0;
  
  if IpClassType(aPacketData,aPacketSize) = imtIpv6 then
  begin
    LHeaderSize := HeaderEthSize(aPacketData,aPacketSize);
    Result      := SizeOf(TIPv6Header);
    LCurrentPos := LHeaderSize + Result;
    LHeaderV6   := HeaderIPv6(aPacketData,aPacketSize);
    LIpProto    := LHeaderV6.NextHeader;
    ExtentionHeader(aPacketData,0,LCurrentPos,LIpProto,nil);

    if (LIpProto = IPPROTO_IP) and aCheckNextHeader  then
    begin
      LNewPacketData  := GetNextBufferHeader(aPacketData,aPacketSize,Result,ETH_P_IP,LNewPacketLen,True);
      Try
        Inc(Result,HeaderIPSize(LNewPacketData, LNewPacketLen));
      Finally
        FreeMem(LNewPacketData);
      End;              
      Exit;
    end;
    if LCurrentPos > LHeaderSize + SizeOf(TIPv6Header) then
      Result:= LCurrentPos - LHeaderSize;
  end
  else
  begin
    LHeaderV4 := HeaderIPv4(aPacketData,aPacketSize);
    if not Assigned(LHeaderV4) then Exit;
    
    Result  := HeaderLenConvert(LHeaderV4.VerLen);

    if (LHeaderV4.Protocol = IPPROTO_IPV6) and aCheckNextHeader then
    begin
      LNewPacketData := GetNextBufferHeader(aPacketData,aPacketSize,Result,ETH_P_IPV6,LNewPacketLen,True);
      Try
        Inc(Result,HeaderIPSize(LNewPacketData, LNewPacketLen));
      Finally
        FreeMem(LNewPacketData);
      End;
    end;    
  end;
end;

class Function TWpcapIPHeader.GetNextBufferHeader(const aPacketData: PByte;aPacketSize,aHeaderPrevLen,aNewIpProto: Integer;var aNewPacketLen: Integer;aCheckNextHeader:Boolean):PByte;
var lHeaderEthLen    : Integer;
begin
  Result := nil;
  if aHeaderPrevLen = 0 then
      aHeaderPrevLen := HeaderIPSize(aPacketData,aPacketSize,aCheckNextHeader);
      
  lHeaderEthLen  := HeaderEthSize(aPacketData,aPacketSize);
  aNewPacketLen  := aPacketSize -aHeaderPrevLen; 
  if aNewPacketLen > 0 then
  begin
    GetMem(Result,aNewPacketLen);
    Move(aPacketData^,Result^,lHeaderEthLen);
    PETHHdr(Result)^.EtherType := ntohs(aNewIpProto);
    Move(PByte(aPacketData + lHeaderEthLen + aHeaderPrevLen)^,Pbyte(Result + lHeaderEthLen)^, aNewPacketLen- lHeaderEthLen);
  end;
end;

class Function TWpcapIPHeader.HeaderLenConvert(const aVerLen: Word):Word;
begin
  Result := (aVerLen and $0F) * 4;
end;

class function TWpcapIPHeader.HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer;AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;  
var LHederInfo         : THeaderString;
    LInternalIP        : PTInternalIP;
    LHeaderV4          : PTIPHeader;
    LHeaderV6          : PIpv6Header;   
    LFlagOffInfo       : String;
    LTrafficClassValue : Byte;
    LPriority          : Byte;   
    LFlowLabel         : Integer;   
    LTrafficClass      : Byte; 
    LTOSInfo           : TDifferentiatedServices;
    LIpProto           : word; 
    LCurrentPos        : Integer;
    LNewPacket         : PByte;
    LNewPacketSize     : Integer;    
begin
  Result        := False;
  FisFilterMode := aisFilterMode;
  new(LInternalIP);
  Try
    if not InternalIP(aPacketData,aPacketSize,nil,LInternalIP,False,False) then exit;
    
    if not Assigned(AListDetail) then
      AListDetail := TListHeaderString.Create;

    LHeaderV4 := HeaderIPv4(aPacketData,aPacketSize);
    if not Assigned(LHeaderV4) then Exit;    
    if LInternalIP.IsIpv6 then
    begin
     
      Result                 := True;
      LHeaderV6              := HeaderIPv6(aPacketData,aPacketSize);

      AListDetail.Add(AddHeaderInfo(aStartLevel,'IP.IPv6','Internet protocol version 6',Format('Src: %s, Dst %s',[LInternalIP.Src,LInternalIP.Dst]),PByte(LHeaderV6),HeaderIPSize(aPacketData,aPacketSize))); 

      AListDetail.Add(AddHeaderInfo(aStartLevel+1,'IP.IPv6.HeaderLen','Header length:',HeaderIPSize(aPacketData,aPacketSize),nil,0));  
      AListDetail.Add(AddHeaderInfo(aStartLevel+1,'IP.IPv6.Version','Version:',(LHeaderV6.Version shr 4) and $0F,PByte(@LHeaderV6.Version),SizeOf(LHeaderV6.Version))); 


      // Leggere il campo TrafficClass
      LTrafficClassValue     := wpcapntohs(LHeaderV6.TrafficClass);
      LPriority              := LTrafficClassValue shr 6;        // 6 bit più significativi
      LFlowLabel             := LTrafficClassValue and $0FFFFF;  // 20 bit per il flow label
      LTrafficClass          := LTrafficClassValue and $3;       // 2 bit meno significativi per la classe di traffico   

      AListDetail.Add(AddHeaderInfo(aStartLevel+1,'IP.IPv6.TrafficClass','Traffic Class:',LTrafficClassValue,PByte(@LHeaderV6.TrafficClass),SizeOf(LHeaderV6.TrafficClass)));          
      AListDetail.Add(AddHeaderInfo(aStartLevel+2,'IP.IPv6.TrafficClass.Priority','Priority:',LPriority,nil,0));          
      AListDetail.Add(AddHeaderInfo(aStartLevel+2,'IP.IPv6.TrafficClass.FlowLabel','FlowLabel:',LFlowLabel,nil,0));   
      AListDetail.Add(AddHeaderInfo(aStartLevel+2,'IP.IPv6.TrafficClass.Class','Class:',LTrafficClass,nil,0));                               
           
      // Leggere il campo FlowLabel

      // Reverse the byte order of the FlowLabel field
      LFlowLabel             := Swap(LHeaderV6.FlowLabel);
      // Mask the 20 bits of interest (bits 0-19)
      LFlowLabel             := LFlowLabel and $FFFFF;
      // Shift the 20 bits to the right so they are aligned to the least significant bit
      LFlowLabel             := LFlowLabel shr 4;
      // Now the FlowLabel variable contains the 20-bit value      

      AListDetail.Add(AddHeaderInfo(aStartLevel+1,'IP.IPv6.FlowLabel2','Flow Label:',LFlowLabel,PByte(@LHeaderV6.FlowLabel),SizeOf(LHeaderV6.FlowLabel)));                
      AListDetail.Add(AddHeaderInfo(aStartLevel+1,'IP.IPv6.PayloadLength','Payload Length:',wpcapntohs(LHeaderV6.PayloadLength),PByte(@LHeaderV6.PayloadLength),SizeOf(LHeaderV6.PayloadLength)));                     
      AListDetail.Add(AddHeaderInfo(aStartLevel+1,'IP.IPv6.NextHeader','Next Header:',Format('%s [%d]',[LInternalIP.ProtoAcronym,LInternalIP.IpProto]),PByte(@LHeaderV6.NextHeader),SizeOf(LHeaderV6.NextHeader)));                     
      AListDetail.Add(AddHeaderInfo(aStartLevel+1,'IP.IPv6.HopLimit','Hop Limit:',Format('%d hop',[LHeaderV6.HopLimit]),PByte(@LHeaderV6.HopLimit),SizeOf(LHeaderV6.HopLimit)));                          
      AListDetail.Add(AddHeaderInfo(aStartLevel+1,'IP.IPv6.SourceAddress','Source Address:',LInternalIP.Src,PByte(@LHeaderV6.SourceAddress),SizeOf(LHeaderV6.SourceAddress)));                          
      AListDetail.Add(AddHeaderInfo(aStartLevel+1,'IP.IPv6.DestinationAddress','Destination Address:',LInternalIP.Dst,PByte(@LHeaderV6.DestinationAddress),SizeOf(LHeaderV6.DestinationAddress))); 
      LCurrentPos := HeaderEthSize(aPacketData,aPacketSize) + SizeOf(TIPv6Header);
      LIpProto    := LHeaderV6.NextHeader;
      ExtentionHeader(aPacketData,aStartLevel,LCurrentPos,LIpProto,AListDetail);                     
    end
    else                                                                                
    begin
      Result  := True;
      AListDetail.Add(AddHeaderInfo(aStartLevel,'IP.IPv4','Internet protocol version 4',Format('Src: %s, Dst %s',[LInternalIP.Src,LInternalIP.Dst]),PByte(LHeaderV4),HeaderIPSize(aPacketData,aPacketSize)));       
      AListDetail.Add(AddHeaderInfo(aStartLevel+1,'IP.IPv4.HeaderLen','Header length:',HeaderLenConvert(LHeaderV4.VerLen),PByte(@LHeaderV4.VerLen),SizeOf(LHeaderV4.VerLen))); 
      AListDetail.Add(AddHeaderInfo(aStartLevel+1,'IP.IPv4.Version','Version:',(LHeaderV4.VerLen shr 4) and $0F,PByte(@LHeaderV4.VerLen),SizeOf(LHeaderV4.VerLen))); 

      AListDetail.Add(AddHeaderInfo(aStartLevel+1,'IP.IPv4.DifferetiatedServicesField','Differetiated services field:',LHeaderV4.TOS,PByte(@LHeaderV4.TOS),SizeOf(LHeaderV4.TOS)));       

      LTOSInfo := DecodeDifferentiatedServices(LHeaderV4.TOS);
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IP.IPv4.Precedence','Precedence:',LTOSInfo.Precedence,@LHeaderV4.TOS,SizeOf(LHeaderV4.TOS), (LHeaderV4.TOS shr 5) ));        
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IP.IPv4.Delay', 'Delay:', LTOSInfo.Delay, @LHeaderV4.TOS,SizeOf(LHeaderV4.TOS), GetBitValue(LHeaderV4.TOS,4) ));        
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IP.IPv4.Throughput','Throughput:',LTOSInfo.Throughput, @LHeaderV4.TOS,SizeOf(LHeaderV4.TOS), GetBitValue(LHeaderV4.TOS,5) ));        
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IP.IPv4.Reliability','Reliability:',LTOSInfo.Reliability, @LHeaderV4.TOS,SizeOf(LHeaderV4.TOS), GetBitValue(LHeaderV4.TOS,6) ));                          
                       
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IP.IPv4.TotalLen','Total length:',wpcapntohs(LHeaderV4.TotalLen), PByte(@LHeaderV4.TotalLen),SizeOf(LHeaderV4.TotalLen) ));            
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IP.IPv4.Identification','Identification:',wpcapntohs(LHeaderV4.ID), PByte(@LHeaderV4.ID),SizeOf(LHeaderV4.ID) ));                  

      AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'IP.IPv4.Flags','Flags:',ByteToBinaryString(LHeaderV4.FlagsOfF shr 13), PByte(@LHeaderV4.FlagsOff),SizeOf(LHeaderV4.FlagsOff), LHeaderV4.FlagsOfF shr 13 )); 
      LFlagOffInfo := GetIpFlag(LHeaderV4.FlagsOfF shr 13,AListDetail,aStartLevel); 
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IP.IPv4.Flags.FragmentOffSet','Fragment OffSet:',wpcapntohs(LHeaderV4.FlagsOff and $1FFF), PByte(@LHeaderV4.FlagsOff),SizeOf(LHeaderV4.FlagsOff)));
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'IP.IPv4.TTL','Time to live:',Format('%d hop',[LHeaderV4.TTL]),PByte(@LHeaderV4.TTL),SizeOf(LHeaderV4.TTL)));                                     
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'IP.IPv4.Protocol','Protocol:',Format('%s [%d]',[LInternalIP.ProtoAcronym,LInternalIP.IpProto]),PByte(@LHeaderV4.Protocol),SizeOf(LHeaderV4.Protocol)));                     
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'IP.IPv4.CheckSum','CheckSum:',wpcapntohs(LHeaderV4.CheckSum),PByte(@LHeaderV4.CheckSum),SizeOf(LHeaderV4.CheckSum)));                  
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'IP.IPv4.Source','Source:',LInternalIP.Src,PByte(@LHeaderV4.SrcIP),SizeOf(LHeaderV4.SrcIP)));                        
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'IP.IPv4.Destination','Destination:',LInternalIP.Dst,PByte(@LHeaderV4.DestIP),SizeOf(LHeaderV4.DestIP)));                              
    end;

    if Result then
    begin
      case LInternalIP.IpProto of
 
        IPPROTO_ICMP,
        IPPROTO_ICMPV6  : TWPcapProtocolICMP.HeaderToString(aPacketData,aPacketSize,aStartLevel,AListDetail,aisFilterMode);
        IPPROTO_TCP     : TWPcapProtocolBaseTCP.HeaderToString(aPacketData,aPacketSize,aStartLevel,AListDetail,aisFilterMode);
        IPPROTO_UDP     : TWPcapProtocolBaseUDP.HeaderToString(aPacketData,aPacketSize,aStartLevel,AListDetail,aisFilterMode);
        IPPROTO_IGMP    : TWPcapProtocolIGMP.HeaderToString(aPacketData,aPacketSize,aStartLevel,AListDetail,aisFilterMode);
        IPPROTO_GGP     :;  
        IPPROTO_IP      :
          begin  
            LNewPacket  := GetNextBufferHeader(aPacketData,aPacketSize,0,ETH_P_IP,LNewPacketSize,True);
            if Assigned(LNewPacket) then
              begin
              Try
                Result := HeaderToString(LNewPacket, LNewPacketSize,aStartLevel,AListDetail,aisFilterMode);
              Finally
                FreeMem(LNewPacket);
              End;           
            end;
          end;
          
        IPPROTO_IPV6    :
        begin
          LNewPacket  := GetNextBufferHeader(aPacketData,aPacketSize,0,ETH_P_IPV6,LNewPacketSize,False);
          if Assigned(LNewPacket) then
          begin
            Try
              Result := HeaderToString(LNewPacket, LNewPacketSize,aStartLevel,AListDetail,aisFilterMode);
            Finally
              FreeMem(LNewPacket);
            End;        
          end;
        end;


        IPPROTO_PUP     :;
        IPPROTO_IDP     :;
        IPPROTO_GRE     :;
        IPPROTO_ESP     :;
        IPPROTO_AH      :;
        IPPROTO_ROUTING :;
        IPPROTO_PGM     :;
        IPPROTO_SCTP    :;
        IPPROTO_RAW     :;
      end;
    end;        
  finally               
    Dispose(LInternalIP)
  end;
end;

class function TWpcapIPHeader.ExtentionHeaderOptions(const aPacketData: PByte;aStartLevel:Integer;var aCurrentPos:Integer;var aIpProto:word;AListDetail: TListHeaderString):Boolean;
var LHopeOptions  : PTOptionHeader;

    procedure WriteInfo(Const alabelInfo:String);
    var aCurrentValue : Byte;
        LLabel        : String;
    begin
      if Assigned(AListDetail) then
      begin
        LLabel := Format('IP.IPv6.ExtHeader.HbH.Options.%s.Flags',[alabelInfo]);
        AListDetail.Add(AddHeaderInfo(aStartLevel+3,LLabel,'Flags',ByteToBinaryString(LHopeOptions.OptType),@LHopeOptions.OptType,SizeOf(LHopeOptions.OptType),LHopeOptions.OptType));

        AListDetail.Add(AddHeaderInfo(aStartLevel+4, Format('%s.Action',[LLabel]), 'Action',GetFistNBit(LHopeOptions.OptType,2), @LHopeOptions.OptType,SizeOf(LHopeOptions.OptType) ));

        AcurrentValue := GetFistNBit(LHopeOptions.OptType,3);                
        AListDetail.Add(AddHeaderInfo(aStartLevel+4, Format('%s.Maychange',[LLabel]), 'May Change',AcurrentValue=1, @AcurrentValue,SizeOf(AcurrentValue),AcurrentValue ));            

        AListDetail.Add(AddHeaderInfo(aStartLevel+4, Format('%s.Len',[LLabel]), 'Data len',GetLastNBit(LHopeOptions.OptType,5), @LHopeOptions.OptType,SizeOf(LHopeOptions.OptType) ));           
        AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.LowOrder',[LLabel]), 'Low order bytes', LHopeOptions.OptDataLen, @LHopeOptions.OptDataLen,SizeOf(LHopeOptions.OptDataLen) ));     
      end;
      Inc(aCurrentPos,SizeOf(TOptionHeader));        
      Result := True;  
    end;
begin
  Result := False;
  LHopeOptions := PTOptionHeader(aPacketData+aCurrentPos); 
                          
  case LHopeOptions.OptType of
    //Pad1
    0:
      begin
        Inc(aCurrentPos,SizeOf(TOptionHeader));          
        Result := True; 
      end;

    //PadN
    1:
      begin 
        if Assigned(AListDetail) then           
          AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IP.IPv6.ExtHeader.HbH.Options.PadN', Format('PadN [%d]',[LHopeOptions.OptType]), null, PByte(LHopeOptions),SizeOf(LHopeOptions), LHopeOptions.OptType ));  

        WriteInfo('PadN');
      end;
    // RFC8200 Jumbo Payload (JMP)
    2:
      begin
        if Assigned(AListDetail) then     
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IP.IPv6.ExtHeader.HbH.Options.JumboPayLoad', Format('Jumbo payload [%d]',[LHopeOptions.OptType]), null, PByte(LHopeOptions),SizeOf(LHopeOptions), LHopeOptions.OptType )); 
        WriteInfo('JumboPayload');
      end;

    //Unassigned
    3,4:;
    //Router alert
    5:
      begin
        if Assigned(AListDetail) then     
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IP.IPv6.ExtHeader.HbH.Options.RouterAlart' , Format('Router alert [%d]',[LHopeOptions.OptType]), null, PByte(LHopeOptions),SizeOf(LHopeOptions),LHopeOptions.OptType)); 
        WriteInfo('RouterAlert');      
      end;
    6..63: ;
    //RFC2460 Home Address (HAD) 
    64:  
      begin
        if Assigned(AListDetail) then     
          AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IP.IPv6.ExtHeader.HbH.Options.HomeAddr' , Format('Home Address [%d]',[LHopeOptions.OptType]),null,PByte(LHopeOptions),SizeOf(LHopeOptions),LHopeOptions.OptType)); 
        WriteInfo('HomeAddress');

      end;
    //Unassigned
    65..127: ;
    //Experimental/Testing
    128..191: ;
    //Unassigned
    192..254: ;
    //Reserved for future use
    255: ;          
  end;   
  
  if Result then    
    ExtentionHeaderOptions(aPacketData,aStartLevel,aCurrentPos,aIpProto,AListDetail);      
end;

class function TWpcapIPHeader.ExtentionHeader(const aPacketData: PByte;aStartLevel:integer;var aCurrentPos:Integer;var aIpProto:word;AListDetail: TListHeaderString):Boolean;
var LHope : PTHopByHopOption;  
begin 
  Result := False;

  case aIpProto of
    IPPROTO_HOPOPTS : 
    begin
      LHope := PTHopByHopOption(aPacketData +aCurrentPos);    
      inc(aCurrentPos,SizeOf(THopByHopOption));  
      aIpProto := LHope.NextHeader;     

      if Assigned(AListDetail) then
      begin
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'IP.IPv6.ExtHeader.HbH', 'IPv6 Hop-by-Hop Option',null, PByte(LHope),SizeOf(THopByHopOption) )); 
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IP.IPv6.ExtHeader.HbH', 'Next Header:',GetIPv6ProtocolName(LHope.NextHeader), PByte(@LHope.NextHeader),SizeOf(LHope.NextHeader), LHope.NextHeader ));                     
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IP.IPv6.ExtHeader.HbH', 'Header ext len:', LHope.HdrExtLen * 8, PByte(@LHope.HdrExtLen),SizeOf(LHope.HdrExtLen), LHope.HdrExtLen ));                     
        aCurrentPos := aCurrentPos + LHope.HdrExtLen;
      end;
      ExtentionHeaderOptions(aPacketData,aStartLevel,aCurrentPos,aIpProto,AListDetail);
      Result := true;
    end;
  end;

  if Result then    
    ExtentionHeader(aPacketData,aStartLevel,aCurrentPos,aIpProto,AListDetail); 
end;

class Procedure TWpcapIPHeader.AnalyzeIPProtocol(const aPacketData: PByte;aPacketSize: Integer; aInternalIP: PTInternalIP;aLogging:Boolean);
var LStopwatch : TStopwatch;
begin
  LStopwatch := TStopwatch.Create;
  LStopwatch := LStopwatch.StartNew;
  TWPcapProtocolBaseTCP.OnLog := OnLog;          
  TWPcapProtocolBaseUDP.OnLog := OnLog;            
  if not TWPcapProtocolBaseUDP.AnalyzeUDPProtocol(aPacketData,aPacketSize,aInternalIP.ProtoAcronym,aInternalIP.DetectedIPProto) then
    TWPcapProtocolBaseTCP.AnalyzeTCPProtocol(aPacketData,aPacketSize,aInternalIP.ProtoAcronym,aInternalIP.DetectedIPProto);
  if aLogging  then    
    DoLog('TWpcapIPHeader.AnalyzeIPProtocol',Format('Execute in [ %d ms ]',[LStopwatch.ElapsedMilliseconds]),TWLLTiming);                   
end;

class function TWpcapIPHeader.InternalIP(const aPacketData: PByte;aPacketSize: Integer;aIANADictionary:TDictionary<String,TIANARow>; aInternalIP: PTInternalIP;aFallowIpLevel,aLogging:Boolean): Boolean;
var LheaderIpV4    : PTIPHeader;
    LheaderIpV6    : PIpv6Header;
    LUdpPhdr       : PUDPHdr;
    LTcpPhdr       : PTCPHdr;    
    LIANARow       : TIANARow; 
    LCurrentPos    : Integer; 
    LNewPacket     : PByte;
    LNewPacketSize : Integer;
begin
  Result                     := False;
  aInternalIP.IpProto        := 0;
  aInternalIP.Src            := String.Empty;
  aInternalIP.Dst            := String.Empty;
  aInternalIP.PortSrc        := 0;
  aInternalIP.PortDst        := 0;
  aInternalIP.IsIPv6         := False;
  aInternalIP.DetectedIPProto:= 0;  
  aInternalIP.IANAProtoStr   := String.Empty;  
  LheaderIpV4                := HeaderIPv4(aPacketData,aPacketSize);

  case IpClassType(aPacketData,aPacketSize) of
    imtIpv4 : 
      begin
        if not Assigned(LheaderIpV4) then Exit;        
        aInternalIP.IpProto  := LheaderIpV4.Protocol;

        if (aInternalIP.IpProto = IPPROTO_IPV6) and aFallowIpLevel then
        begin
          DoLog('TWpcapIPHeader.InternalIP','Found IPv4 link to Next IPv6 header',TWLLInfo);               
          LNewPacket  := GetNextBufferHeader(aPacketData,aPacketSize,0,ETH_P_IPV6,LNewPacketSize,False);
          Try
            Result := InternalIP(LNewPacket, LNewPacketSize,aIANADictionary,aInternalIP,True,True);
          Finally
            FreeMem(LNewPacket);
          End;              
          Exit;
        end;
        
        aInternalIP.IpPrototr      := GetIPv4ProtocolName(aInternalIP.IpProto);                    
        aInternalIP.ProtoAcronym   := GetIPv4ProtocolName(aInternalIP.IpProto);
        aInternalIP.Src            := MakeUInt32IntoIPv4Address(wpcapntohl(LheaderIpV4.SrcIP.Addr));
        aInternalIP.Dst            := MakeUInt32IntoIPv4Address(wpcapntohl(LheaderIpV4.DestIP.Addr));
        AnalyzeIPProtocol(aPacketData,aPacketSize,aInternalIP,aLogging);         
        Result := True;
      end;
   imtIpv6:
      begin
        {IPv6}                       
        LheaderIpV6                 := HeaderIPv6(aPacketData,aPacketSize);
        aInternalIP.IpProto         := LheaderIpV6.NextHeader;
        LCurrentPos                 := HeaderEthSize(aPacketData,aPacketSize) + SizeOf(TIPv6Header);
        ExtentionHeader(aPacketData,0,LCurrentPos, aInternalIP.IpProto,nil); 

        if (aInternalIP.IpProto = IPPROTO_IP) and aFallowIpLevel then
        begin
          DoLog('TWpcapIPHeader.InternalIP','Found IPv6 link to Next IPv4 header',TWLLInfo);       
          LNewPacket  := GetNextBufferHeader(aPacketData,aPacketSize,0,ETH_P_IP,LNewPacketSize,False);
          Try
            Result := InternalIP(LNewPacket, LNewPacketSize,aIANADictionary,aInternalIP,True,True);
          Finally
            FreeMem(LNewPacket);
          End;              
          Exit;
        end;
                           
        aInternalIP.ProtoAcronym    := GetIPv6ProtocolName(aInternalIP.IpProto);                    
        aInternalIP.IpPrototr       := GetIPv6ProtocolName(aInternalIP.IpProto);                    
        aInternalIP.Src             := IPv6AddressToString(LheaderIpV6.SourceAddress);
        aInternalIP.Dst             := IPv6AddressToString(LheaderIpV6.DestinationAddress);
        aInternalIP.IsIPv6          := True;
        AnalyzeIPProtocol(aPacketData,aPacketSize,aInternalIP,aLogging); 
        Result := True;    
      end;      
  end;
  if aLogging then  
    DoLog('TWpcapIPHeader.InternalIP',Format('Found IpProto [ %d --> %s ]',[aInternalIP.IpProto,aInternalIP.ProtoAcronym]),TWLLInfo);
  case aInternalIP.IpProto of

    IPPROTO_ICMP,
    IPPROTO_ICMPV6  : 
      begin
        TWPcapProtocolICMP.OnLog := OnLog;
        TWPcapProtocolICMP.IsValid(aPacketData,aPacketSize,aInternalIP.ProtoAcronym,aInternalIP.DetectedIPProto);
      end;
    
    IPPROTO_TCP     : 
      begin
        if TWPcapProtocolBaseTCP.HeaderTCP(aPacketData,aPacketSize,LTcpPhdr) then
        begin
          aInternalIP.PortSrc := TWPcapProtocolBaseTCP.SrcPort(LTcpPhdr);
          aInternalIP.PortDst := TWPcapProtocolBaseTCP.DstPort(LTcpPhdr);    

          if not Assigned(aIANADictionary) then Exit;

          if aIANADictionary.TryGetValue(Format('%d_%d',[aInternalIP.PortDst,IPPROTO_IANA_TPC]),LIANARow ) then
           aInternalIP.IANAProtoStr := LIANARow.ProtocolName
        end;      
      end;
      
    IPPROTO_UDP     : 
      begin
        if TWPcapProtocolBaseUDP.HeaderUDP(aPacketData,aPacketSize,LUdpPhdr) then
        begin
          aInternalIP.PortSrc := TWPcapProtocolBaseUDP.SrcPort(LUdpPhdr);
          aInternalIP.PortDst := TWPcapProtocolBaseUDP.DstPort(LUdpPhdr);
          {how can detect direction of packet ??}
          if not Assigned(aIANADictionary) then Exit;
    
          if aIANADictionary.TryGetValue(Format('%d_%d',[aInternalIP.PortDst,IPPROTO_IANA_UDP]),LIANARow) then
           aInternalIP.IANAProtoStr := LIANARow.ProtocolName
          else if aIANADictionary.TryGetValue(Format('%d_%d',[aInternalIP.PortSrc,IPPROTO_IANA_UDP]),LIANARow) then
           aInternalIP.IANAProtoStr := LIANARow.ProtocolName
        end     
      end;

    IPPROTO_IGMP    : 
      begin
        TWPcapProtocolIGMP.OnLog := OnLog;
        TWPcapProtocolIGMP.IsValid(aPacketData,aPacketSize,aInternalIP.ProtoAcronym,aInternalIP.DetectedIPProto);
      end;

    IPPROTO_IPV6    :
      begin
        TWPcapProtocolBaseUDP.OnLog := OnLog;
        TWPcapProtocolBaseTCP.OnLog := OnLog;        
        if TWPcapProtocolBaseUDP.HeaderUDP(aPacketData,aPacketSize,LUdpPhdr) then
        begin
          aInternalIP.PortSrc := TWPcapProtocolBaseUDP.SrcPort(LUdpPhdr);
          aInternalIP.PortDst := TWPcapProtocolBaseUDP.DstPort(LUdpPhdr);
          {how can detect direction of packet ??}
          if not Assigned(aIANADictionary) then Exit;
    
          if aIANADictionary.TryGetValue(Format('%d_%d',[aInternalIP.PortDst,IPPROTO_IANA_UDP]),LIANARow) then
           aInternalIP.IANAProtoStr := LIANARow.ProtocolName
          else if aIANADictionary.TryGetValue(Format('%d_%d',[aInternalIP.PortSrc,IPPROTO_IANA_UDP]),LIANARow) then
           aInternalIP.IANAProtoStr := LIANARow.ProtocolName
        end 
        else if TWPcapProtocolBaseTCP.HeaderTCP(aPacketData,aPacketSize,LTcpPhdr) then
        begin          
          aInternalIP.PortSrc := TWPcapProtocolBaseTCP.SrcPort(LTcpPhdr);
          aInternalIP.PortDst := TWPcapProtocolBaseTCP.DstPort(LTcpPhdr);    

          if not Assigned(aIANADictionary) then Exit;
    
          if aIANADictionary.TryGetValue(Format('%d_%d',[aInternalIP.PortDst,IPPROTO_IANA_TPC]),LIANARow) then
           aInternalIP.IANAProtoStr := LIANARow.ProtocolName
        end;               
      end;
      
    IPPROTO_GGP     ,
    IPPROTO_PUP     ,
    IPPROTO_IDP     ,
    IPPROTO_GRE     ,
    IPPROTO_ESP     ,
    IPPROTO_AH      ,
    IPPROTO_ROUTING ,
    IPPROTO_PGM     ,
    IPPROTO_SCTP    ,    
    IPPROTO_RAW     : 
      if aLogging then      
        DoLog('TWpcapIPHeader.InternalIP',Format('IpProto [ %d --> %s ] not implemented',[aInternalIP.IpProto,aInternalIP.ProtoAcronym]),TWLLWarning);
  end;  
end;

class function TWpcapIPHeader.GetIPv6ProtocolName(aProtocol: Word): string;
const
  IPv6Protocols: array[0..11] of record
    Protocol: Byte;
    Name: string;
  end = (
    (Protocol: IPPROTO_HOPOPTS; Name: 'ICMPv6'),
    (Protocol: IPPROTO_ICMPV6; Name: 'ICMPv6'),
    (Protocol: IPPROTO_TCP; Name: 'TCP'),
    (Protocol: IPPROTO_UDP; Name: 'UDP'),
    (Protocol: IPPROTO_ROUTINGV6; Name: 'Routing header'),
    (Protocol: IPPROTO_FRAGMENT; Name: 'Fragment header'),
    (Protocol: IPPROTO_ESP; Name: 'Encapsulation Security Payload'),
    (Protocol: IPPROTO_AH; Name: 'Authentication header'),
    (Protocol: IPPROTO_NONE; Name: 'No next header'),
    (Protocol: IPPROTO_DSTOPTS; Name: 'Destination options'),
    (Protocol: IPPROTO_MH; Name: 'Mobility header'),
    (Protocol: $FF; Name: 'Reserved')
  );
var
  i: Integer;
begin
  for i := Low(IPv6Protocols) to High(IPv6Protocols) do
    if aProtocol = IPv6Protocols[i].Protocol then
      Exit(IPv6Protocols[i].Name);

  Result := Format('Unknown IPV6 %d',[aProtocol]);
end;
                                    
class function TWpcapIPHeader.GetIPv4ProtocolName(aProtocol: Word): string;
begin
  case aProtocol of
    IPPROTO_HOPOPTS : Result := 'ICMP';
    IPPROTO_ICMP    : Result := 'ICMP';
    IPPROTO_IGMP    : Result := 'IGMP';
    IPPROTO_GGP     : Result := 'GGP';
    IPPROTO_TCP     : Result := 'TCP';
    IPPROTO_UDP     : Result := 'UDP';
    IPPROTO_IPV6    : Result := 'IPv6';
    IPPROTO_ICMPV6  : Result := 'ICMPv6';
    IPPROTO_PUP     : Result := 'PUP';   // ETH ??
    IPPROTO_IDP     : Result := 'xns idp';
    IPPROTO_GRE     : Result := 'GRE';
    IPPROTO_ESP     : Result := 'ESP';
    IPPROTO_AH      : Result := 'AH';    
    IPPROTO_ROUTING : Result := 'ROUTING';
    IPPROTO_PGM     : Result := 'PGM';
    IPPROTO_SCTP    : Result := 'SCTP';
    IPPROTO_RAW     : Result := 'RAW';
    else Result := Format('Unknown %d',[aProtocol]);
  end;
end;

class function TWpcapIPHeader.EthAndIPHeaderSize(const aPacketData: PByte; aPacketSize: Integer;aCheckNextHeader:Boolean=True): Word;
begin
  Result := HeaderEthSize(aPacketData,aPacketSize)+HeaderIPSize(aPacketData,aPacketSize,aCheckNextHeader);
end;



end.
