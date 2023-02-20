unit wpcap.Level.IP;

interface

uses
  System.Generics.Collections, wpcap.Packet, winSock, wpcap.StrUtils,
  wpcap.Conts, System.SysUtils, wpcap.Level.Eth, wpcap.IANA.DbPort,
  wpcap.Protocol.UDP, wpcap.Protocol.TCP,winsock2,wpcap.Types;


type  
  TIPAddrBytes = array [0 .. 3] of Byte;
  TIPAddress = record
      case Integer of
        0: (Bytes: TIPAddrBytes);
        1: (Addr: Cardinal);
    end;


  // equivalent to the Internet Protocol Version 4 section of wireshark in the package detail
  PTIPHeader = ^TIPHeader;
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

  TWpcapIPHeader = class 
  Strict private
    
  private
    /// <summary>
    ///   Determines if the given packet size is valid for an Ethernet frame with an IPv4 or IPv6 header.
    /// </summary>
    /// <param name="aPacketSize">The size of the packet in bytes.</param>
    /// <param name="isIPv6">Specifies whether the packet has an IPv6 payload.</param>
    /// <returns>
    ///   True if the packet size is valid, False otherwise.
    /// </returns>
    class function isValidSize(aPacketSize: Integer; isIPv6: Boolean): Boolean; static;

    /// <summary>
    ///   Analyzes the IP protocol of the packet data and populates the provided internal IP record with the appropriate data.
    ///   If the protocol is not UDP or TCP, the protocol acronym is left empty and the detected IP protocol value is set to 0.
    /// </summary>
    /// <param name="aPacketData">A pointer to the start of the packet data.</param>
    /// <param name="aPacketSize">The size of the packet data in bytes.</param>
    /// <param name="aInternalIP">A pointer to the internal IP record to be populated with the analysis results.</param>
    class procedure AnalyzeIPProtocol(const aPacketData: PByte; aPacketSize: Integer; aInternalIP: PTInternalIP);
    
    ///  <summary>
    ///    Analyzes a UDP protocol packet to determine its acronym name and protocol identifier.
    ///  </summary>
    ///  <param name="aData">
    ///    A pointer to the packet data to analyze.
    ///  </param>
    ///  <param name="aSize">
    ///    The size of the packet data.
    ///  </param>
    ///  <param name="aArcronymName">
    ///    An output parameter that will receive the acronym name of the detected protocol.
    ///  </param>
    ///  <param name="aIdProtoDetected">
    ///    An output parameter that will receive the protocol identifier of the detected protocol.
    ///  </param>
    ///  <returns>
    ///    True if a supported protocol was detected, False otherwise.
    ///  </returns>
    class function AnalyzeUDPProtocol(const aData: PByte; aSize: Integer; var aArcronymName: string; var aIdProtoDetected: Byte): Boolean;static;

    ///  <summary>
    ///    Analyzes a TCP protocol packet to determine its acronym name and protocol identifier.
    ///  </summary>
    ///  <param name="aData">
    ///    A pointer to the packet data to analyze.
    ///  </param>
    ///  <param name="aSize">
    ///    The size of the packet data.
    ///  </param>
    ///  <param name="aArcronymName">
    ///    An output parameter that will receive the acronym name of the detected protocol.
    ///  </param>
    ///  <param name="aIdProtoDetected">
    ///    An output parameter that will receive the protocol identifier of the detected protocol.
    ///  </param>
    ///  <returns>
    ///    True if a supported protocol was detected, False otherwise.
    ///  </returns>
    class function AnalyzeTCPProtocol(const aData:Pbyte;aSize:Integer;var aArcronymName:String;var aIdProtoDetected:Byte):boolean;static;
    
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
    /// <param name="isIPv6">A boolean value indicating whether the provided packet data is an IPv6 packet (true) or an IPv4 packet (false).</param>
    /// <returns>The size of the IP header in bytes.</returns>
    class function HeaderSize(isIPv6: Boolean): Word; static;

    /// <summary>
    ///   Returns a dictionary containing the string representation of each field in the IP header, as well as its value in the provided packet data.
    /// </summary>
    /// <returns>A dictionary containing the string representation of each field in the IP header, as well as its value in the provided packet data.</returns>
    class function HeaderToString(const aPacketData: PByte; aPacketSize: Integer;AListDetail: TList<THeaderString>): Boolean;

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
    class function InternalIP(const aPacketData: PByte; aPacketSize: Integer; aIANADictionary: TDictionary<String, TIANARow>; aInternalIP: PTInternalIP): Boolean;static;

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
  end;

implementation

uses wpcap.protocol;

{ TIPHeaderClas }

class function TWpcapIPHeader.AnalyzeUDPProtocol(const aData:Pbyte;aSize:Integer;var aArcronymName:String;var aIdProtoDetected:Byte):boolean;
var LUDPPtr        : PUDPHdr;
    LUDPPayLoad    : PByte;
    I              : Integer;
    LisIPV6        : Boolean;
begin
  Result        := False;
  if not GetHeaderUDP(aData,aSize,LUDPPtr,LisIPV6) then exit;
  
  aIdProtoDetected := DETECT_PROTO_UDP;
  LUDPPayLoad      := GetUDPPayLoad(aData,LisIPV6);

  for I := 0 to FListProtolsUDPDetected.Count-1 do
  begin
    if FListProtolsUDPDetected[I].IsValid(aData,aSize,LUDPPtr,LUDPPayLoad,aArcronymName,aIdProtoDetected) then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

class function TWpcapIPHeader.AnalyzeTCPProtocol(const aData:Pbyte;aSize:Integer;var aArcronymName:String;var aIdProtoDetected:Byte):boolean;
var LTCPPPtr        : PTCPHdr;
    LTCPPayLoad    : PByte;
    I              : Integer;
    LisIPV6        : Boolean;
begin
  Result        := False;
  if not GetHeaderTCP(aData,aSize,LTCPPPtr,LisIPV6) then exit;
  
  aIdProtoDetected := DETECT_PROTO_TCP;
  LTCPPayLoad      := GetTCPPayLoad(aData,LisIPV6);

  for I := 0 to FListProtolsTCPDetected.Count-1 do
  begin
    if FListProtolsTCPDetected[I].IsValid(aData,aSize,LTCPPPtr,LTCPPayLoad,aArcronymName,aIdProtoDetected) then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

class function TWpcapIPHeader.isValidSize(aPacketSize: Integer;isIPv6:boolean): Boolean;
begin
   result := aPacketSize > HeaderSize(isIPv6);
end;

class function TWpcapIPHeader.HeaderIPv4(const aPacketData: PByte;aPacketSize: Integer): PTIPHeader;
begin
  Result := nil;
  if not isValidSize(aPacketSize,False) then exit;

  Result := PTIPHeader(aPacketData + SizeOf(TETHHdr))
end;

class function TWpcapIPHeader.HeaderIPv6(const aPacketData: PByte;aPacketSize: Integer): PIpv6Header;
begin
  Result := nil;
  if not isValidSize(aPacketSize,true) then exit;

  Result := PIPv6Header(aPacketData + SizeOf(TETHHdr))
end;

class function TWpcapIPHeader.HeaderSize(isIPv6: Boolean): Word;
begin
  if isIPv6  then
    Result := SizeOf(TIPv6Header)
  else
    Result := SizeOf(TIPHeader)
end;

class function TWpcapIPHeader.HeaderToString(const aPacketData: PByte; aPacketSize: Integer;AListDetail: TList<THeaderString>): Boolean;
var LHederInfo  : THeaderString;
    LInternalIP : PTInternalIP;
    LHeaderV4   : PTIPHeader;
    LHeaderV6   : PIpv6Header;    
begin
  Result := False;
  new(LInternalIP);
  Try
    if not InternalIP(aPacketData,aPacketSize,nil,LInternalIP) then exit;
    
    if not Assigned(AListDetail) then
      AListDetail := TList<THeaderString>.Create;

    LHeaderV4 := HeaderIPv4(aPacketData,aPacketSize);
    
    if LInternalIP.IsIpv6 then
    begin
      Result                 := True;
      LHeaderV6              := HeaderIPv6(aPacketData,aPacketSize);
      LHederInfo.Level       := 0;
      LHederInfo.Description := Format('Internet protocol version 6, Src: %s, Dst %s ',[LInternalIP.Src,LInternalIP.Dst]);
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(LHeaderV6),HeaderSize(True),False));
      AListDetail.Add(LHederInfo);    
    end
    else
    begin
      Result                 := False;
      LHederInfo.Level       := 0;
      LHederInfo.Description := Format('Internet protocol version 4, Src: %s, Dst %s ',[LInternalIP.Src,LInternalIP.Dst]);
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(LHeaderV4),HeaderSize(False),False));
      AListDetail.Add(LHederInfo);


      LHederInfo.Level       := 1;
      LHederInfo.Description := Format('Version: %d ',[LHeaderV4.VerLen]);
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.VerLen)),1,False));
      AListDetail.Add(LHederInfo); 
      
      LHederInfo.Level       := 1;
      LHederInfo.Description := Format('Differetiated services field: %d ',[LHeaderV4.TOS]);
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.TOS)),1,False));
      AListDetail.Add(LHederInfo);
      
      LHederInfo.Level       := 1;
      LHederInfo.Description := Format('Total lenght: %d ',[LHeaderV4.TotalLen]);
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.TotalLen)),4,False));
      AListDetail.Add(LHederInfo);    
      
      LHederInfo.Level       := 1;
      LHederInfo.Description := Format('Identification: %d ',[LHeaderV4.ID]);
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.id)),4,False));
      AListDetail.Add(LHederInfo);          
      
      LHederInfo.Level       := 1;
      LHederInfo.Description := Format('Flags: %d ',[LHeaderV4.FlagsOff]);
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.FlagsOff)),4,False));
      AListDetail.Add(LHederInfo);          
            
      LHederInfo.Level       := 1;
      LHederInfo.Description := Format('Time to live: %d ',[LHeaderV4.TTL]);
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.TTL)),4,False));
      AListDetail.Add(LHederInfo);      


      LHederInfo.Level       := 1;
      LHederInfo.Description := Format('Protocol: %s [%d]',[LInternalIP.IpProtoAcronym,LInternalIP.IpProto]);
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.Protocol)),1,False));
      AListDetail.Add(LHederInfo);              

      LHederInfo.Level       := 1;
      LHederInfo.Description := Format('CheckSum: %d ',[LHeaderV4.Checksum]);
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.Checksum)),4,False));
      AListDetail.Add(LHederInfo);  

      
      LHederInfo.Level       := 1;
      LHederInfo.Description := Format('Source: %s ',[LInternalIP.Src]);
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.SrcIP)),5,False));
      AListDetail.Add(LHederInfo);
            
      LHederInfo.Level       := 1;
      LHederInfo.Description := Format('Destination: %s ',[LInternalIP.Dst]);
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.DestIP)),5,False));
      AListDetail.Add(LHederInfo);
      
    end;


  finally               
    Dispose(LInternalIP)
  end;
end;

class Procedure TWpcapIPHeader.AnalyzeIPProtocol(const aPacketData: PByte;aPacketSize: Integer; aInternalIP: PTInternalIP);
begin
  if not AnalyzeUDPProtocol(aPacketData,aPacketSize,aInternalIP.IpProtoAcronym,aInternalIP.DetectedIPProto) then
    AnalyzeTCPProtocol(aPacketData,aPacketSize,aInternalIP.IpProtoAcronym,aInternalIP.DetectedIPProto);
end;

class function TWpcapIPHeader.InternalIP(const aPacketData: PByte;aPacketSize: Integer;aIANADictionary:TDictionary<String,TIANARow>; aInternalIP: PTInternalIP): Boolean;
var LheaderIpV4 : PTIPHeader;
    LheaderIpV6 : PIpv6Header;
    LUdpPhdr    : PUDPHdr;
    LTcpPhdr    : PTCPHdr;    
    aIANARow    : TIANARow;    
begin
  Result                     := False;
  aInternalIP.IpProtoAcronym := String.Empty;
  aInternalIP.IpProto        := 0;
  aInternalIP.Src            := String.Empty;  
  aInternalIP.Dst            := String.Empty;
  aInternalIP.PortSrc        := 0;
  aInternalIP.PortDst        := 0;
  aInternalIP.IsIPv6         := False;
  aInternalIP.DetectedIPProto:= 0;  
  aInternalIP.IANAProtoStr   := String.Empty;
  
  LheaderIpV4                := HeaderIPv4(aPacketData,aPacketSize);
  case TWpcapEthHeader.IpClassType(aPacketData,aPacketSize) of
    imtIpv4 : 
      begin
        aInternalIP.IpProto        := LheaderIpV4.Protocol; 
        aInternalIP.IpProtoAcronym := GetIPv4ProtocolName(aInternalIP.IpProto);
        aInternalIP.Src            := intToIPV4(LheaderIpV4.SrcIP.Addr);
        aInternalIP.Dst            := intToIPV4(LheaderIpV4.DestIP.Addr);
        AnalyzeIPProtocol(aPacketData,aPacketSize,aInternalIP);         
        Result := True;
      end;
   imtIpv6:
      begin
        {IPv6}                       
        LheaderIpV6                 := HeaderIPv6(aPacketData,aPacketSize);
        aInternalIP.IpProto         := LheaderIpV4.Protocol;
        aInternalIP.IpProtoAcronym  := GetIPv6ProtocolName(aInternalIP.IpProto);                    
        aInternalIP.Src             := IPv6AddressToString(LheaderIpV6.SourceAddress);
        aInternalIP.Dst             := IPv6AddressToString(LheaderIpV6.DestinationAddress);
        aInternalIP.IsIPv6          := True;
        AnalyzeIPProtocol(aPacketData,aPacketSize,aInternalIP); 
        Result := True;
      end;      
  end;


  if GetHeaderUDP(aPacketData,aPacketSize,LUdpPhdr,aInternalIP.IsIPv6) then
  begin
    aInternalIP.PortSrc := ntohs(LUdpPhdr.SrcPort);
    aInternalIP.PortDst := ntohs(LUdpPhdr.DstPort);
    {how can detect direction of packet ??}
    if not Assigned(aIANADictionary) then Exit;
    
    if aIANADictionary.TryGetValue(Format('%d_%d',[aInternalIP.PortDst,IPPROTO_IANA_UDP]),aIANARow) then
     aInternalIP.IANAProtoStr := aIANARow.ProtocolName
    else if aIANADictionary.TryGetValue(Format('%d_%d',[aInternalIP.PortSrc,IPPROTO_IANA_UDP]),aIANARow) then
     aInternalIP.IANAProtoStr := aIANARow.ProtocolName
  end
  else if GetHeaderTCP(aPacketData,aPacketSize,LTcpPhdr,aInternalIP.IsIPv6) then
  begin
    aInternalIP.PortSrc := ntohs(LTcpPhdr.SrcPort);
    aInternalIP.PortDst := ntohs(LTcpPhdr.DstPort);    

    if not Assigned(aIANADictionary) then Exit;
    
    if aIANADictionary.TryGetValue(Format('%d_%d',[aInternalIP.PortDst,IPPROTO_IANA_TPC]),aIANARow) then
     aInternalIP.IANAProtoStr := aIANARow.ProtocolName
  end;
end;

class function TWpcapIPHeader.GetIPv6ProtocolName(aProtocol: Word): string;
const
  IPv6Protocols: array[0..12] of record
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
    (protocol: IPPROTO_ICMPV62;Name:'ICMPv6'),
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
    IPPROTO_ICMPV62,
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


end.
