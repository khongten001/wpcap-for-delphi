unit wpcap.Level.IP;

interface

uses
  System.Generics.Collections, wpcap.Packet, winSock, wpcap.StrUtils,
  wpcap.Conts, System.SysUtils, wpcap.Level.Eth, wpcap.IANA.DbPort,Variants,
  wpcap.Protocol.UDP, wpcap.Protocol.TCP,winsock2,wpcap.Types;


type  
  TIPAddrBytes = array [0 .. 3] of Byte;
  TIPAddress = record
      case Integer of
        0: (Bytes: TIPAddrBytes);
        1: (Addr: Cardinal);
    end;

  TDifferentiatedServices = record
    Precedence : Byte;
    Delay      : Boolean;
    Throughput : Boolean;
    Reliability: Boolean;
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
    class function isValidSizeIP(const aPacketData: PByte;aPacketSize: Integer): Boolean;static;

    /// <summary>
    ///   Analyzes the IP protocol of the packet data and populates the provided internal IP record with the appropriate data.
    ///   If the protocol is not UDP or TCP, the protocol acronym is left empty and the detected IP protocol value is set to 0.
    /// </summary>
    /// <param name="aPacketData">A pointer to the start of the packet data.</param>
    /// <param name="aPacketSize">The size of the packet data in bytes.</param>
    /// <param name="aInternalIP">A pointer to the internal IP record to be populated with the analysis results.</param>
    class procedure AnalyzeIPProtocol(const aPacketData: PByte; aPacketSize: Integer; aInternalIP: PTInternalIP);
    class function DecodeDifferentiatedServices(
      TOS: Byte): TDifferentiatedServices; static;
  
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
    class function HeaderIPSize(const aPacketData: PByte; aPacketSize: Integer): Word; static;

    /// <summary>
    ///   Returns the size of the IP header and Eth Header in bytes based on whether the provided packet data represents an IPv4 or IPv6 packet.
    /// </summary>
    /// <returns>The size of the IP header in bytes.</returns>
    class function EthAndIPHeaderSize(const aPacketData: PByte; aPacketSize: Integer): Word;static;

    /// <summary>
    ///   Returns a dictionary containing the string representation of each field in the IP header, as well as its value in the provided packet data.
    /// </summary>
    /// <returns>A dictionary containing the string representation of each field in the IP header, as well as its value in the provided packet data.</returns>
    class function HeaderToString(const aPacketData: PByte; aPacketSize: Integer;AListDetail: TListHeaderString): Boolean;override;

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

class function TWpcapIPHeader.DecodeDifferentiatedServices(TOS: Byte): TDifferentiatedServices;
begin
  Result.Precedence  := TOS shr 5;
  Result.Delay       := (TOS and $10) = $10;
  Result.Throughput  := (TOS and $8) = $8;
  Result.Reliability := (TOS and $4) = $4;
end;

{ TIPHeaderClas }
class function TWpcapIPHeader.isValidSizeIP(const aPacketData: PByte;aPacketSize: Integer): Boolean;
begin
   result := aPacketSize > EthAndIPHeaderSize(aPacketData,aPacketSize);
end;

class function TWpcapIPHeader.HeaderIPv4(const aPacketData: PByte;aPacketSize: Integer): PTIPHeader;
begin
  Result := nil;
  if not isValidSizeIP(aPacketData,aPacketSize) then exit;

  Result := PTIPHeader(aPacketData + HeaderEthSize)
end;

class function TWpcapIPHeader.HeaderIPv6(const aPacketData: PByte;aPacketSize: Integer): PIpv6Header;
begin
  Result := nil;
  if not isValidSizeIP(aPacketData,aPacketSize) then exit;

  Result := PIPv6Header(aPacketData + HeaderEthSize);
end;

class function TWpcapIPHeader.HeaderIPSize(const aPacketData: PByte;aPacketSize: Integer): Word;
begin
  if IpClassType(aPacketData,aPacketSize) = imtIpv6 then
    Result := SizeOf(TIPv6Header)
  else
    Result := SizeOf(TIPHeader)
end;

class function TWpcapIPHeader.HeaderToString(const aPacketData: PByte; aPacketSize: Integer;AListDetail: TListHeaderString): Boolean;


  function DecodeDifferentiatedServices(TOS: Byte): TDifferentiatedServices;
  begin
    Result.Precedence := TOS shr 5;
    Result.Delay := (TOS and $10) = $10;
    Result.Throughput := (TOS and $8) = $8;
    Result.Reliability := (TOS and $4) = $4;
  end;
var LHederInfo         : THeaderString;
    LInternalIP        : PTInternalIP;
    LHeaderV4          : PTIPHeader;
    LHeaderV6          : PIpv6Header;   
    LFlagOffInfo       : String;
    LIsFragmented      : Boolean;
    LFragmentOffset    : Integer;
    LIsLastFragment    : Boolean; 
    LTrafficClassValue : Byte;
    LPriority          : Byte;   
    LFlowLabel         : Integer;   
    LTrafficClass      : Byte; 
    LTOSInfo           : TDifferentiatedServices;
begin
  Result := False;
  new(LInternalIP);
  Try
    if not InternalIP(aPacketData,aPacketSize,nil,LInternalIP) then exit;
    
    if not Assigned(AListDetail) then
      AListDetail := TListHeaderString.Create;

    LHeaderV4 := HeaderIPv4(aPacketData,aPacketSize);
    
    if LInternalIP.IsIpv6 then
    begin
      Result                 := True;
      LHeaderV6              := HeaderIPv6(aPacketData,aPacketSize);
      LHederInfo.Level       := 0;
      LHederInfo.Description := Format('Internet protocol version 6, Src: %s, Dst %s ',[LInternalIP.Src,LInternalIP.Dst]);
      LHederInfo.Value       := NULL;  
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(LHeaderV6),HeaderIPSize(aPacketData,aPacketSize),False));
      AListDetail.Add(LHederInfo);

      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Version:';
      LHederInfo.Value       := (LHeaderV6.Version shr 4) and $0F;
      LHederInfo.Hex         := String.Join(sLineBreak, DisplayHexData(PByte(@LHeaderV6.Version), SizeOf(LHeaderV6.Version), False));
      AListDetail.Add(LHederInfo);      


      // Leggere il campo TrafficClass
      LTrafficClassValue     := ntohs(LHeaderV6.TrafficClass);
      LPriority              := LTrafficClassValue shr 6;  // 6 bit più significativi
      LFlowLabel             := LTrafficClassValue and $0FFFFF;  // 20 bit per il flow label
      LTrafficClass          := LTrafficClassValue and $3;    // 2 bit meno significativi per la classe di traffico      
      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Traffic Class:';
      LHederInfo.Value       := LTrafficClassValue;
      LHederInfo.Hex         := String.Join(sLineBreak, DisplayHexData(PByte(@LHeaderV6.TrafficClass), SizeOf(LHeaderV6.TrafficClass), False));
      AListDetail.Add(LHederInfo);

      LHederInfo.Level       := 2;
      LHederInfo.Description := 'Priority:';
      LHederInfo.Value       := LPriority;
      LHederInfo.Hex         := String.Empty;
      AListDetail.Add(LHederInfo);

      LHederInfo.Level       := 2;
      LHederInfo.Description := 'FlowLabel:';
      LHederInfo.Value       := LFlowLabel;
      LHederInfo.Hex         := String.Empty;
      AListDetail.Add(LHederInfo);

      LHederInfo.Level       := 2;
      LHederInfo.Description := 'Class:';
      LHederInfo.Value       := LTrafficClass;
      LHederInfo.Hex         := String.Empty;
      AListDetail.Add(LHederInfo);            
      
      // Leggere il campo FlowLabel

      // Reverse the byte order of the FlowLabel field
      LFlowLabel             := Swap(LHeaderV6.FlowLabel);
      // Mask the 20 bits of interest (bits 0-19)
      LFlowLabel             := LFlowLabel and $FFFFF;
      // Shift the 20 bits to the right so they are aligned to the least significant bit
      LFlowLabel             := LFlowLabel shr 4;
      // Now the FlowLabel variable contains the 20-bit value      
      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Flow Label:';
      LHederInfo.Value       := LFlowLabel;
      LHederInfo.Hex         := String.Join(sLineBreak, DisplayHexData(PByte(@LHeaderV6.FlowLabel), SizeOf(LHeaderV6.FlowLabel), False));
      AListDetail.Add(LHederInfo);

      // Leggere il campo PayloadLength
      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Payload Length:';
      LHederInfo.Value       := ntohs(LHeaderV6.PayloadLength);
      LHederInfo.Hex         := String.Join(sLineBreak, DisplayHexData(PByte(@LHeaderV6.PayloadLength), SizeOf(LHeaderV6.PayloadLength), False));
      AListDetail.Add(LHederInfo);

      // Leggere il campo NextHeader
      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Next Header:';
      LHederInfo.Value       := Format('%s [%d]',[LInternalIP.IpProtoAcronym,LInternalIP.IpProto]);
      LHederInfo.Hex         := String.Join(sLineBreak, DisplayHexData(PByte(@LHeaderV6.NextHeader), SizeOf(LHeaderV6.NextHeader), False));
      AListDetail.Add(LHederInfo);

      // Leggere il campo HopLimit
      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Hop Limit:';
      LHederInfo.Value       := Format('%d hop',[LHeaderV6.HopLimit]);
      LHederInfo.Hex         := String.Join(sLineBreak, DisplayHexData(PByte(@LHeaderV6.HopLimit), SizeOf(LHeaderV6.HopLimit), False));
      AListDetail.Add(LHederInfo);

      // Leggere il campo SourceAddress
      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Source Address:';
      LHederInfo.Value       := LInternalIP.Src;
      LHederInfo.Hex         := String.Join(sLineBreak, DisplayHexData(PByte(@LHeaderV6.SourceAddress), SizeOf(LHeaderV6.SourceAddress), False));
      AListDetail.Add(LHederInfo);

      // Leggere il campo DestinationAddress
      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Destination Address:';
      LHederInfo.Value       := LInternalIP.Dst;
      LHederInfo.Hex         := String.Join(sLineBreak, DisplayHexData(PByte(@LHeaderV6.DestinationAddress), SizeOf(LHeaderV6.DestinationAddress), False));
      AListDetail.Add(LHederInfo);
    end
    else                                                                                
    begin
      Result                 := False;
      LHederInfo.Level       := 0;
      LHederInfo.Description := Format('Internet protocol version 4, Src: %s, Dst %s ',[LInternalIP.Src,LInternalIP.Dst]);
      LHederInfo.Value       := NULL;
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(LHeaderV4),HeaderIPSize(aPacketData,aPacketSize),False));
      AListDetail.Add(LHederInfo);


      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Version:';      
      LHederInfo.Value       := (LHeaderV4.VerLen shr 4) and $0F;
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.VerLen)),1,False));
      AListDetail.Add(LHederInfo); 

      LHederInfo.Description := 'Header length:';      
      LHederInfo.Value       := (LHeaderV4.VerLen and $0F) * 4;
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.VerLen)),1,False));
      AListDetail.Add(LHederInfo); 

      
      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Differetiated services field:';
      LHederInfo.Value       := LHeaderV4.TOS;
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.TOS)),1,False));
      AListDetail.Add(LHederInfo);

      LTOSInfo := DecodeDifferentiatedServices(LHeaderV4.TOS);

      LHederInfo.Level       := 2;
      LHederInfo.Description := 'Precedence:';
      LHederInfo.Value       := LTOSInfo.Precedence;
      LHederInfo.Hex         := String.Empty;
      AListDetail.Add(LHederInfo);
      
      LHederInfo.Level       := 2;
      LHederInfo.Description := 'Delay:';
      LHederInfo.Value       := LTOSInfo.Delay;
      LHederInfo.Hex         := String.Empty;
      AListDetail.Add(LHederInfo);
      
      LHederInfo.Level       := 2;
      LHederInfo.Description := 'Throughput:';
      LHederInfo.Value       := LTOSInfo.Throughput;
      LHederInfo.Hex         := String.Empty;
      AListDetail.Add(LHederInfo);
      
      LHederInfo.Level       := 2;
      LHederInfo.Description := 'Reliability:';
      LHederInfo.Value       := LTOSInfo.Reliability;
      LHederInfo.Hex         := String.Empty;
      AListDetail.Add(LHederInfo);                        
      
      
      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Total length:';
      LHederInfo.Value       := ntohs(LHeaderV4.TotalLen);
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.TotalLen)),4,False));
      AListDetail.Add(LHederInfo);    
      
      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Identification:';
      LHederInfo.Value       := ntohs(LHeaderV4.ID);   
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.id)),4,False));
      AListDetail.Add(LHederInfo);          
      
      LIsFragmented           := (LHeaderV4.FlagsOff and $8000) <> 0; // true se il pacchetto può essere frammentato
      LIsLastFragment         := (LHeaderV4.FlagsOff and $2000) <> 0; // true se questo è l'ultimo frammento del pacchetto
      LFragmentOffset         := LHeaderV4.FlagsOff and $1FFF; // offset del frammento (in unità di 8 byte)    

      LFlagOffInfo := String.Empty;
      if LIsFragmented then
        LFlagOffInfo := 'IsFragmented';
      if LIsLastFragment then
        LFlagOffInfo := 'IsLastFragment';

        LFlagOffInfo := Format('%s Fragment Offset %d',[LFlagOffInfo,LFragmentOffset]).Trim;

      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Flags:';
      LHederInfo.Value       := Format('%d %s',[ntohs(LHeaderV4.FlagsOff),LFlagOffInfo]);
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.FlagsOff)),4,False));
      AListDetail.Add(LHederInfo);          
            
      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Time to live:';
      LHederInfo.Value       := Format('%d hop',[LHeaderV4.TTL]);      
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.TTL)),4,False));
      AListDetail.Add(LHederInfo);      


      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Protocol:';
      LHederInfo.Value       := Format('%s [%d]',[LInternalIP.IpProtoAcronym,LInternalIP.IpProto]);
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.Protocol)),1,False));
      AListDetail.Add(LHederInfo);              

      LHederInfo.Level       := 1;
      LHederInfo.Description := 'CheckSum:';
      LHederInfo.Value       := ntohs(LHeaderV4.Checksum);         
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.Checksum)),4,False));
      AListDetail.Add(LHederInfo);  

      
      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Source:';
      LHederInfo.Value       := LInternalIP.Src;               
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.SrcIP)),5,False));
      AListDetail.Add(LHederInfo);
            
      LHederInfo.Level       := 1;
      LHederInfo.Description := 'Destination:';
      LHederInfo.Value       := LInternalIP.Dst;                     
      LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeaderV4.DestIP)),5,False));
      AListDetail.Add(LHederInfo);  
      if not TWPcapProtocolBaseUDP.HeaderToString(aPacketData,aPacketSize,AListDetail) then
        TWPcapProtocolBaseTCP.HeaderToString(aPacketData,aPacketSize,AListDetail);
    end;
  finally               
    Dispose(LInternalIP)
  end;
end;

class Procedure TWpcapIPHeader.AnalyzeIPProtocol(const aPacketData: PByte;aPacketSize: Integer; aInternalIP: PTInternalIP);
begin
  if not TWPcapProtocolBaseUDP.AnalyzeUDPProtocol(aPacketData,aPacketSize,aInternalIP.IpProtoAcronym,aInternalIP.DetectedIPProto) then
    TWPcapProtocolBaseTCP.AnalyzeTCPProtocol(aPacketData,aPacketSize,aInternalIP.IpProtoAcronym,aInternalIP.DetectedIPProto);
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
  case IpClassType(aPacketData,aPacketSize) of
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

  if TWPcapProtocolBaseUDP.HeaderUDP(aPacketData,aPacketSize,LUdpPhdr) then
  begin
    aInternalIP.PortSrc := TWPcapProtocolBaseUDP.SrcPort(LUdpPhdr);
    aInternalIP.PortDst := TWPcapProtocolBaseUDP.DstPort(LUdpPhdr);
    {how can detect direction of packet ??}
    if not Assigned(aIANADictionary) then Exit;
    
    if aIANADictionary.TryGetValue(Format('%d_%d',[aInternalIP.PortDst,IPPROTO_IANA_UDP]),aIANARow) then
     aInternalIP.IANAProtoStr := aIANARow.ProtocolName
    else if aIANADictionary.TryGetValue(Format('%d_%d',[aInternalIP.PortSrc,IPPROTO_IANA_UDP]),aIANARow) then
     aInternalIP.IANAProtoStr := aIANARow.ProtocolName
  end
  else if TWPcapProtocolBaseTCP.HeaderTCP(aPacketData,aPacketSize,LTcpPhdr) then
  begin
    aInternalIP.PortSrc := TWPcapProtocolBaseTCP.SrcPort(LTcpPhdr);
    aInternalIP.PortDst := TWPcapProtocolBaseTCP.DstPort(LTcpPhdr);    

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

class function TWpcapIPHeader.EthAndIPHeaderSize(const aPacketData: PByte; aPacketSize: Integer): Word;
begin
  Result := HeaderEthSize+HeaderIPSize(aPacketData,aPacketSize);
end;

end.
