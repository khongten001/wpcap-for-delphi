unit wpcap.Protocol.UDP;

interface

uses
  wpcap.Conts, wpcap.Types, WinSock, wpcap.BufferUtils, wpcap.Protocol.Base,
  System.SysUtils, System.Variants, wpcap.StrUtils;

type
  //In this structure for UPD packet, the fields are:
  //
  //uh_sport: the source port (2 bytes)
  //uh_dport: the destination port (2 bytes)
  //uh_ulen : the length of the UDP datagram, header included (2 bytes)
  //uh_sum  : the UDP datagram checksum (2 bytes)
  PUDPHdr = ^TUDPHdr;
  TUDPHdr = packed record
    SrcPort   : Word;    // Source port
    DstPort   : Word;    // Destination port
    Length    : Word;    // Length of UDP packet (including header)
    CheckSum  : Word;    // UDP checksum (optional, can be zero)
  end;

  /// <summary>
  /// Base class for all protocols that use the User Datagram Protocol (UDP).
  /// This class extends the TWPcapProtocolBase class with UDP-specific functions.
  /// </summary>
  TWPcapProtocolBaseUDP = Class(TWPcapProtocolBase)
  private

  protected
    /// <summary>
    /// Checks whether the length of the payload is valid for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function PayLoadLengthIsValid(const aUDPPtr: PUDPHdr): Boolean; virtual;
  public
    class function AcronymName: String; override;
    class function DefaultPort: Word; override;
    class function HeaderLength(aFlag:Byte): word; override;
    class function IDDetectProto: byte; override;  
    /// <summary>
    /// Returns the length of the UDP payload.
    /// </summary>
    class function UDPPayLoadLength(const aUDPPtr: PUDPHdr): Word; static;

    /// <summary>
    /// Checks whether the packet is valid for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function IsValid(const aPacket:PByte;aPacketSize:Integer; var aAcronymName: String;
      var aIdProtoDetected: Byte): Boolean; virtual;

    /// <summary>
    /// Returns the source port number for the UDP packet.
    /// </summary>
    class function SrcPort(const aUDPPtr: PUDPHdr): Word; static;

    /// <summary>
    /// Returns the destination port number for the UDP packet.
    /// </summary>
    class function DstPort(const aUDPPtr: PUDPHdr): Word; static;  

    /// <summary>
    /// Attempts to parse a UDP header from the provided data, and sets the pointer to the parsed header.
    /// </summary>
    /// <param name="aData">The data to parse.</param>
    /// <param name="aSize">The size of the data.</param>
    /// <param name="aPUDPHdr">The pointer to the parsed UDP header.</param>
    /// <param name="aIsIPV6">The the type of header IP</param>  
    /// <returns>True if a UDP header was successfully parsed, otherwise False.</returns>
    class function HeaderUDP(const aData: PByte; aSize: Integer; var aPUDPHdr: PUDPHdr): Boolean;static;

    /// <summary>
    /// Returns a pointer to the payload of the provided UDP data.
    /// </summary>
    /// <param name="AData">The UDP data to extract the payload from.</param>
    /// <param name="aSize">PacketIp</param>
    /// <returns>A pointer to the beginning of the UDP payload.</returns>
    class function GetUDPPayLoad(const AData: PByte;aSize: word): PByte;static;     

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
   
    /// <summary>
    /// This function returns a TListHeaderString of strings representing the fields in the UDP header. 
    //It takes a pointer to the packet data and an integer representing the size of the packet as parameters, and returns a dictionary of strings.
    /// </summary>
    class function HeaderToString(const aPacketData: PByte; aPacketSize: Integer;AListDetail: TListHeaderString): Boolean;override;            
  end;

implementation

uses wpcap.Level.Ip,wpcap.Protocol;

{TWPcapProtocolBaseUDP}

class function TWPcapProtocolBaseUDP.DefaultPort: Word;
begin
  Result := 0; 
end;

class function TWPcapProtocolBaseUDP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_UDP;
end;

class function TWPcapProtocolBaseUDP.HeaderLength(aFlag:Byte): word;
begin
  Result := SizeOf(TUDPHdr)
end;

class function TWPcapProtocolBaseUDP.AcronymName: String;
begin
  Result := 'UDP';
end;

class function TWPcapProtocolBaseUDP.PayLoadLengthIsValid(const aUDPPtr: PUDPHdr): Boolean;
begin
  Result := UDPPayLoadLength(aUDPPtr)> HeaderLength(0);
end;

class function TWPcapProtocolBaseUDP.UDPPayLoadLength(const aUDPPtr: PUDPHdr): word;
begin
  Result := wpcapntohs(aUDPPtr.Length);
end;

class function TWPcapProtocolBaseUDP.IsValid(const aPacket:PByte;aPacketSize:Integer;var aAcronymName:String;var aIdProtoDetected:Byte): Boolean;
var LPUDPHdr: PUDPHdr;
begin
  Result := False;
  if not HeaderUDP(aPacket,aPacketSize,LPUDPHdr) then Exit;
  
  if not PayLoadLengthIsValid(LPUDPHdr) then  Exit;

  Result := IsValidByDefaultPort(SrcPort(LPUDPHdr),DstPort(LPUDPHdr),aAcronymName,aIdProtoDetected);
end;

class function TWPcapProtocolBaseUDP.SrcPort(const aUDPPtr: PUDPHdr): Word;
begin
  Result := wpcapntohs(aUDPPtr.SrcPort);
end;

class function TWPcapProtocolBaseUDP.DstPort(const aUDPPtr: PUDPHdr): Word;
begin
  Result := wpcapntohs(aUDPPtr.DstPort);
end;

class function TWPcapProtocolBaseUDP.GetUDPPayLoad(const AData:Pbyte;aSize: Word):PByte;
begin
  Result := AData + TWpcapIPHeader.EthAndIPHeaderSize(AData,aSize)+ HeaderLength(0);
end;

class function TWPcapProtocolBaseUDP.HeaderUDP(const aData: PByte; aSize: Integer; var aPUDPHdr: PUDPHdr): Boolean;
var aSizeEthIP:Word;
begin
  Result     := False;
  aSizeEthIP := TWpcapIPHeader.EthAndIPHeaderSize(AData,aSize);

  // Check if the data size is sufficient for the Ethernet, IP, and UDP headers
  if (aSize < aSizeEthIP + HeaderLength(0)) then Exit;

  // Parse the Ethernet header
  case TWpcapIPHeader.IpClassType(aData,aSize) of
    imtIpv4 : 
      begin
        // Parse the IPv4 header
        if TWpcapIPHeader.HeaderIPv4(aData,aSize).Protocol <> IPPROTO_UDP then Exit;

        // Parse the UDP header
        aPUDPHdr := PUDPHdr(aData + aSizeEthIP);
        Result   := True;     
      end;
   imtIpv6:
      begin

        if TWpcapIPHeader.HeaderIPv6(aData,aSize).NextHeader <> IPPROTO_UDP then Exit;
        // Parse the UDP header
        aPUDPHdr := PUDPHdr(aData + aSizeEthIP);
        Result   := True;
      end;      
  end;
end;

class function TWPcapProtocolBaseUDP.AnalyzeUDPProtocol(const aData:Pbyte;aSize:Integer;var aArcronymName:String;var aIdProtoDetected:Byte):boolean;
var LUDPPtr : PUDPHdr;
    I       : Integer;
begin
  Result  := False;
  if not HeaderUDP(aData,aSize,LUDPPtr) then exit;
  
  aIdProtoDetected := IDDetectProto;
  Result           := True;
  for I := 0 to FListProtolsUDPDetected.Count-1 do
    if FListProtolsUDPDetected[I].IsValid(aData,aSize,aArcronymName,aIdProtoDetected) then Exit;
end;

class function TWPcapProtocolBaseUDP.HeaderToString(const aPacketData: PByte;aPacketSize: Integer; AListDetail: TListHeaderString): Boolean;
var LPUDPHdr : PUDPHdr;
begin
  Result := False;
  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then exit;
  
  AListDetail.Add(AddHeaderInfo(0,Format('User Datagram Protocol, Src Port: %d, Dst Port: %d',[SrcPort(LPUDPHdr),DstPort(LPUDPHdr)]),null,Pbyte(LPUDPHdr),HeaderLength(0)));
  AListDetail.Add(AddHeaderInfo(1,'Header length:',HeaderLength(0),nil,0));
  AListDetail.Add(AddHeaderInfo(1,'Source port:',SrcPort(LPUDPHdr),@(LPUDPHdr.SrcPort),SizeOf(LPUDPHdr.SrcPort)));
  AListDetail.Add(AddHeaderInfo(1,'Destination port:',DstPort(LPUDPHdr),@(LPUDPHdr.DstPort),SizeOf(LPUDPHdr.DstPort)));
  AListDetail.Add(AddHeaderInfo(1,'Length:',SizeToStr(UDPPayLoadLength(LPUDPHdr)),@(LPUDPHdr.Length),SizeOf(LPUDPHdr.Length)));  
  AListDetail.Add(AddHeaderInfo(1,'Checksum:',wpcapntohs(LPUDPHdr.CheckSum),@(LPUDPHdr.CheckSum),SizeOf(LPUDPHdr.CheckSum)));    
  AListDetail.Add(AddHeaderInfo(1,'Payload length:',SizeToStr(UDPPayLoadLength(LPUDPHdr)-8),nil,0));      
  Result := True;
end;

end.
