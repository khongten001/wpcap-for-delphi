unit wpcap.Protocol.TCP;

interface

uses wpcap.Conts,wpcap.Types,WinSock,System.Types,wpcap.Protocol.Base,System.Variants,System.SysUtils,wpcap.StrUtils;

type

  TCPHdr = packed record
    SrcPort   : Word;     // TCP source port
    DstPort   : Word;     // TCP destination port
    SeqNum    : DWORD;    // TCP sequence number
    AckNum    : DWORD;    // TCP acknowledgment number
    DataOff   : Byte;     // TCP data offset (number of 32-bit words in header)
    Flags     : Byte;     // TCP flags (SYN, ACK, FIN, etc.)
    WindowSize: Word;     // TCP window size
    Checksum  : Word;     // TCP checksum
    UrgPtr    : Word;     // TCP urgent pointer
  end;
  PTCPHdr = ^TCPHdr;


  /// <summary>
  /// Base class for all protocols that use the TCP stands for Transmission Control Protocol. (TCP).
  /// This class extends the TWPcapProtocolBase class with TCP-specific functions.
  /// </summary>
  TWPcapProtocolBaseTCP = Class(TWPcapProtocolBase)
  private
  protected
    /// <summary>
    /// Checks whether the length of the payload is valid for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function PayLoadLengthIsValid(const aTCPPtr: PTCPHdr;const aPacketData:PByte;aPacketSize:Word): Boolean; virtual;
    
  public
    class function AcronymName: String; override;
    class function DefaultPort: Word; override;
    class function HeaderLength: word; override;
    class function IDDetectProto: Integer; override;
    /// <summary>
    /// Returns the length of the TCP payload.
    /// </summary>
    class function TCPPayLoadLength(const aTCPPtr: PTCPHdr;const aPacketData:PByte;aPacketSize:Word): Word; static;

    /// <summary>
    /// Checks whether the packet is valid for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function IsValid(const aPacket:PByte;aPacketSize:Integer;var aAcronymName: String;var aIdProtoDetected: Byte): Boolean; virtual;

    /// <summary>
    /// Returns the source port number for the TCP packet.
    /// </summary>
    class function SrcPort(const aTCPPtr: PTCPHdr): Word; static;

    /// <summary>
    /// Returns the destination port number for the TCP packet.
    /// </summary>
    class function DstPort(const aTCPPtr: PTCPHdr): Word; static;   
    /// <summary>
    /// Checks whether the packet has the default port for the protocol.
    /// </summary>
    class function IsValidByDefaultPort(aDstPort: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;overload;    

    /// <summary>
    /// Extracts the TCP header from a packet and returns it through aPHeader.
    /// </summary>
    /// <param name="aData">Pointer to the start of the packet.</param>
    /// <param name="aSize">Size of the packet.</param>
    /// <param name="aPHeader">Pointer to the TCP header.</param>
    /// <returns>True if the TCP header was successfully extracted, False otherwise.</returns>
    class function HeaderTCP(const aData: PByte; aSize: Integer; var aPTCPHdr: PTCPHdr): Boolean;static;

    /// <summary>
    /// Returns a pointer to the payload of the provided TCP data.
    /// </summary>
    /// <param name="AData">The TCP data to extract the payload from.</param>
    /// <param name="aSize">Size of packet</param>
    /// <returns>A pointer to the beginning of the TCP payload.</returns>
    class function GetTCPPayLoad(const AData: PByte;aSize: word): PByte;static;  

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

    class function HeaderToString(const aPacketData: PByte; aPacketSize: Integer;AListDetail: TListHeaderString): Boolean;override;      
  end;      



implementation

uses wpcap.Level.Ip,wpcap.protocol;

class function TWPcapProtocolBaseTCP.DefaultPort: Word;
begin
  Result := 0; 
end;

class function TWPcapProtocolBaseTCP.IDDetectProto: Integer;
begin
  Result := DETECT_PROTO_TCP;
end;

class function TWPcapProtocolBaseTCP.HeaderLength: word;
begin
  Result := SizeOf(TCPHdr)
end;

class function TWPcapProtocolBaseTCP.AcronymName: String;
begin
  Result := 'TCP';
end;

class function TWPcapProtocolBaseTCP.AnalyzeTCPProtocol(const aData:Pbyte;aSize:Integer;var aArcronymName:String;var aIdProtoDetected:Byte):boolean;
var LTCPPPtr        : PTCPHdr;
    I              : Integer;
begin
  Result := False;
  if not HeaderTCP(aData,aSize,LTCPPPtr) then exit;
  
  aIdProtoDetected := DETECT_PROTO_TCP;

  for I := 0 to FListProtolsTCPDetected.Count-1 do
  begin
    if FListProtolsTCPDetected[I].IsValid(aData,aSize,aArcronymName,aIdProtoDetected) then
    begin
      Result := True;
      Exit;
    end;
  end;
end;


{ TWPcapProtocolBaseTCP }
class function TWPcapProtocolBaseTCP.PayLoadLengthIsValid(const aTCPPtr: PTCPHdr;const aPacketData:PByte; aPacketSize:Word): Boolean;
begin
   Result := TCPPayLoadLength(aTCPPtr,aPacketData,aPacketSize)> HeaderLength;
end;

class function TWPcapProtocolBaseTCP.TCPPayLoadLength(const aTCPPtr: PTCPHdr;const aPacketData:PByte;aPacketSize:Word): Word;
var DataOffset: Integer;
begin
  // Get the data offset in bytes
  DataOffset := ((aTCPPtr^.DataOff and $F0) shr 4) * SizeOf(DWORD);

  // Calculate the length of the payload
  Result := aPacketSize -  TWpcapIPHeader.EthAndIPHeaderSize(aPacketData,aPacketSize) - DataOffset;
end;

class function TWPcapProtocolBaseTCP.IsValid(const aPacket:PByte;aPacketSize:Integer;var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var LTCPPtr: PTCPHdr;
begin
  Result := False;    
  if not HeaderTCP(aPacket,aPacketSize,LTCPPtr) then exit;   
  if not PayLoadLengthIsValid(LTCPPtr,aPacket,aPacketSize) then  Exit;

  Result := IsValidByDefaultPort(DstPort(LTCPPtr),aAcronymName,aIdProtoDetected)
end;

class function TWPcapProtocolBaseTCP.SrcPort(const aTCPPtr: PTCPHdr): Word;
begin
  Result := ntohs(aTCPPtr.SrcPort);
end;

class function TWPcapProtocolBaseTCP.DstPort(const aTCPPtr: PTCPHdr): Word;
begin
  Result := ntohs(aTCPPtr.DstPort);
end;

class function TWPcapProtocolBaseTCP.IsValidByDefaultPort(aDstPort: Integer;
  var aAcronymName: String; var aIdProtoDetected: Byte): Boolean;
begin
  Result := False;
  if DefaultPort = 0 then Exit;
  
   Result := ( aDstPort = DefaultPort );

   if not Result then exit;

   aAcronymName     := AcronymName;
   aIdProtoDetected := IDDetectProto;   
end;

class function TWPcapProtocolBaseTCP.GetTCPPayLoad(const AData: PByte; aSize: word): PByte;
var TCPHeader       : PTCPhdr;
    EthIpHeaderSize : Integer;
begin
  EthIpHeaderSize := TWpcapIPHeader.EthAndIPHeaderSize(AData,aSize);
  TCPHeader       := PTCPhdr(AData  + EthIpHeaderSize);
  Result          := AData + EthIpHeaderSize + ( TCPHeader.DataOff * 4);
end;

class function TWPcapProtocolBaseTCP.HeaderTCP(const aData: PByte; aSize: Integer; var aPTCPHdr: PTCPHdr): Boolean;
var aSizeEthAndIP: Word;
begin
  Result        := False;
  aSizeEthAndIP := TWpcapIPHeader.EthAndIPHeaderSize(AData,aSize);
  // Check if the data size is sufficient for the Ethernet, IP, and TCP headers
  if (aSize < aSizeEthAndIP + SizeOf(TCPHdr)) then Exit;
  
    // Parse the Ethernet header
  case TWpcapIPHeader.IpClassType(aData,aSize) of
    imtIpv4 : 
      begin
        // Parse the IPv4 header
        if TWpcapIPHeader.HeaderIPv4(aData,aSize).Protocol <> IPPROTO_TCP then Exit;

        // Parse the UDP header
        aPTCPHdr := PTCPHdr(aData + TWpcapIPHeader.EthAndIPHeaderSize(AData,aSize));
        Result   := True;     
      end;
   imtIpv6:
      begin
        if TWpcapIPHeader.HeaderIPv6(aData,aSize).NextHeader <> IPPROTO_TCP then Exit;
        // Parse the TCP header
        aPTCPHdr := PTCPHdr(aData + TWpcapIPHeader.EthAndIPHeaderSize(AData,aSize));
        Result   := True;
      end;      
  end;
end;

class function TWPcapProtocolBaseTCP.HeaderToString(const aPacketData: PByte;aPacketSize: Integer; AListDetail: TListHeaderString): Boolean;
var LPTCPHdr  : PTCPHdr;
    LHederInfo: THeaderString;
begin

  if not HeaderTCP(aPacketData,aPacketSize,LPTCPHdr) then exit;
  
  LHederInfo.Level       := 0;
  LHederInfo.Description := Format('Transmission Control Protocol, Src Port: %d, Dst %d: 80, Seq: %d, Ack: %d, Len: %s',[SrcPort(LPTCPHdr),DstPort(LPTCPHdr),
                                  ntohl(LPTCPHdr.SeqNum),ntohl(LPTCPHdr.AckNum),SizeTostr(LPTCPHdr.DataOff shr 4)]);
  LHederInfo.Value       := NUlL;
  LHederInfo.Hex         := String.Empty;
  AListDetail.Add(LHederInfo);
  
  LHederInfo.Level       := 1;
  LHederInfo.Description := 'Source port:';
  LHederInfo.Value       := ntohs(LPTCPHdr.SrcPort);
  LHederInfo.Hex         := IntToHex(ntohs(LPTCPHdr.SrcPort), 4);
  AListDetail.Add(LHederInfo);

  LHederInfo.Level       := 1;
  LHederInfo.Description := 'Destination port:';
  LHederInfo.Value       := ntohs(LPTCPHdr.DstPort);
  LHederInfo.Hex         := IntToHex(ntohs(LPTCPHdr.DstPort), 4);
  AListDetail.Add(LHederInfo);

  LHederInfo.Level       := 1;
  LHederInfo.Description := 'Sequence number:';
  LHederInfo.Value       := ntohl(LPTCPHdr.SeqNum);
  LHederInfo.Hex         := IntToHex(ntohl(LPTCPHdr.SeqNum), 8);
  AListDetail.Add(LHederInfo);

  LHederInfo.Level       := 1;
  LHederInfo.Description := 'Acknowledgment number:';
  LHederInfo.Value       := ntohl(LPTCPHdr.AckNum);
  LHederInfo.Hex         := IntToHex(ntohl(LPTCPHdr.AckNum), 8);
  AListDetail.Add(LHederInfo);

  LHederInfo.Level       := 1;
  LHederInfo.Description := 'Data offset:';
  LHederInfo.Value       := SizeTostr(LPTCPHdr.DataOff shr 4);
  LHederInfo.Hex         := IntToHex(LPTCPHdr.DataOff, 2);
  AListDetail.Add(LHederInfo);

  LHederInfo.Level       := 1;
  LHederInfo.Description := 'Reserved bits:';
  LHederInfo.Value       := (LPTCPHdr.DataOff and $0F) shl 2;
  LHederInfo.Hex         := IntToHex((LPTCPHdr.DataOff and $0F) shl 2, 2);
  AListDetail.Add(LHederInfo);

  LHederInfo.Level       := 1;
  LHederInfo.Description := 'Flags:';
  LHederInfo.Value       := ntohs(LPTCPHdr.Flags);        //GetTCPFlags
  LHederInfo.Hex         := IntToHex(LPTCPHdr.Flags, 2);
  AListDetail.Add(LHederInfo);

  LHederInfo.Level       := 1;
  LHederInfo.Description := 'Window size:';
  LHederInfo.Value       := ntohs(LPTCPHdr.WindowSize);
  LHederInfo.Hex         := IntToHex(ntohs(LPTCPHdr.WindowSize), 4);
  AListDetail.Add(LHederInfo);

  LHederInfo.Level       := 1;
  LHederInfo.Description := 'Checksum:';
  LHederInfo.Value       := ntohs(LPTCPHdr.Checksum);
  LHederInfo.Hex         := IntToHex(ntohs(LPTCPHdr.Checksum), 4);
  AListDetail.Add(LHederInfo);

  LHederInfo.Level       := 1;
  LHederInfo.Description := 'Urgent pointer:';
  LHederInfo.Value       := ntohs(LPTCPHdr.UrgPtr);
  LHederInfo.Hex         := IntToHex(ntohs(LPTCPHdr.UrgPtr),2)

end;

end.
