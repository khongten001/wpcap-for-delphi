unit wpcap.Protocol.L2TP;

interface

uses wpcap.Protocol.Base,wpcap.Conts,WinSock2,wpcap.Protocol.UDP;

type

  /// <summary>
  /// Represents the header for the Layer 2 Tunneling Protocol (L2TP).
  /// </summary>
  PL2TPHdr = ^TL2TPHdr;
  TL2TPHdr = packed record
    Flags     : Byte;      // Flags for the L2TP header.
    Version   : Byte;      // Version of the L2TP protocol.
    Length    : Word;      // Length of the L2TP header and payload.
    TunnelId  : Word;      // Identifier for the L2TP tunnel.
    SessionId : Word;      // Identifier for the L2TP session.
    Ns        : Byte;      // Next sequence number for this session.
    Nr        : Byte;      // Next received sequence number for this session.
    OffsetSize: Word;      // Size of the optional offset field in the header.
  end;

  
  /// <summary>
  /// Represents the Layer 2 Tunneling Protocol (L2TP) implementation for the WPcap library, which provides access to network traffic on Windows.
  /// </summary>
  TWPcapProtocolL2TP = Class(TWPcapProtocolBaseUDP)
  public
    /// <summary>
    /// Returns the default port number used by the L2TP protocol (1701).
    /// </summary>
    class Function DefaultPort: Word;override;

    /// <summary>
    /// Return Intenal protocol ID
    /// </summary>
    class function IDDetectProto: Integer; override;
    
    /// <summary>
    /// Returns the name of the protocol for the L2TP protocol
    /// </summary>
    class function ProtoName: String; override;

    /// <summary>
    /// Returns the acronym name for the L2TP protocol ("L2TP").
    /// </summary>
    class function AcronymName: String; override;

    /// <summary>
    /// Returns the length of the L2TP header in bytes.
    /// </summary>
    class function HeaderLength: word; override;

    /// <summary>
    /// Determines whether the given UDP packet contains a valid L2TP header and payload.
    /// </summary>
    class function IsValid(const aPacket:PByte;aPacketSize:Integer;const aUDPPtr: PUDPHdr;const aUDPPayLoad:Pbyte;var aAcronymName:String;var aIdProtoDetected:Byte): Boolean;override;

    /// <summary>
    /// Returns a pointer to the L2TP header within the given UDP payload.
    /// </summary>
    class Function Header(const aUDPPayLoad:PByte):PL2TPHdr;   
  end;  



implementation


{ TWPcapProtocolDNS }

class function TWPcapProtocolL2TP.DefaultPort: Word;
begin
  Result := PROTO_L2TP_PORT;
end;

class function TWPcapProtocolL2TP.IDDetectProto: Integer;
begin
  Result := DETECT_PROTO_L2TP;
end;

class function TWPcapProtocolL2TP.ProtoName: String;
begin
  Result := 'Layer 2 Tunneling Protocol';
end;

class function TWPcapProtocolL2TP.AcronymName: String;
begin
  Result := 'L2TP';
end;

class function TWPcapProtocolL2TP.HeaderLength: word;
begin
  Result := SizeOf(TL2TPHdr)
end;

class function TWPcapProtocolL2TP.IsValid(const aPacket:PByte;aPacketSize:Integer;const aUDPPtr: PUDPHdr;const aUDPPayLoad: Pbyte; var aAcronymName: String;
  var aIdProtoDetected: Byte): Boolean;

const L2TP_MAGIC_COOKIE = 3355574314; 
      L2TP_VERSION      = 2;  
var LL2TPHdr : PL2TPHdr;
    Lcoockie : Pcardinal;
begin
  Result := False;
  if Not PayLoadLengthIsValid(aUDPPtr) then Exit;
    
  LL2TPHdr  := Header(aUDPPayLoad);
  {4 byte after UDP header for test L2TP_MAGIC_COOKIE}
  Lcoockie  := PCardinal(aUDPPayLoad);
    
  if ntohl(Lcoockie^) <> L2TP_MAGIC_COOKIE then Exit;

  Result := ( LL2TPHdr.version = L2TP_VERSION) and 
            ( ntohs(LL2TPHdr.length) = ntohs(aUDPPtr.Length)-8);
  if Result then
  begin
    aAcronymName     := AcronymName;
    aIdProtoDetected := IDDetectProto;
  end;
end;

class function TWPcapProtocolL2TP.Header(const aUDPPayLoad: PByte): PL2TPHdr;
begin
  Result := PL2TPHdr(aUDPPayLoad)
end;


end.
