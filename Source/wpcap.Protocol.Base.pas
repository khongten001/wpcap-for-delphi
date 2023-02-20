unit wpcap.Protocol.Base;

interface

uses wpcap.Protocol.UDP,wpcap.Protocol.TCP,System.SysUtils,WinSock,System.Types;

Type


  /// <summary>
  /// Base class for all protocols in a packet capture. 
  /// This class defines the base behavior that each protocol should implement.
  /// </summary>
  TWPcapProtocolBase = class
  public
    /// <summary>
    /// Returns the default port number for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function DefaultPort: Word; virtual;

    /// <summary>
    /// Returns the protocol name.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function ProtoName: String; virtual;

    /// <summary>
    /// Returns the protocol acronym name.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function AcronymName: String; virtual;

    /// <summary>
    /// Returns detailed information about the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function DetailInfo: String; virtual;

    /// <summary>
    /// Returns the identifier of the detected protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function IDDetectProto: Integer; virtual;

    /// <summary>
    /// Returns the length of the protocol header.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function HeaderLength: Word; virtual;

    /// <summary>
    /// Checks whether the packet has the default port for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function IsValidByDefaultPort(aSrcPort, aDstPort: Integer; var aAcronymName: String;
      var aIdProtoDetected: Byte): Boolean;overload; virtual;

    /// <summary>
    /// Checks whether the packet has the default port for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function HeaderToString:String;virtual;
  end;

  /// <summary>
  /// Base class for all protocols that use the User Datagram Protocol (UDP).
  /// This class extends the TWPcapProtocolBase class with UDP-specific functions.
  /// </summary>
  TWPcapProtocolBaseUDP = Class(TWPcapProtocolBase)
  protected
    /// <summary>
    /// Checks whether the length of the payload is valid for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function PayLoadLengthIsValid(const aUDPPtr: PUDPHdr): Boolean; virtual;
  public
    /// <summary>
    /// Returns the length of the UDP payload.
    /// </summary>
    class function UDPPayLoadLength(const aUDPPtr: PUDPHdr): Word; static;

    /// <summary>
    /// Checks whether the packet is valid for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function IsValid(const aPacket:PByte;aPacketSize:Integer;const aUDPPtr: PUDPHdr; const aUDPPayLoad: PByte; var aAcronymName: String;
      var aIdProtoDetected: Byte): Boolean; virtual;

    /// <summary>
    /// Returns the source port number for the UDP packet.
    /// </summary>
    class function SrcPort(const aUDPPtr: PUDPHdr): Word; static;

    /// <summary>
    /// Returns the destination port number for the UDP packet.
    /// </summary>
    class function DstPort(const aUDPPtr: PUDPHdr): Word; static;   
  end;

  /// <summary>
  /// Base class for all protocols that use the TCP stands for Transmission Control Protocol. (TCP).
  /// This class extends the TWPcapProtocolBase class with TCP-specific functions.
  /// </summary>
  TWPcapProtocolBaseTCP = Class(TWPcapProtocolBase)
  protected
    /// <summary>
    /// Checks whether the length of the payload is valid for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function PayLoadLengthIsValid(const aTCPPtr: PTCPHdr): Boolean; virtual;
    
  public
    /// <summary>
    /// Returns the length of the TCP payload.
    /// </summary>
    class function TCPPayLoadLength(const aTCPPtr: PTCPHdr): Word; static;

    /// <summary>
    /// Checks whether the packet is valid for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function IsValid(const aPacket:PByte;aPacketSize:Integer;const aTCPPtr: PTCPHdr; const aTCPPayLoad: PByte; var aAcronymName: String;
      var aIdProtoDetected: Byte): Boolean; virtual;

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
  end;      

  
implementation

{ TWPcapProtocolBase }

class function TWPcapProtocolBase.DetailInfo: String;
begin
  Result := String.Empty;
end;

class function TWPcapProtocolBase.DefaultPort: Word;
begin
  raise Exception.Create('TWPcapProtocolBase.DefaultPort- Non implemented in base class - please override this method');
end;

class function TWPcapProtocolBase.IDDetectProto: Integer;
begin
  raise Exception.Create('TWPcapProtocolBase.IDDetectProto- Non implemented in base class - please override this method');
end;

class function TWPcapProtocolBase.HeaderLength: word;
begin
  raise Exception.Create('TWPcapProtocolBase.HeaderLength- Non implemented in base class - please override this method');
end;

class function TWPcapProtocolBase.AcronymName: String;
begin
  raise Exception.Create('TWPcapProtocolBase.AcronymName- Non implemented in base class - please override this method');
end;

class function TWPcapProtocolBase.IsValidByDefaultPort(aSrcPort, aDstPort: integer;
  var aAcronymName: String; var aIdProtoDetected: Byte): Boolean;
begin
   Result := ( aSrcPort = DefaultPort ) or ( aDstPort = DefaultPort );

   if not Result then exit;

   aAcronymName     := AcronymName;
   aIdProtoDetected := IDDetectProto;   
end;

class function TWPcapProtocolBase.ProtoName: String;
begin
  Result := String.Empty;
end;

class function TWPcapProtocolBase.HeaderToString: String;
begin
  Result := String.Empty;
end;

{TWPcapProtocolBaseUDP}

class function TWPcapProtocolBaseUDP.PayLoadLengthIsValid(const aUDPPtr: PUDPHdr): Boolean;
begin
  Result := UDPPayLoadLength(aUDPPtr)> HeaderLength;
end;

class function TWPcapProtocolBaseUDP.UDPPayLoadLength(const aUDPPtr: PUDPHdr): word;
begin
  Result := ntohs(aUDPPtr.Length);
end;

class function TWPcapProtocolBaseUDP.IsValid(const aPacket:PByte;aPacketSize:Integer;const aUDPPtr: PUDPHdr;
  const aUDPPayLoad: Pbyte;var aAcronymName:String;var aIdProtoDetected:Byte): Boolean;
begin
  Result := False;
  if not PayLoadLengthIsValid(aUDPPtr) then  Exit;

  Result := IsValidByDefaultPort(SrcPort(aUDPPtr),DstPort(aUDPPtr),aAcronymName,aIdProtoDetected);
end;

class function TWPcapProtocolBaseUDP.SrcPort(const aUDPPtr: PUDPHdr): Word;
begin
  Result := ntohs(aUDPPtr.SrcPort);
end;

class function TWPcapProtocolBaseUDP.DstPort(const aUDPPtr: PUDPHdr): Word;
begin
  Result := ntohs(aUDPPtr.DstPort);
end;

{ TWPcapProtocolBaseTCP }
class function TWPcapProtocolBaseTCP.PayLoadLengthIsValid(const aTCPPtr: PTCPHdr): Boolean;
begin
   Result := TCPPayLoadLength(aTCPPtr)> HeaderLength;
end;

class function TWPcapProtocolBaseTCP.TCPPayLoadLength(const aTCPPtr: PTCPHdr): Word;
var DataOffset: Integer;
begin
  // Get the data offset in bytes
  DataOffset := ((aTCPPtr^.DataOff and $F0) shr 4) * SizeOf(DWORD);

  // Calculate the length of the payload
  Result := 1000; //PacketLength - SizeOf(TCPHdr) - DataOffset;    TODO Change class to pass packet
end;

class function TWPcapProtocolBaseTCP.IsValid(const aPacket:PByte;aPacketSize:Integer;const aTCPPtr: PTCPHdr;const aTCPPayLoad: PByte; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
begin
  Result := False;
  if not PayLoadLengthIsValid(aTCPPtr) then  Exit;

  Result := IsValidByDefaultPort(DstPort(aTCPPtr),aAcronymName,aIdProtoDetected)
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
   Result := ( aDstPort = DefaultPort );

   if not Result then exit;

   aAcronymName     := AcronymName;
   aIdProtoDetected := IDDetectProto;   
end;

end.
