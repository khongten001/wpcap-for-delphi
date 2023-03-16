unit wpcap.Protocol.SIP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,wpcap.StrUtils,
  Wpcap.protocol.UDP, WinApi.Windows,wpcap.BufferUtils,Variants;

type
   {https://www.rfc-editor.org/rfc/rfc3261.}

  
  /// <summary>
  /// The SIP protocol implementation class.
  /// </summary>
  TWPcapProtocolSIP = Class(TWPcapProtocolBaseUDP)
  private
    CONST
  protected
  public
    /// <summary>
    /// Returns the default SIP port (110).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the SIP protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the SIP protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the POP3 protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function HeaderToString(const aPacketData: PByte; aPacketSize: Integer; AListDetail: TListHeaderString): Boolean; override;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; override;        
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolSIP }



class function TWPcapProtocolSIP.DefaultPort: Word;
begin
  Result := PROTO_SIP_PORT;
end;

class function TWPcapProtocolSIP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_SIP
end;

class function TWPcapProtocolSIP.ProtoName: String;
begin
  Result := 'Session Initiation Protocol';
end;

class function TWPcapProtocolSIP.IsValid(const aPacket: PByte;
  aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var LUDPPPtr: PUDPHdr;
begin
  Result  := inherited IsValid(aPacket,aPacketSize,aAcronymName,aIdProtoDetected);  
end;

class function TWPcapProtocolSIP.AcronymName: String;
begin
  Result := 'SIP';
end;

class function TWPcapProtocolSIP.HeaderToString(const aPacketData: PByte;aPacketSize: Integer; AListDetail: TListHeaderString): Boolean;
var LUDPPayLoad        : PByte;
    LPUDPHdr           : PUDPHdr;
begin
  Result := False;

  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LUDPPayLoad := GetUDPPayLoad(aPacketData,aPacketSize);

  AListDetail.Add(AddHeaderInfo(0, Format('%s (%s)', [ProtoName, AcronymName]), null, nil,0));


  Result := True;
end;


end.
                                                 
