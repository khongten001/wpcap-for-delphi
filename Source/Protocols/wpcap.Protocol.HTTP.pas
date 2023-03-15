unit wpcap.Protocol.HTTP;

interface

uses wpcap.Protocol.Base,wpcap.Conts,wpcap.Types,System.SysUtils,Wpcap.protocol.TCP;

type

  /// <summary>
  /// The HTTP protocol implementation class.
  /// </summary>
  TWPcapProtocolHTTP = Class(TWPcapProtocolBaseTCP)
  private
  protected
  public
    /// <summary>
    /// Returns the default HTTP port (80 or 8080).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the HTTP protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the HTTP protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the HTTP protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; override;    
      
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolHTTP }
class function TWPcapProtocolHTTP.DefaultPort: Word;
begin
  Result := PROTO_HTTP_PORT_1;
end;

class function TWPcapProtocolHTTP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_HTTP
end;

class function TWPcapProtocolHTTP.ProtoName: String;
begin
  Result := 'Hypertext Transfer Protocol';
end;

class function TWPcapProtocolHTTP.AcronymName: String;
begin
  Result := 'HTTP';
end;

class function TWPcapProtocolHTTP.IsValid(const aPacket: PByte;
  aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var LTCPPtr: PTCPHdr;
begin
  Result  := inherited IsValid(aPacket,aPacketSize,aAcronymName,aIdProtoDetected);  
  if not Result then
  begin
    if not HeaderTCP(aPacket,aPacketSize,LTCPPtr) then exit;   
    if not PayLoadLengthIsValid(LTCPPtr,aPacket,aPacketSize) then  Exit;
    Result := IsValidByPort(PROTO_HTTP_PORT_2,DstPort(LTCPPtr),aAcronymName,aIdProtoDetected)  
  end;
end;

 



end.
                                                 
