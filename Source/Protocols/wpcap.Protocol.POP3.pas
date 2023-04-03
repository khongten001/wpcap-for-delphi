unit wpcap.Protocol.POP3;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,idGlobal,
  Wpcap.protocol.TCP,System.Variants,Wpcap.BufferUtils,wpcap.StrUtils;

type

  /// <summary>
  /// The POP3 protocol implementation class.
  /// </summary>
  TWPcapProtocolPOP3 = Class(TWPcapProtocolBaseTCP)
  private
  protected
  public
    /// <summary>
    /// Returns the default POP3 port (110).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the POP3 protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the POP3 protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the POP3 protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; override;            
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean; override;
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolPOP3 }
class function TWPcapProtocolPOP3.DefaultPort: Word;
begin
  Result := PROTO_POP3_PORT;
end;

class function TWPcapProtocolPOP3.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_POP3
end;

class function TWPcapProtocolPOP3.ProtoName: String;
begin
  Result := 'Post Office Protocol';
end;

class function TWPcapProtocolPOP3.AcronymName: String;
begin
  Result := 'POP3';
end;

class function TWPcapProtocolPOP3.IsValid(const aPacket: PByte;aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;

var LTCPPtr: PTCPHdr;
begin
  Result := False;    
  if not HeaderTCP(aPacket,aPacketSize,LTCPPtr) then exit;   
  if not PayLoadLengthIsValid(LTCPPtr,aPacket,aPacketSize) then  Exit;

  Result := IsValidByDefaultPort(DstPort(LTCPPtr),SrcPort(LTCPPtr),aAcronymName,aIdProtoDetected)  
end;

class function TWPcapProtocolPOP3.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;
var LTCPPayLoad        : PByte;
    LTCPPHdr           : PTCPHdr;
    LTCPPayLoadLen     : Integer;
    LOffset            : Integer;    
begin
  Result := False;

  if not HeaderTCP(aPacketData,aPacketSize,LTCPPHdr) then Exit;
  FIsFilterMode    := aIsFilterMode;
  LTCPPayLoad      := GetTCPPayLoad(aPacketData,aPacketSize);
  LTCPPayLoadLen   := TCPPayLoadLength(LTCPPHdr,aPacketData,aPacketSize);
  AListDetail.Add(AddHeaderInfo(aStartLevel,AcronymName, Format('%s (%s)', [ProtoName, AcronymName]), null, LTCPPayLoad,LTCPPayLoadLen ));

  LOffSet    := 0;  
  Result     := ParserByEndOfLine(aStartLevel,LTCPPayLoadLen,LTCPPayLoad,AListDetail,LOffSet);
end;


end.
                                                 
