unit wpcap.Protocol.HTTP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,
  Wpcap.protocol.TCP,System.Variants,Wpcap.BufferUtils,wpcap.StrUtils;

type
  {https://datatracker.ietf.org/doc/html/rfc7230}

  TPacketHeader = packed record
    ts_sec  : LongInt; // tempo di cattura, secondi
    ts_usec : LongInt; // tempo di cattura, microsecondi
    incl_len: LongInt; // lunghezza dei dati catturati
    orig_len: LongInt; // lunghezza originale del pacchetto
  end;
  PPacketHeader = ^TPacketHeader;

  TIPHeader = packed record
    ip_verlen  : Byte;     // versione IP e lunghezza dell'header
    ip_tos     : Byte;     // tipo di servizio
    ip_len     : Word;     // lunghezza totale del pacchetto IP
    ip_id      : Word;     // identificatore del pacchetto
    ip_fragoff : Word;     // offset del frammento
    ip_ttl     : Byte;     // time-to-live
    ip_proto   : Byte;     // protocollo
    ip_checksum: Word;     // checksum dell'header IP
    ip_src     : LongWord; // indirizzo IP sorgente
    ip_dst     : LongWord; // indirizzo IP destinazione
  end;
  PIPHeader = ^TIPHeader;

  TTCPHeader = packed record
    tcp_srcport : Word;     // porta sorgente TCP
    tcp_dstport : Word;     // porta destinazione TCP
    tcp_seq     : LongWord; // numero di sequenza
    tcp_ack     : LongWord; // numero di ACK
    tcp_offset  : Byte;     // offset dell'header TCP
    tcp_flags   : Byte;     // flag TCP (syn, ack, etc.)
    tcp_window  : Word;     // finestra di ricezione
    tcp_checksum: Word;     // checksum dell'header TCP
    tcp_urgent  : Word;     // indicatore di dati urgenti
  end;
  PTCPHeader = ^TTCPHeader;

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
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean; override;          
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

class function TWPcapProtocolHTTP.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;
var LTCPPayLoad    : PByte;
    LTCPPayLoadLen : Integer;
    LTCPPHdr       : PTCPHdr;
begin
  Result := False;

  if not HeaderTCP(aPacketData,aPacketSize,LTCPPHdr) then Exit;

  LTCPPayLoad     := GetTCPPayLoad(aPacketData,aPacketSize);
  LTCPPayLoadLen  := TCPPayLoadLength(LTCPPHdr,aPacketData,aPacketSize);
  FIsFilterMode   := aIsFilterMode;
  AListDetail.Add(AddHeaderInfo(aStartLevel,AcronymName, Format('%s (%s)', [ProtoName, AcronymName]),null, LTCPPayLoad, LTCPPayLoadLen ));

  Result := True;
end;

 



end.
                                                 
