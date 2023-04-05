unit wpcap.Protocol.SSDP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,wpcap.StrUtils,
  Wpcap.protocol.UDP, WinApi.Windows,wpcap.BufferUtils,Variants;
type
  
  /// <summary>
  /// The SSDP protocol implementation class.
  /// </summary>
  TWPcapProtocolSSDP = Class(TWPcapProtocolBaseUDP)
  private
  protected
  public
    /// <summary>
    /// Returns the default SSDP port (110).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the SSDP protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the SSDP protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the POP3 protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean; override;
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolSSDP }



class function TWPcapProtocolSSDP.DefaultPort: Word;
begin
  Result := PROTO_SSDP_PORT;
end;

class function TWPcapProtocolSSDP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_SSDP
end;

class function TWPcapProtocolSSDP.ProtoName: String;
begin
  Result := 'Trivial File Transfer Protocol';
end;

class function TWPcapProtocolSSDP.AcronymName: String;
begin
  Result := 'SSDP';
end;

class function TWPcapProtocolSSDP.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;
var LUDPPayLoad        : PByte;
    LPUDPHdr           : PUDPHdr;    
    LUdpPayLoadLen     : integer;
    LOffSet            : Integer;
begin
  Result := False;

  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LUDPPayLoad    := GetUDPPayLoad(aPacketData,aPacketSize);
  FIsFilterMode  := aIsFilterMode;
  LUdpPayLoadLen := UDPPayLoadLength(LPUDPHdr)-8;
  AListDetail.Add(AddHeaderInfo(aStartLevel,AcronymName, Format('%s (%s)', [ProtoName, AcronymName]), null, LUDPPayLoad,LUdpPayLoadLen));

  LOffSet    := 0;  
  Result     := ParserByEndOfLine(aStartLevel,LUDPPayLoadLen,LUDPPayLoad,AListDetail,LOffSet);
end;


end.
                                                 
