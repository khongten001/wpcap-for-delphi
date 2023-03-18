unit wpcap.Protocol.RTP;

interface

uses
  wpcap.Protocol.UDP, wpcap.Protocol.Base, wpcap.Conts, wpcap.Types,
  System.SysUtils, wpcap.BufferUtils, system.Variants,wpcap.StrUtils;

type

{
  https://datatracker.ietf.org/doc/html/rfc3550
  
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |V=2|P|X|  CC   |M|     PT      |       sequence number         |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |                           timestamp                           |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |           synchronization source (SSRC) identifier            |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 |            contributing source (CSRC) identifiers             |
 |                             ....                              |
 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


}


  TRTPHeader = packed record
    Version_Padding_Extension_CC  : Byte; // Versione, Padding, Extension, Count CSRC
    Marker_PT                     : Byte; // Marker, Payload Type
    SequenceNumber                : Word;
    Timestamp                     : Cardinal;
    SSRC                          : Cardinal;
  end;
  PTRTPHeader = ^TRTPHeader;

  TRTPHeaderInternal = packed record
    Version                       : Byte;
    Padding                       : Boolean;
    Extension                     : Boolean;
    COuntCSRC                     : Byte; 
    Marker                        : Boolean;
    PayloadType                   : Byte; 
    SequenceNumber                : Word;
    Timestamp                     : Cardinal;
    SSRC                          : Cardinal;
    CSRC                          : TArray<Cardinal>;
  end;
  PTRTPHeaderInternal = ^TRTPHeaderInternal;
  
  /// <summary>
  /// The RTP protocol implementation class.
  /// </summary>
  TWPcapProtocolRTP = Class(TWPcapProtocolBaseUDP)
  private
    class function GetInternalStructure(const aPacketData: PByte;aPacketSize:Integer): PTRTPHeaderInternal; static;
    class function GetRTPPayloadTypeString(APayloadType: Byte): string; static;
    
  protected
  public
    /// <summary>
    /// Returns the default RTP port (5355).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the RTP protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the RTP protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the RTP protocol.
    /// </summary>
    class function AcronymName: String; override;
    /// <summary>
    ///  Returns a pointer to the RTP header.
    /// </summary>
    class function Header(const aUDPPayLoad: PByte): PTRTPHeader; static;    
    /// <summary>
    ///  Returns the length of the RTP header.
    /// </summary>
    class function HeaderLength(aFlag:Byte): word; override;
    /// <summary>
    ///  Converts the RTP header to a string and adds it to the list of header details.
    /// </summary>
    /// <param name="aPacketData">
    ///   Pointer to the start of the packet data of winpcap.
    /// </param>
    /// <param name="aPacketSize">
    ///   The size of the packet data.
    /// </param>
    /// <param name="AListDetail">
    ///   The list of header details to append to.
    /// </param>
    /// <returns>
    ///   True if the header was successfully added to the list, False otherwise.
    /// </returns>
    class function HeaderToString(const aPacketData: PByte; aPacketSize: Integer; AListDetail: TListHeaderString): Boolean; override;
    class function GetPayLoadRTP(const aPacketData: PByte;aPacketSize: Integer;var aSize:Integer): PByte; static;
    class function GetSoxCommandDecode(const aPacketData:PByte;aPacketSize:Integer): String; static;      
    class function IsValid(const aPacket:PByte;aPacketSize:Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean; override;    
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolMDNS }
class function TWPcapProtocolRTP.DefaultPort: Word;
begin
  Result := PROTO_RTP_PORT;
end;

class function TWPcapProtocolRTP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_RTP
end;

class function TWPcapProtocolRTP.ProtoName: String;
begin
  Result := 'Real-time Transport Protocol';
end;

class function TWPcapProtocolRTP.AcronymName: String;
begin
  Result := 'RTP';
end;

class function TWPcapProtocolRTP.HeaderLength(aFlag:Byte): word; 
begin
  Result:= SizeOf(TRTPHeader)
end;

class function TWPcapProtocolRTP.Header(const aUDPPayLoad: PByte): PTRTPHeader;
begin
  Result := PTRTPHeader(aUDPPayLoad);
end;

class function TWPcapProtocolRTP.HeaderToString(const aPacketData: PByte;aPacketSize: Integer; AListDetail: TListHeaderString): Boolean;
var LInternalHeader : PTRTPHeaderInternal;
    LHeaderRTP      : PTRTPHeader;
    LUDPPayLoad     : PByte;
    LPUDPHdr        : PUDPHdr;
    LPayLoad        : PByte;
    LSizePayLoad    : integer;
    I               : Integer;
begin
  Result := False;

  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LUDPPayLoad     := GetUDPPayLoad(aPacketData,aPacketSize);
  LHeaderRTP      := Header(LUDPPayLoad);    
  LInternalHeader := GetInternalStructure(aPacketData,aPacketSize);

  if not Assigned(LInternalHeader) then Exit;
  Try
    LPayLoad := GetPayLoadRTP(aPacketData,aPacketSize,LSizePayLoad);
    Try
      AListDetail.Add(AddHeaderInfo(0, Format('%s (%s)', [ProtoName, AcronymName]), null, PByte(LHeaderRTP), SizeOf(TRTPHeader)));
      AListDetail.Add(AddHeaderInfo(1, 'Version:',LInternalHeader.Version , @LHeaderRTP.Version_Padding_Extension_CC, SizeOf(LHeaderRTP.Version_Padding_Extension_CC)));
      AListDetail.Add(AddHeaderInfo(1, 'Padding:',LInternalHeader.Padding, @LHeaderRTP.Version_Padding_Extension_CC, SizeOf(LHeaderRTP.Version_Padding_Extension_CC)));
      AListDetail.Add(AddHeaderInfo(1, 'Extension:', LInternalHeader.Extension, @LHeaderRTP.Version_Padding_Extension_CC, SizeOf(LHeaderRTP.Version_Padding_Extension_CC)));
      AListDetail.Add(AddHeaderInfo(1, 'CSRC Count:',LInternalHeader.CountCSRC, @LHeaderRTP.Version_Padding_Extension_CC, SizeOf(LHeaderRTP.Version_Padding_Extension_CC)));
      AListDetail.Add(AddHeaderInfo(1, 'Marker:',LInternalHeader.Marker , @LHeaderRTP.Marker_PT, SizeOf(LHeaderRTP.Marker_PT)));
      AListDetail.Add(AddHeaderInfo(1, 'Payload Type:', GetRTPPayloadTypeString(LInternalHeader.PayloadType), @LHeaderRTP.Marker_PT, SizeOf(LHeaderRTP.Marker_PT)));
      AListDetail.Add(AddHeaderInfo(1, 'Sequence Number:', LInternalHeader.SequenceNumber, @LHeaderRTP.SequenceNumber, SizeOf(LHeaderRTP.SequenceNumber)));
      AListDetail.Add(AddHeaderInfo(1, 'Timestamp:',LInternalHeader.Timestamp , @LHeaderRTP.timestamp, SizeOf(LHeaderRTP.timestamp)));
      AListDetail.Add(AddHeaderInfo(1, 'SSRC:', LInternalHeader.ssrc, @LHeaderRTP.ssrc, SizeOf(LHeaderRTP.ssrc)));
      AListDetail.Add(AddHeaderInfo(1, 'payload',SizeToStr( LSizePayLoad),LPayLoad,  LSizePayLoad));

      for I := Low(LInternalHeader.CSRC) to High(LInternalHeader.CSRC) do
          AListDetail.Add(AddHeaderInfo(1, 'CSRC:', LInternalHeader.CSRC[I], @LInternalHeader.CSRC[I], SizeOf(Cardinal)));
      
      Result := True;
    Finally
      FreeMem(LPayLoad);
    End;
  Finally
    Dispose(LInternalHeader)
  End;  
end;

Class function TWPcapProtocolRTP.GetRTPPayloadTypeString(APayloadType: Byte): string;
const
  RTPPayloadTypes: array[0..82] of string = ('PCMU (G.711 μ-law)', 'reserved (formerly 1016)', 'reserved (formerly 1017)', 'GSM', 'G723', 'DVI4', 'DVI4', 'LPC', 'PCMA (G.711 A-law)',
    'G722', 'L16 (uncompressed)', 'L16 (uncompressed)', 'QCELP', 'CN (uncompressed)', 'MPA', 'G728', 'DVI4', 'DVI4', 'G729', 'reserved (TSB)', 'reserved (IANA)', 'reserved (IANA)', 
    'unassigned', 'CelB (not IANA assigned)', 'JPEG (not IANA assigned)', 'unassigned', 'nv', 'unassigned', 'H261', 'MPV', 'MP2T', 'H263', 'unassigned', 'unassigned', 'H263-1998', 
    'reserved (Cisco)', 'reserved (Cisco)', 'reserved (Cisco)', 'reserved (Cisco)', 'reserved (Cisco)', 'reserved (Cisco)', 'reserved (Cisco)', 'reserved (Cisco)', 'reserved (Cisco)',
    'reserved (Cisco)', 'reserved (Cisco)', 'reserved (Cisco)', 'reserved (Cisco)', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 
    'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned',
    'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned',
    'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned', 'unassigned');
begin
  if APayloadType <= High(RTPPayloadTypes) then
    Result := RTPPayloadTypes[APayloadType]
  else if APayloadType > 127 then
    Result := 'Dynamic'
  else     
    Result := 'unknown';
    
  Result := Format('%s [%d]',[Result,APayloadType])    
end;


Class function TWPcapProtocolRTP.GetPayLoadRTP(const aPacketData: PByte;aPacketSize:Integer;var aSize:Integer):PByte;
var LInternalHeader : PTRTPHeaderInternal;
    LUDPPayLoad     : PByte;
    LPUDPHdr        : PUDPHdr;    
begin
  Result          := nil;
  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;  
  LInternalHeader := GetInternalStructure(aPacketData,aPacketSize);

  if not Assigned(LInternalHeader) then Exit;

  LUDPPayLoad  := GetUDPPayLoad(aPacketData,aPacketSize);
  Try
    if LInternalHeader.Padding then
    begin
    
    end
    else
    begin
      if LInternalHeader.CountCSRC > 0 then
      begin

        aSize  := UDPPayLoadLength(LPUDPHdr)- HeaderLength(0) - (LInternalHeader.CountCSRC*SizeOf(cardinal))-8;
        if aSize > 0 then
        begin
          Result := AllocMem(aSize);
          Move(LUDPPayLoad[HeaderLength(0) + (LInternalHeader.CountCSRC * SizeOf(Cardinal))], Result^, ASize);
        end;

      end
      else
      begin
        aSize  := UDPPayLoadLength(LPUDPHdr)- HeaderLength(0)-8 ;        
        Result := AllocMem(aSize);
        Move(LUDPPayLoad[HeaderLength(0)], Result^, ASize);
      end;
    end;
    
  Finally
    Dispose(LInternalHeader)
  End;  
end;

Class function TWPcapProtocolRTP.GetSoxCommandDecode(const aPacketData:PByte;aPacketSize:Integer):String;
  //sox -t raw -r 8000 -c 1 -e a-law RTP.raw RTP.wav
var LInternalHeader : PTRTPHeaderInternal;
    LHeaderRTP      : PTRTPHeader;
    LUDPPayLoad     : PByte;
    LPUDPHdr        : PUDPHdr;
begin
  Result := String.Empty;

  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LUDPPayLoad     := GetUDPPayLoad(aPacketData,aPacketSize);
  LHeaderRTP      := Header(LUDPPayLoad);    
  LInternalHeader := GetInternalStructure(aPacketData,aPacketSize);

  if not Assigned(LInternalHeader) then Exit;
  Try  
    case LInternalHeader.PayloadType of
       8 : Result :=  'sox -t raw -r 8000 -c 1 -e a-law %s %s'
    end;
  
  Finally
    Dispose(LInternalHeader);
  End;
end;

Class Function TWPcapProtocolRTP.GetInternalStructure(const aPacketData: PByte;aPacketSize:Integer):PTRTPHeaderInternal;
var LHeaderRTP   : PTRTPHeader;
    LUDPPayLoad  : PByte;
    LPUDPHdr     : PUDPHdr;
    I            : Integer;
begin
  Result := nil;
  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LUDPPayLoad  := GetUDPPayLoad(aPacketData,aPacketSize);
  LHeaderRTP   := Header(LUDPPayLoad);
  New(Result);

  Result.Version        := (LHeaderRTP.Version_Padding_Extension_CC shr 6);
  Result.Padding        := GetBitValue(LHeaderRTP.Version_Padding_Extension_CC,3) = 1;
  Result.Extension      := GetBitValue(LHeaderRTP.Version_Padding_Extension_CC,4) = 1;  
  Result.CountCSRC      := GetLastNBit(LHeaderRTP.Version_Padding_Extension_CC,4);    
  Result.Marker         := GetBitValue(LHeaderRTP.Marker_PT,1)=1;
  Result.PayloadType    := GetLastNBit(LHeaderRTP.Marker_PT,7);
  Result.SequenceNumber := wpcapntohs(LHeaderRTP.SequenceNumber);
  Result.Timestamp      := wpcapntohl(LHeaderRTP.timestamp);
  Result.SSRC           := wpcapntohl(LHeaderRTP.SSRC);

  SetLength(Result.CSRC,Result.CountCSRC );
  for I := 0 to Result.CountCSRC -1 do
    Result.CSRC[i] := wpcapntohl(PCardinal(LUDPPayLoad + HeaderLength(0) + (I*SizeOf(Cardinal)))^);        
end;

class function TWPcapProtocolRTP.IsValid(const aPacket: PByte;aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var LInternalHeader : PTRTPHeaderInternal;
    LPayLoad        : PByte;
    LSizePayLoad    : Integer;
begin
  Result := False;

  LInternalHeader := GetInternalStructure(aPacket,aPacketSize);

  if not Assigned(LInternalHeader) then Exit;
  Try
    if (LInternalHeader.Version <> 2) then exit;
    
    LPayLoad := GetPayLoadRTP(aPacket,aPacketSize,LSizePayLoad);
    Try
      Result := ( LSizePayLoad > 100);
    Finally
      FreeMem(LPayLoad);
    End;
      

    if Result then
    begin
      aAcronymName     := AcronymName;
      aIdProtoDetected := IDDetectProto
    end;
  Finally
    Dispose(LInternalHeader);
  End;
end;

end.
                                                 
