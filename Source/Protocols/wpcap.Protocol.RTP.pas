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
    Version_Padding_Extension_CC  : Uint8; // Versione, Padding, Extension, Count CSRC
    Marker_PT                     : Uint8; // Marker, Payload Type
    SequenceNumber                : Uint16;
    Timestamp                     : Uint32;
    SSRC                          : Uint32;
  end;
  PTRTPHeader = ^TRTPHeader;

  TRTPHeaderInternal = packed record
    Version                       : Uint8;
    Padding                       : Boolean;
    Extension                     : Boolean;
    COuntCSRC                     : Uint8; 
    Marker                        : Boolean;
    PayloadType                   : Uint8; 
    SequenceNumber                : Uint16;
    Timestamp                     : Uint32;
    SSRC                          : Uint32;
    CSRC                          : TArray<Uint32>;
  end;
  PTRTPHeaderInternal = ^TRTPHeaderInternal;
  
  /// <summary>
  /// The RTP protocol implementation class.
  /// </summary>
  TWPcapProtocolRTP = Class(TWPcapProtocolBaseUDP)
  private
    CONST
      PT_PCMU        = 0;       //* RFC 1890 */
      PT_1016        = 1;       //* RFC 1890 */
      PT_G721        = 2;       //* RFC 1890 */
      PT_GSM         = 3;       //* RFC 1890 */
      PT_G723        = 4;       //* From Vineet Kumar of Intel; see the Web page */
      PT_DVI4_8000   = 5;       //* RFC 1890 */
      PT_DVI4_16000  = 6;       //* RFC 1890 */
      PT_LPC         = 7;       //* RFC 1890 */
      PT_PCMA        = 8;       //* RFC 1890 */
      PT_G722        = 9;       //* RFC 1890 */
      PT_L16_STEREO  = 10;      //* RFC 1890 */
      PT_L16_MONO    = 11;      //* RFC 1890 */
      PT_QCELP       = 12;      //* Qualcomm Code Excited Linear Predictive coding? */
      PT_CN          = 13;      //* RFC 3389 */
      PT_MPA         = 14;      //* RFC 1890, RFC 2250 */
      PT_G728        = 15;      //* RFC 1890 */
      PT_DVI4_11025  = 16;      //* from Joseph Di Pol of Sun; see the Web page */
      PT_DVI4_22050  = 17;      //* from Joseph Di Pol of Sun; see the Web page */
      PT_G729        = 18;      //
      PT_CN_OLD      = 19;      //* Payload type reserved (old version Comfort Noise) */
      PT_CELB        = 25;      //* RFC 2029 */
      PT_JPEG        = 26;      //* RFC 2435 */
      PT_NV          = 28;      //* RFC 1890 */
      PT_H261        = 31;      //* RFC 2032 */
      PT_MPV         = 32;      //* RFC 2250 */
      PT_MP2T        = 33;      //* RFC 2250 */
      PT_H263        = 34;      //* from Chunrong Zhu of Intel; see the Web page */    
      PT_iLBC        = 99;
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
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean; override;
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

class function TWPcapProtocolRTP.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;
var LInternalHeader : PTRTPHeaderInternal;
    LHeaderRTP      : PTRTPHeader;
    LUDPPayLoad     : PByte;
    LPUDPHdr        : PUDPHdr;
    LPayLoad        : PByte;
    LSizePayLoad    : integer;
    LUDPPayLoadLen  : Integer;
    I               : Integer;
begin
  Result := False;

  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LUDPPayLoad     := GetUDPPayLoad(aPacketData,aPacketSize);
  LHeaderRTP      := Header(LUDPPayLoad);   
  LUDPPayLoadLen  := UDPPayLoadLength(LPUDPHdr)-8;  
  LInternalHeader := GetInternalStructure(aPacketData,aPacketSize);
  FIsFilterMode   := aIsFilterMode;

  if not Assigned(LInternalHeader) then Exit;
  Try
    LPayLoad := GetPayLoadRTP(aPacketData,aPacketSize,LSizePayLoad);
    Try
      AListDetail.Add(AddHeaderInfo(aStartLevel, AcronymName, Format('%s (%s)', [ProtoName, AcronymName]), null, LUDPPayLoad, LUDPPayLoadLen ));
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Version',[AcronymName]), 'Version:',LInternalHeader.Version , @LHeaderRTP.Version_Padding_Extension_CC, SizeOf(LHeaderRTP.Version_Padding_Extension_CC)));
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Padding',[AcronymName]), 'Padding:',LInternalHeader.Padding, @LHeaderRTP.Version_Padding_Extension_CC, SizeOf(LHeaderRTP.Version_Padding_Extension_CC)));
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Extension',[AcronymName]), 'Extension:', LInternalHeader.Extension, @LHeaderRTP.Version_Padding_Extension_CC, SizeOf(LHeaderRTP.Version_Padding_Extension_CC)));
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.CountCSRC',[AcronymName]), 'CSRC Count:',LInternalHeader.CountCSRC, @LHeaderRTP.Version_Padding_Extension_CC, SizeOf(LHeaderRTP.Version_Padding_Extension_CC)));
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Marker',[AcronymName]), 'Marker:',LInternalHeader.Marker , @LHeaderRTP.Marker_PT, SizeOf(LHeaderRTP.Marker_PT)));
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.PayloadType',[AcronymName]), 'Payload Type:', GetRTPPayloadTypeString(LInternalHeader.PayloadType), @LHeaderRTP.Marker_PT, SizeOf(LHeaderRTP.Marker_PT), LInternalHeader.PayloadType ));
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SequenceNumber',[AcronymName]), 'Sequence Number:', LInternalHeader.SequenceNumber, @LHeaderRTP.SequenceNumber, SizeOf(LHeaderRTP.SequenceNumber)));
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Timestamp',[AcronymName]), 'Timestamp:',LInternalHeader.Timestamp , @LHeaderRTP.timestamp, SizeOf(LHeaderRTP.timestamp)));
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SSRC',[AcronymName]), 'SSRC:', LInternalHeader.ssrc, @LHeaderRTP.ssrc, SizeOf(LHeaderRTP.ssrc)));
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.payload',[AcronymName]), 'payload',SizeToStr( LSizePayLoad),LPayLoad,  LSizePayLoad, LSizePayLoad));

      for I := Low(LInternalHeader.CSRC) to High(LInternalHeader.CSRC) do
          AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.CSRC',[AcronymName]), 'CSRC:', LInternalHeader.CSRC[I], @LInternalHeader.CSRC[I], SizeOf(Uint32)));
      
      Result := True;
    Finally
      FreeMem(LPayLoad);
    End;
  Finally
    Dispose(LInternalHeader)
  End;  
end;

Class function TWPcapProtocolRTP.GetRTPPayloadTypeString(APayloadType: Byte): string;
begin

  case APayloadType of
     PT_PCMU        : Result := 'PCMU (G.711 μ-law)';      
     PT_1016        : Result := 'reserved (formerly 1016)';
     PT_G721        : Result := 'G721';
     PT_GSM         : Result := 'GSM';
     PT_G723        : Result := 'G723';
     PT_DVI4_8000   : Result := 'DVI4 8000';
     PT_DVI4_16000  : Result := 'DVI4 16000';
     PT_LPC         : Result := 'LPC';     
     PT_PCMA        : Result := 'PCMA (G.711 A-law)';
     PT_G722        : Result := 'G722 ';
     PT_L16_STEREO  : Result := 'L16 Stereo';
     PT_L16_MONO    : Result := 'L16 Mono';
     PT_QCELP       : Result := 'QCELP';
     PT_CN          : Result := 'CN';
     PT_MPA         : Result := 'MPA';
     PT_G728        : Result := 'G728';
     PT_DVI4_11025  : Result := 'DVI4 11025';
     PT_DVI4_22050  : Result := 'DVI4 22050';
     PT_G729        : Result := 'G729';
     PT_CN_OLD      : Result := 'CN Old';
     20..22         : Result := 'reserved (IANA)';
     23..24         : Result := 'unassigned';
     PT_CELB        : Result := 'CelB';
     PT_JPEG        : Result := 'JPEG';
     27             : Result := 'unassigned';
     PT_NV          : Result := 'NV';
     29..30         : Result := 'unassigned';
     PT_H261        : Result := 'H261';
     PT_MPV         : Result := 'MPV';
     PT_MP2T        : Result := 'MP2T';
     PT_H263        : Result := 'H263';
     PT_iLBC        : Result := 'iLBC';
  else     
    Result := 'unknown';     
  end;
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

        aSize  := UDPPayLoadLength(LPUDPHdr)- HeaderLength(0) - (LInternalHeader.CountCSRC*SizeOf(Uint32))-8;
        if ( aSize > 0 ) and (aSize < aPacketSize) then
        begin
          Result := AllocMem(aSize);
          Move(LUDPPayLoad[HeaderLength(0) + (LInternalHeader.CountCSRC * SizeOf(Uint32))], Result^, ASize);
        end;

      end
      else
      begin
        aSize  := UDPPayLoadLength(LPUDPHdr)- HeaderLength(0)-8 ; 
        if ( aSize > 0 ) and (aSize < aPacketSize) then
        begin
          Result := AllocMem(aSize);
          Move(LUDPPayLoad[HeaderLength(0)], Result^, ASize);
        end;
      end;
    end;
    
  Finally
    Dispose(LInternalHeader)
  End;  
end;

Class function TWPcapProtocolRTP.GetSoxCommandDecode(const aPacketData:PByte;aPacketSize:Integer):String;
  //sox -t raw -r 8000 -c 1 -e a-law RTP.raw RTP.wav
var LInternalHeader : PTRTPHeaderInternal;
    LPUDPHdr        : PUDPHdr;
begin
  Result := String.Empty;

  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LInternalHeader := GetInternalStructure(aPacketData,aPacketSize);

  if not Assigned(LInternalHeader) then Exit;
  Try  
    case LInternalHeader.PayloadType of
       PT_PCMU        : result := '"%ssox.exe" -t raw -r 8000 -c 1 -e u-law %s -b 16 %s';   //PCMA (G.711 u-law)
       PT_1016        :;
       PT_G721        : result := '"%sffmpeg.exe" -f g726 -i %s -ar 8000 %s';
       PT_GSM         : result := '"%ssox.exe" -t gsm -r 8000 -c 1 %s -b 16 %s';
       PT_G723        : result := '"%ssox.exe" -t g723 %s -b 16 %s';
       PT_DVI4_8000   : ;//result := '"%ssox.exe" -t raw -r 8000 -b 16 -c 1 -e signed-integer %s %s';
       PT_DVI4_16000  : ;//result := '"%ssox.exe" -t raw -r 16000 -c 1 -e a-law %s -b 16 %s';
       PT_LPC         :;     
       PT_PCMA        : result := '"%ssox.exe" -t raw -r 8000 -c 1 -e a-law %s -b 16 %s';   //PCMA (G.711 a-law)
       PT_G722        : result := '"%sffmpeg.exe" -f g722 -i %s -ar 16000 %s';
       PT_L16_STEREO  : result := '"%ssox.exe" -t s16 -r 44100 -c 2 %s -b 16 %s';
       PT_L16_MONO    : result := '"%ssox.exe" -t s16 -r 44100 -c 1 %s -b 16 %s';
       PT_QCELP       :;
       PT_CN          :;
       PT_MPA         : result := '"%ssox.exe" -t mp3 %s -b 16 %s';
       PT_G728        :;
       PT_DVI4_11025  :;
       PT_DVI4_22050  :;
       PT_G729        : result := '"%sffmpeg.exe" -f g729 -i %s -ar 8000 %s';
       PT_CN_OLD      :;
       PT_CELB        :;
       PT_JPEG        :;
       PT_NV          :;
       PT_H261        : result := '"%sffmpeg.exe" -f h261 -i %s %s';
       PT_MPV         :;
       PT_MP2T        :;
       PT_H263        : result := '"%sffmpeg.exe" -f h263 -i %s %s';
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

  if Result.CountCSRC > 0 then
  begin
    SetLength(Result.CSRC,Result.CountCSRC );
    for I := 0 to Result.CountCSRC -1 do
      Result.CSRC[i] := wpcapntohl(PCardinal(LUDPPayLoad + HeaderLength(0) + (I*SizeOf(Uint32)))^);        
  end;
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
      Result :=  ( LInternalHeader.SequenceNumber > 0) and ( LSizePayLoad > 10) and ( ( LSizePayLoad > 100) or ( (LInternalHeader.PayloadType <= PT_H263) or (LInternalHeader.PayloadType = PT_iLBC)) )  ;
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
                                                 
