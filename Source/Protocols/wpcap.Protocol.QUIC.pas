//*************************************************************
//                        WPCAP FOR DELPHI                    *
//				                                        			      *
//                     Freeware Library                       *
//                       For Delphi 10.4                      *
//                            by                              *
//                     Alessandro Mancini                     *
//				                                        			      *
//*************************************************************
{LICENSE:
THIS SOFTWARE IS PROVIDED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND,
EITHER EXPRESSED OR IMPLIED INCLUDING BUT NOT LIMITED TO THE APPLIED
WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
YOU ASSUME THE ENTIRE RISK AS TO THE ACCURACY AND THE USE OF THE SOFTWARE
AND ALL OTHER RISK ARISING OUT OF THE USE OR PERFORMANCE OF THIS SOFTWARE
AND DOCUMENTATION. PRODUCTIONS DOES NOT WARRANT THAT THE SOFTWARE IS ERROR-FREE
OR WILL OPERATE WITHOUT INTERRUPTION. THE SOFTWARE IS NOT DESIGNED, INTENDED
OR LICENSED FOR USE IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE CONTROLS,
INCLUDING WITHOUT LIMITATION, THE DESIGN, CONSTRUCTION, MAINTENANCE OR
OPERATION OF NUCLEAR FACILITIES, AIRCRAFT NAVIGATION OR COMMUNICATION SYSTEMS,
AIR TRAFFIC CONTROL, AND LIFE SUPPORT OR WEAPONS SYSTEMS. PRODUCTIONS SPECIFICALLY
DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF FITNESS FOR SUCH PURPOSE.

You may use/change/modify the component under 1 conditions:
1. In your application, add credits to "WPCAP FOR DELPHI"
{*******************************************************************************}

unit wpcap.Protocol.QUIC;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,wpcap.StrUtils,
  Wpcap.protocol.UDP, WinApi.Windows,wpcap.BufferUtils,Variants,idGlobal;

type
   {
   https://www.chromium.org/quic/
   https://datatracker.ietf.org/doc/html/rfc8999.
   https://datatracker.ietf.org/doc/html/rfc9000,
   https://datatracker.ietf.org/doc/html/rfc9001,
   https://datatracker.ietf.org/doc/html/rfc9002}
  {
  TQUICHeader = packed record
    Flags: Byte;
    Version: array[0..3] of Byte;            //[Position by version]
    DestConnectionID: array[0..19] of Byte;   //[Optional]
    SrcConnectionID: array[0..19] of Byte;    //[Optional]
    TokenLength: Word;                         //[Optional]
    Length: Word;
    PacketNumber: array[0..3] of Byte;         //[Optional]
  end;  
   }
  
  /// <summary>
  /// The QUIC protocol implementation class.
  /// </summary>
  TWPcapProtocolQUIC = Class(TWPcapProtocolBaseUDP)
  private
    CONST
      Q043 = $34343300;
      Q046 = $34363000;
      Q050 = $51303530;    
  protected
  public
    /// <summary>
    /// Returns the default QUIC port (110).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the QUIC protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the QUIC protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the POP3 protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean; override;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; override;        
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolQUIC }
class function TWPcapProtocolQUIC.DefaultPort: Word;
begin
  Result := PROTO_TLS_PORT;
end;

class function TWPcapProtocolQUIC.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_QUIC
end;

class function TWPcapProtocolQUIC.ProtoName: String;
begin
  Result := 'Quick UDP Internet Connections';
end;

class function TWPcapProtocolQUIC.IsValid(const aPacket: PByte;
  aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
begin
  Result  := inherited IsValid(aPacket,aPacketSize,aAcronymName,aIdProtoDetected);  
end;

class function TWPcapProtocolQUIC.AcronymName: String;
begin
  Result := 'QUIC';
end;

class function TWPcapProtocolQUIC.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;
var LUDPPayLoad      : PByte;
    LUDPPayLoadLen   : Integer;
    LPUDPHdr         : PUDPHdr;
    TtmpByte         : Byte;
    LFirst_byte_bit1 : Boolean;
    LFirst_byte_bit2 : Boolean;
    LFirst_byte_bit3 : Boolean;
    LFirst_byte_bit4 : Boolean;
    LFirst_byte_bit5 : Boolean;
    LFirst_byte_bit6 : Boolean;
    LFirst_byte_bit7 : Boolean;
    LFirst_byte_bit8 : Boolean;    
    LVersion         : LongWord;
    LDestConnectionID: TIdBytes;
    Linitial_salt    : TBytes;    
    LCurrentPos      : Integer;
begin
  Result := False;

  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LUDPPayLoad    := GetUDPPayLoad(aPacketData,aPacketSize);
  LUDPPayLoadLen := UDPPayLoadLength(LPUDPHdr)-8;
  FIsFilterMode  := aIsFilterMode;
  AListDetail.Add(AddHeaderInfo(aStartLevel, AcronymName , Format('%s (%s)', [ProtoName, AcronymName]), null, LUDPPayLoad,LUDPPayLoadLen));
  LCurrentPos      := 0;
  TtmpByte         := ParserUint8Value(LUDPPayLoad,aStartLevel+1,LUDPPayLoadLen,Format('%s.Flags',[AcronymName]), 'Flags:',AListDetail,ByteToBinaryStringInternal,True,LCurrentPos);       
  LFirst_byte_bit1 := GetBitValue(TtmpByte,1)=1;
  LFirst_byte_bit2 := GetBitValue(TtmpByte,2)=1;
  LFirst_byte_bit3 := GetBitValue(TtmpByte,3)=1;
  LFirst_byte_bit4 := GetBitValue(TtmpByte,4)=1;
  LFirst_byte_bit5 := GetBitValue(TtmpByte,5)=1;
  LFirst_byte_bit6 := GetBitValue(TtmpByte,6)=1;
  LFirst_byte_bit7 := GetBitValue(TtmpByte,7)=1;
  LFirst_byte_bit8 := GetBitValue(TtmpByte,8)=1;

  AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.HeaderForm',[AcronymName]), 'Header Form:', LFirst_byte_bit1, @LFirst_byte_bit1,SizeOf(LFirst_byte_bit1), GetBitValue(TtmpByte,1) ));
  AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.FixedBit',[AcronymName]), 'Fixed bit:', LFirst_byte_bit2, @LFirst_byte_bit1,SizeOf(LFirst_byte_bit1), GetBitValue(TtmpByte,2) ));  

  LVersion         := 0; 
  if (LFirst_byte_bit1) then
    Move((LUDPPayLoad + 1)^, LVersion, SizeOf(LVersion))
  else if LFirst_byte_bit5 and not LFirst_byte_bit2 then
  begin
    if not (LFirst_byte_bit8) then      
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.NoVersion',[AcronymName]), 'Packet without version', null, @TtmpByte,SizeOf(TtmpByte)))
    else if (LFirst_byte_bit5) then
      Move((LUDPPayLoad + 9)^, LVersion, SizeOf(LVersion))
    else
      Move((LUDPPayLoad + 5)^, LVersion, SizeOf(LVersion))
  end
  else 
    AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.NoVersion',[AcronymName]), 'Packet without version', null, @TtmpByte,SizeOf(TtmpByte)));

  if LVersion <> 0 then
  begin
    AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Version',[AcronymName]), 'Version:', LongWordToString(LVersion).Trim, @LVersion,SizeOf(LVersion), LVersion ));
    LVersion := wpcapntohl(LVersion);
  end;
    
  {Extracting the Server Connection ID} 
  if (LVersion = Q043) then
  begin
    if (LFirst_byte_bit5) then
    begin
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.DstConnectionId.Len',[AcronymName]), 'Destination Connection ID Length:', 8, nil,0));  
      LCurrentPos := 1;
      ParserGenericBytesValue(LUDPPayLoad,aStartLevel+1,LUDPPayLoadLen,8,Format('%s.DstConnectionId',[AcronymName]), 'Destination Connection ID:',AListDetail,BytesToHex,True,LCurrentPos);            
    end;
  end
  else if (LVersion = Q046) then
  begin
    TtmpByte := PByte(LUDPPayLoad+5)^;
    if (TtmpByte <> $50) then
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.DstConnectionId.Len',[AcronymName]), 'Unexpected connection ID length', null, @TtmpByte,SizeOf(TtmpByte) ,TtmpByte))
    else
    begin      
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.DstConnectionId.Len',[AcronymName]), 'Destination Connection ID Length:', 8, nil,0));   
      LCurrentPos := 6;
      ParserGenericBytesValue(LUDPPayLoad,aStartLevel+1,LUDPPayLoadLen,8,Format('%s.DstConnectionId',[AcronymName]), 'Destination Connection ID:',AListDetail,BytesToHex,True,LCurrentPos);          
    end;
  end
  else
  begin 
    LCurrentPos := 5;
    TtmpByte    := ParserUint8Value(LUDPPayLoad,aStartLevel+1,LUDPPayLoadLen,Format('%s.DstConnectionId.len ',[AcronymName]), 'Destination Connection ID Length:',AListDetail,SizeaUint8ToStr,True,LCurrentPos); 
    ParserGenericBytesValue(LUDPPayLoad,aStartLevel+1,LUDPPayLoadLen,TtmpByte,Format('%s.DstConnectionId',[AcronymName]), 'Destination Connection ID:',AListDetail,BytesToHex,True,LCurrentPos); 
  end;


  {Source ??}

  {Token ??}

  {length ??}


  if LFirst_byte_bit1 then
  begin
    //PacketNumber
  end;
  
  {Extracting the Payload from Initial Packets}

  if (LVersion = Q043) or (LVersion = Q046) then
  begin
    // Skip decryption because initial packet is not encrypted
    if (LVersion = Q043) then
    begin
      if (LFirst_byte_bit3) or (LFirst_byte_bit4) then
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.UnexpectedPktLen',[AcronymName]), 'Unexpected packet number length', null, @TtmpByte,SizeOf(TtmpByte), TtmpByte ))
      else
      begin
        Move((LUDPPayLoad + 6)^, LDestConnectionID[0], TtmpByte);
    //    Lpayload := Copy(packet, 27, Length(packet) - 26);
      end;

    end
    else // version = Q046
    begin
      if (not LFirst_byte_bit7) or (not LFirst_byte_bit8) then
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.UnexpectedPktLen',[AcronymName]), 'Unexpected packet number length', null, @TtmpByte,SizeOf(TtmpByte), TtmpByte ))
      else
      begin
        Move((LUDPPayLoad + 6)^, LDestConnectionID[0], TtmpByte);
       // Lpayload := Copy(packet, 31, Length(packet) - 30);
      end;
    end;
  end
  else
  begin
    if (LFirst_byte_bit3) or (LFirst_byte_bit4) then
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.UnexpectedPktLen',[AcronymName]), 'Unexpected packet number length', null, @TtmpByte,SizeOf(TtmpByte), TtmpByte ))      
    else if (LVersion = Q050) then
      Linitial_salt := TBytes.Create($50, $45, $74, $ef, $d0, $66, $fe, $2f, $9d, $94, $5c, $fc, $db, $d3, $a7, $f0, $d3, $b5, $6b, $45)
    else if (LVersion = $ff00001d) then
      Linitial_salt := TBytes.Create($af, $bf, $ec, $28, $99, $93, $d2, $4c, $9e, $97, $86, $f1, $9c, $61, $11, $e0, $43, $90, $a8, $99)
    else if (LVersion = $00000001) then
      Linitial_salt := TBytes.Create($38, $76, $2c, $f7, $f5, $59, $34, $b3, $4d, $17, $9a, $e6, $a4, $c8, $0c, $ad, $cc, $bb, $7f, $0a)
    else
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.UnknownVersion',[AcronymName]), 'Unknown version', null, @TtmpByte,SizeOf(TtmpByte)))    
  end;

  //Lpayload = Decrypt(LUDPPayLoad, Linitial_salt){https://datatracker.ietf.org/doc/html/rfc9001#section-5}

  {https://docs.google.com/document/d/1GV2j-PGl7YGFqmWbYvzu7-UNVIpFdbprtmN9tt6USG8/preview#heading=h.c67iuuphij3v}
  {Extracting Crypto Data from the Payload}

     {Extracting the Client Hello from the Crypto Data}  {https://www.rfc-editor.org/rfc/rfc8446}
    
  {PADDING ??}

  SetLength(Linitial_salt,0);
  Result := True;
end;


end.
                                                 
