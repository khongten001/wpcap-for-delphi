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
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,wpcap.StrUtils,wpcap.packet,
  Wpcap.protocol.UDP, WinApi.Windows,wpcap.BufferUtils,Variants,idGlobal,System.Math;

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
    Version: array[0..3] of Byte;             //[Position by version]
    DestConnectionID: array[0..19] of Byte;   //[Optional]
    SrcConnectionID: array[0..19] of Byte;    //[Optional]
    TokenLength: Word;                        //[Optional]
    Length: Word;                             //[Optional]
    PacketNumber: array[0..3] of Byte;        //[Optional]
  end;  
   }
  
  /// <summary>
  /// The QUIC protocol implementation class.
  /// </summary>
  TWPcapProtocolQUIC = Class(TWPcapProtocolBaseUDP)
  private
    CONST
      V_1         = $01000000;   // big endian representation of 0x00000001
      V_Q024      = $34323051;   // big endian representation of 0x51303234
      V_Q025      = $35323051;   // big endian representation of 0x51303235
      V_Q030      = $30333051;   // big endian representation of 0x51303330
      V_Q033      = $33333051;   // big endian representation of 0x51303333
      V_Q034      = $34333051;   // big endian representation of 0x51303334
      V_Q035      = $35333051;   // big endian representation of 0x51303335
      V_Q037      = $37333051;   // big endian representation of 0x51303337
      V_Q039      = $39333051;   // big endian representation of 0x51303339
      V_Q043      = $33343051;   // big endian representation of 0x51303433
      V_Q046      = $36343051;   // big endian representation of 0x51303436
      V_Q050      = $30353051;   // big endian representation of 0x51303530
      V_T050      = $30353054;   // big endian representation of 0x54303530
      V_T051      = $31353054;   // big endian representation of 0x54303531
      V_MVFST_22  = $b0b0cefa;   // big endian representation of 0xfaceb001
      V_MVFST_27  = $b002b0cefa; // big endian representation of 0xfaceb002
      V_MVFST_EXP = $e00b0cefa;  // big endian representation of 0xfaceb00e

      QUIC_LPT_INITIAL   = 0;
      QUIC_LPT_0RTT      = 1;
      QUIC_LPT_HANDSHAKE = 2;
      QUIC_LPT_RETRY     = 3; 
      QUIC_SHORT_PACKET  = 4;    
    class function IsValidVersion(aVersion: UInt32): Boolean; static;
    class function IsValidVersionGQUIC(aVersion: UInt32): Boolean; static;
    class function IsValidVersionQUIC(aVersion: UInt32): Boolean; static;
    class function GetDecimalQUICVersion(version: UInt32): Byte; static;
    class function IsQuicValidByMax(aVersion: UInt32;
      aMaxVersion: Uint8): Boolean; static;
    class function GetLogPacketType(aFirst_byte: Uint8; aVersion: UInt32): Byte; static;
    class function LogPacketTypeToString(const aLogPacketType: Byte): String; static;
    class function VersionToString(const aVersion: Uint32): String; static;
    class function AjustPacketNUmber(aMaxPktNum, aPktNum: UInt64;
      n: UInt64 ): UInt64; static;
    class function GetMaxPacketNumber(aLongType: Byte;
      aFirstByte: Uint8): Uint64; static;  // big endian representation of 0xfaceb00e
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
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean; override;
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

class function TWPcapProtocolQUIC.IsValidVersionGQUIC(aVersion: UInt32): Boolean;
begin
  Result := ((aVersion and $FFFFFF00) = $00353000) { T05X } or
  ((aVersion and $FFFFFF00) = $00353051) { Q05X } or
  ((aVersion and $FFFFFF00) = $00343051) { Q04X } or
  ((aVersion and $FFFFFF00) = $00333051) { Q03X } or
  ((aVersion and $FFFFFF00) = $00323051);{ Q02X }
end;

class function TWPcapProtocolQUIC.IsValidVersionQUIC(aVersion: UInt32): Boolean;
begin
    Result := (aVersion = V_1) or
    ((aVersion and $FFFFFF00) = $FF000000) or { IETF Drafts }
    ((aVersion and $FFFFF000) = $FACEB000) or { Facebook }
    ((aVersion and $0F0F0F0F) = $0A0A0A0A) or { Forcing Version Negotiation }
    (aVersion = $C4509A70);                   { V2 IETF Drafts }
end;

class function TWPcapProtocolQUIC.IsValidVersion(aVersion: UInt32): Boolean;
begin
  Result := IsValidVersionGQUIC(aVersion) or IsValidVersionQUIC(aVersion);
end;

class function TWPcapProtocolQUIC.GetDecimalQUICVersion(version: UInt32): Byte;
begin 
  if (version shr 8) = $FF0000 then
    Exit(Byte(version));
  if version = $00000001 then
    Exit(34);
  if version = V_MVFST_22 then
    Exit(22);
  if (version = V_MVFST_27) or (version = V_MVFST_EXP) then
    Exit(27);
  if (version and $0F0F0F0F) = $0A0A0A0A then
    Exit(29);
    
  { QUIC Version 2 }
  if version = $709A50C4 then
    Exit(100);
  Result := 0;
end;

class function TWPcapProtocolQUIC.IsQuicValidByMax(aVersion: UInt32; aMaxVersion: Uint8): Boolean;
var LUint8Value: Uint8;
begin
  LUint8Value := GetDecimalQUICVersion(aVersion);
  Result      := (LUint8Value <> 0) and (LUint8Value <= aMaxVersion);
end;

class function TWPcapProtocolQUIC.LogPacketTypeToString(const aLogPacketType:Byte):String;
begin
  case aLogPacketType of
      QUIC_LPT_INITIAL   : Result := 'Initial record';
      QUIC_LPT_0RTT      : Result := '0 - RTT';
      QUIC_LPT_HANDSHAKE : Result := 'Handshake';
      QUIC_LPT_RETRY     : Result := 'Retry'; 
      QUIC_SHORT_PACKET  : Result := 'Short packet'; 
  else
    Result := Format('Unknown %d',[aLogPacketType])
  end;
end;

Class function TWPcapProtocolQUIC.VersionToString(const aVersion : Uint32):String;
begin
  case aVersion of  
      V_1         : Result := '1';        
      V_Q024      : Result := 'Q024';
      V_Q025      : Result := 'Q025';     
      V_Q030      : Result := 'Q030';     
      V_Q033      : Result := 'Q033';     
      V_Q034      : Result := 'Q034';     
      V_Q035      : Result := 'Q035';     
      V_Q037      : Result := 'Q037';     
      V_Q039      : Result := 'Q039';     
      V_Q043      : Result := 'Q043';     
      V_Q046      : Result := 'Q046';     
      V_Q050      : Result := 'Google Q050';     
      V_T050      : Result := 'Google T050';     
      V_T051      : Result := 'Google T051';     
      V_MVFST_22  : Result := 'Facebook MVFST_22'; 
      V_MVFST_27  : Result := 'Facebook MVFST_27'; 
      V_MVFST_EXP : Result := 'Facebook MVFST_EXP'; 
  else
    Result := Format('Unknown %d',[aVersion])  
  end;
end;

class function TWPcapProtocolQUIC.GetLogPacketType(aFirst_byte: Uint8; aVersion: UInt32): Byte;
begin
  // Up to V1
  if not (aVersion = $709A50C4) then
  begin
    if (aFirst_byte and $30) shr 4 = 0 then
      Result := QUIC_LPT_INITIAL
    else if (aFirst_byte and $30) shr 4 = 1 then
      Result := QUIC_LPT_0RTT
    else if (aFirst_byte and $30) shr 4 = 2 then
      Result := QUIC_LPT_HANDSHAKE
    else
      Result := QUIC_LPT_RETRY;
  end
  else // From V2
  begin
    if (aFirst_byte and $30) shr 4 = 0 then
      Result := QUIC_LPT_RETRY
    else if (aFirst_byte and $30) shr 4 = 1 then
      Result := QUIC_LPT_INITIAL
    else if (aFirst_byte and $30) shr 4 = 2 then
      Result := QUIC_LPT_0RTT
    else
      Result := QUIC_LPT_HANDSHAKE;
  end;
end;

class function TWPcapProtocolQUIC.GetMaxPacketNumber(aLongType:Byte;aFirstByte: Uint8): Uint64;
var pkn_space: Integer;
begin
  if ((aFirstByte and $80) <> 0) and (aLongType = QUIC_LPT_INITIAL) then
    pkn_space := 0
  else if ((aFirstByte and $80) <> 0) and (aLongType = QUIC_LPT_HANDSHAKE) then
    pkn_space := 1
  else
    pkn_space := 2;
  Result :=  pkn_space;
end;

{By wireshark}
class function TWPcapProtocolQUIC.AjustPacketNUmber(aMaxPktNum, aPktNum: UInt64; n: UInt64 ): UInt64;
var k, u, a, b, a1, b1: UInt64;
begin
  k := aMaxPktNum;
  if k = G_MAXUINT64 then
    k := aMaxPktNum
  else
    k := aMaxPktNum + 1;

  u  := k and not((UInt64(1) shl n) - 1);
  a  := u or aPktNum;
  b  := (u + (UInt64(1) shl n)) or aPktNum;
  a1 := IfThen(k < a, a - k, k - a);
  b1 := IfThen(k < b, b - k, k - b);

  if a1 < b1 then
    Result := a
  else
    Result := b;
end;

class function TWPcapProtocolQUIC.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean;
var LUDPPayLoad      : PByte;
    LUDPPayLoadLen   : Integer;
    LDummy           : Integer;
    TtmpByte         : Byte;
    LIsLogHeader     : Boolean;
    LFixedBit        : Boolean;
    LSpinBit         : Boolean;
    LFirst_byte_bit4 : Boolean;
    LFirst_byte_bit5 : Boolean;
    LFirst_byte_bit6 : Boolean;
    LFirst_byte_bit7 : Boolean;
    LFirst_byte_bit8 : Boolean;    
    LVersion         : Uint32;
    LDestConnectionID: TIdBytes;
    LUint8           : Uint8;
    Linitial_salt    : TBytes;    
    LCurrentPos      : Integer;
    LLongType        : Byte;
    LFirstByte       : Uint8;
    LVersionStr      : String;
    LLongTypeStr     : String;
    LInfo            : String;
    LTmpValue        : String;
    LPacketNumberSize: Uint8;

    Procedure SetPacketType(aType:Byte);
    begin
      LLongType     := aType;
      LLongTypeStr  := LogPacketTypeToString(LLongType);
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.PacketType',[AcronymName]), 'Packet type:', LLongTypeStr, @LLongType,SizeOf(LLongType),LLongType ));      
    end;

    Procedure VersionForQUIC_SHORT_VALUE(aOffset:Byte);
    begin
      SetPacketType(QUIC_SHORT_PACKET);
      if not (LFirst_byte_bit8) then  
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.NoVersion',[AcronymName]), 'Packet without version', null, @LFirstByte,SizeOf(LFirstByte)))
      else
        Move((LUDPPayLoad + aOffset)^, LVersion, SizeOf(LVersion))          
    end;

    Procedure SrcConnectionId(aOffset,aLen:Integer);
    begin
      LCurrentPos := aOffset;
      LTmpValue   := ParserGenericBytesValue(LUDPPayLoad,aStartLevel+1,LUDPPayLoadLen,aLen,Format('%s.SrcConnectionId',[AcronymName]), 'Source Connection ID:',AListDetail,BytesToHex,True,LCurrentPos);
      if not LTmpValue.Trim.IsEmpty then
        LInfo := Format('%S SCID %s',[LInfo,LTmpValue])    
    end;

    Procedure DstConnectionId(aOffset,aLen:Integer);
    begin
      LCurrentPos := aOffset;
      LTmpValue := ParserGenericBytesValue(LUDPPayLoad,aStartLevel+1,LUDPPayLoadLen,aLen,Format('%s.DstConnectionId',[AcronymName]), 'Destination Connection ID:',AListDetail,BytesToHex,True,LCurrentPos);            
      if not LTmpValue.Trim.IsEmpty then
        LInfo := Format('%S DCID %s',[LInfo,LTmpValue])    
    end;    
    
begin
  Result         := False;
  LUDPPayLoad    := inherited GetPayLoad(aPacketData,aPacketSize,LUDPPayLoadLen,LDummy);    

  if not Assigned(LUDPPayLoad) then
  begin
    FisMalformed := true;
    Exit;
  end;  
  
  FIsFilterMode  := aIsFilterMode;
  AListDetail.Add(AddHeaderInfo(aStartLevel, AcronymName , Format('%s (%s)', [ProtoName, AcronymName]), null, LUDPPayLoad,LUDPPayLoadLen));
  LCurrentPos      := 0;
  LFirstByte       := ParserUint8Value(LUDPPayLoad,aStartLevel+1,LUDPPayLoadLen,Format('%s.Flags',[AcronymName]), 'Flags:',AListDetail,ByteToBinaryStringInternal,True,LCurrentPos);       

  LIsLogHeader       := GetBitValue(LFirstByte,1)=1;
  LFixedBit          := GetBitValue(LFirstByte,2)=1;
  LSpinBit           := GetBitValue(LFirstByte,3)=1;
  LFirst_byte_bit4   := GetBitValue(LFirstByte,4)=1;
  LFirst_byte_bit5   := GetBitValue(LFirstByte,5)=1;
  LFirst_byte_bit6   := GetBitValue(LFirstByte,6)=1;
  LFirst_byte_bit7   := GetBitValue(LFirstByte,7)=1;
  LFirst_byte_bit8   := GetBitValue(LFirstByte,8)=1;
  LVersion           := 0; 

  AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.HeaderForm',[AcronymName]), 'Header Form:', LIsLogHeader, @LIsLogHeader,SizeOf(LIsLogHeader), GetBitValue(LFirstByte,1) ));
  AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.FixedBit',[AcronymName]), 'Fixed bit:', LFixedBit, @LFixedBit,SizeOf(LFixedBit), GetBitValue(LFirstByte,2) ));  
  
  // If the first bit of the flags byte is set, then the version number is present in the next four bytes.
  if LIsLogHeader then
  begin
    Move(LUDPPayLoad[1], LVersion, SizeOf(LVersion)) ;
    SetPacketType(GetLogPacketType(LFirstByte,LVersion))
  end 
  else if LFirst_byte_bit5 and not LFixedBit then  // If the fifth bit is set but the second bit is not, then the version number is present in the 5th-8th bytes.
    VersionForQUIC_SHORT_VALUE(5)
  else if LFirst_byte_bit5 and LFixedBit then   // If the fifth and second bits are both set, then the version number is present in the 9th-12th bytes
    VersionForQUIC_SHORT_VALUE(9)
  else 
    SetPacketType(QUIC_SHORT_PACKET);     
  
  if LIsLogHeader then
  begin
    if LLongType = QUIC_LPT_INITIAL then
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.PacketNumberLen',[AcronymName]), 'Packet number len:', LPacketNumberSize, @LPacketNumberSize,SizeOf(LPacketNumberSize) ));      
  

    LVersionStr  := VersionToString(LVersion);
    LInfo        := Format( 'QUIC V %s %s',[LVersionStr,LLongTypeStr]);
    AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Version',[AcronymName]), 'Version:', LVersionStr, @LVersion,SizeOf(LVersion), wpcapntohl(LVersion) )); 
  
    {Extracting the Server Connection ID and Source Connection ID} 
    if (LVersion = V_Q043) then
    begin
      if (LFirst_byte_bit5) then
      begin
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.DstConnectionId.Len',[AcronymName]), 'Destination Connection ID Length:', 8, nil,0));  
        DstConnectionId(1,8)        
      end;      
      if (LFirst_byte_bit6) then
      begin
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SrcConnectionId.Len',[AcronymName]), 'Source Connection ID Length:', 8, nil,0));  
        SrcConnectionId(2,8);
      end;
    end
    else if (LVersion = V_Q046) then
    begin
      TtmpByte := PByte(LUDPPayLoad+5)^;
      if (TtmpByte <> $50) then
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.DstConnectionId.Len',[AcronymName]), 'Unexpected connection ID length', null, @TtmpByte,SizeOf(TtmpByte) ,TtmpByte))
      else
      begin      
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.DstConnectionId.Len',[AcronymName]), 'Destination Connection ID Length:', 8, nil,0));   
        DstConnectionId(6,8);
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SrcConnectionId.Len',[AcronymName]), 'Source Connection ID Length:', 8, nil,0));
        SrcConnectionId(LCurrentPos,8);                    
      end;
    end
    else
    begin 
      LCurrentPos := 5;
      TtmpByte    := ParserUint8Value(LUDPPayLoad,aStartLevel+1,LUDPPayLoadLen,Format('%s.DstConnectionId.len ',[AcronymName]), 'Destination Connection ID Length:',AListDetail,SizeaUint8ToStr,True,LCurrentPos); 
      DstConnectionId(LCurrentPos,TtmpByte);
      TtmpByte  := ParserUint8Value(LUDPPayLoad,aStartLevel+1,LUDPPayLoadLen,Format('%s.SrcConnectionId.len',[AcronymName]), 'Source Connection ID Length:',AListDetail,SizeaUint8ToStr,True,LCurrentPos);
      SrcConnectionId(LCurrentPos,TtmpByte)              
    end;
  
    {Extracting the Token Length and Token}
    if LLongType = QUIC_LPT_INITIAL then
    begin
      LUint8 := ParserUint8Value(LUDPPayLoad,aStartLevel+1,LUDPPayLoadLen,Format('%s.TokenLength',[AcronymName]), 'Token Length:',AListDetail,SizeaUint8ToStr,True,LCurrentPos);
      ParserGenericBytesValue(LUDPPayLoad,aStartLevel+1,LUDPPayLoadLen,LUint8,Format('%s.Token',[AcronymName]), 'Token:',AListDetail,BytesToHex,True,LCurrentPos);
    end;

    {Extracting the Length field}
    ParserUint12Value(LUDPPayLoad,aStartLevel+1,LUDPPayLoadLen,Format('%s.Length',[AcronymName]), 'Length:',AListDetail,SizeWordToStr,True,LCurrentPos);

    {TODO Extracting the Packet Number}
   { if LLongType = QUIC_LPT_INITIAL then
    begin
      case LPacketNumberSize of
        1 : ParserUint8Value(LUDPPayLoad,aStartLevel+1,LUDPPayLoadLen,Format('%s.PacketNumber',[AcronymName]), 'Packet Number:',AListDetail,nil,True,LCurrentPos);
        2 : ParserUint16Value(LUDPPayLoad,aStartLevel+1,LUDPPayLoadLen,Format('%s.PacketNumber',[AcronymName]), 'Packet Number:',AListDetail,nil,True,LCurrentPos);
      end;
    end;
    }

    {TODO Extracting the Payload from Initial Packets}
    (*
    if (LVersion = V_Q043) or (LVersion = V_Q046) then
    begin
      // Skip decryption because initial packet is not encrypted
      if (LVersion = V_Q043) then
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
      else if (LVersion = V_Q050) then
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
    SetLength(Linitial_salt,0); *)
  end
  else
  begin
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.SpinBit',[AcronymName]), 'Spin bit:', LSpinBit, @LSpinBit,SizeOf(LSpinBit), GetBitValue(TtmpByte,3) ));  
    LInfo := LLongTypeStr
  end;
  aAdditionalParameters.Info := Format('%s %s',[LInfo,aAdditionalParameters.Info]).Trim;
  Result := True;
end;


end.
                                                 
