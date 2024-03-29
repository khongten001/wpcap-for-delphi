﻿//*************************************************************
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

unit wpcap.Protocol.Base;

interface

uses
  System.SysUtils, WinSock, System.Types, wpcap.Level.Eth, wpcap.StrUtils,idGlobal,wpcap.Packet,
  System.Variants,wpcap.Types,wpcap.BufferUtils,System.Classes,wpcap.IpUtils,Winapi.Windows;

Type
  /// <summary>
  /// Base class for all protocols in a packet capture. 
  /// This class defines the base behavior that each protocol should implement.
  /// </summary>
  TWPcapProtocolBase = class(TWpcapEthHeader)
  private
     class var FOnFoundMalformedPacket : TNotifyEvent;   
  protected
     
    /// <summary>
    /// Convert a Uint8 value to a string representing its size.
    /// </summary>
    class function SizeaUint8ToStr(const aUint8: UInt8): string;

    /// <summary>
    ///Convert a Uint32 (cardinal) value to a string representing its size.
    /// </summary>
    class function SizeCardinalToStr(const aCardinal: UInt32): string;

    /// <summary>
    ///Convert a Uint16 (word) value to a string representing its size.
    /// </summary>
    class function SizeWordToStr(const aWord: UInt16): string;
          
    /// <summary>
    /// Convert a byte value to a binary string.
    /// </summary>
    class function ByteToBinaryStringInternal(const AByte: UInt8): string;

    /// <summary>
    /// Convert an array of bytes to a hexadecimal string.  
    /// </summary>
    class function BytesToHex(const ABytes: TidBytes): string;
            
    /// <summary>
    /// Convert a byte value to a String representation of a boolean value.
    /// </summary>
    class function ByteToBooleanStr(const aValue: Uint8): string;

    /// <summary>
    /// Convert an array of bytes to a string without locale
    /// </summary>
    class function BytesToStringRawInternal(const ABytes: TidBytes): string;
     
    /// <summary>
    /// Convert a Uinr32 value to a string representing an IPv4 address.
    /// </summary>
    class function MakeUint32IntoIPv4AddressInternal(const aValue: UInt32): string;    
     
    /// <summary>
    /// Convert an array of bytes representing an IPv6 address to a string representation.
    /// </summary>
    class function IPv6AddressToStringInternal(const ABytes: TidBytes): string;     

    /// <summary>
    /// Check if the specified length is valid within the given actual position and maximum length.
    /// if not valid call event FOnFoundMalformedPacket
    /// </summary>     
    class function isValidLen(const aActualPos, aMaxLen: Integer; aLen: Integer): Boolean; static;

    /// <summary>
    /// Check if the given test port matches either the source or destination port.
    /// </summary>
    class function IsValidByPort(aTestPort, aSrcPort, aDstPort: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; virtual;

    class function ParserUint8Value(const aPacketData:PByte; aLevel:byte; aMaxLen:Integer; const aLabel,aCaption : String; AListDetail: TListHeaderString; aToStringFunction:TWpcapUint8ToString; isBigEndian:Boolean;var aCurrentPos:Integer):Uint8;  
    class function ParserUint12Value(const aPacketData:PByte; aLevel:byte; aMaxLen:Integer; const aLabel,aCaption : String; AListDetail: TListHeaderString; aToStringFunction:TWpcapUint16ToString; isBigEndian:Boolean;var aCurrentPos:Integer):Uint16;     
    class function ParserUint16Value(const aPacketData:PByte; aLevel:byte; aMaxLen:Integer; const aLabel,aCaption : String; AListDetail: TListHeaderString; aToStringFunction:TWpcapUint16ToString; isBigEndian:Boolean;var aCurrentPos:Integer):Uint16;
    class function ParserUint24Value(const aPacketData:PByte; aLevel:byte; aMaxLen:Integer; const aLabel,aCaption : String; AListDetail: TListHeaderString; aToStringFunction:TWpcapUint32ToString; isBigEndian:Boolean;var aCurrentPos:Integer):Uint32;     
    class function ParserUint32Value(const aPacketData:PByte; aLevel:byte; aMaxLen:Integer; const aLabel,aCaption : String; AListDetail: TListHeaderString; aToStringFunction:TWpcapUint32ToString; isBigEndian:Boolean;var aCurrentPos:Integer;isIP:Boolean=False):Uint32;
    class function ParserUint64Value(const aPacketData:PByte; aLevel:byte; aMaxLen:Integer; const aLabel,aCaption : String; AListDetail: TListHeaderString; aToStringFunction:TWpcapUint64ToString; isBigEndian:Boolean;var aCurrentPos:Integer):Uint64;     
    class function ParserGenericBytesValue(const aPacketData: PByte;aLevel: byte; aMaxLen, aLen: Integer; const aLabel, aCaption: String;AListDetail: TListHeaderString; aToStringFunction: TWpcapBytesToString;isBigEndian: Boolean; var aCurrentPos: Integer;isIP:Boolean=False):String;
    class function ParserBytesToInteger(const aPacketData: PByte;aLevel: byte; aMaxLen, aLen: Integer; const aLabel, aCaption: String;AListDetail: TListHeaderString;isBigEndian: Boolean; var aCurrentPos: Integer):Integer;
    class function ParserByEndOfLine(aStartLevel,aPayLoadLen:Integer; aPayLoad: PByte; AListDetail: TListHeaderString;var aStartOffSet: Integer;aAdditionalParameters: PTAdditionalParameters): Boolean;   
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
    class function IDDetectProto: byte; virtual;

    /// <summary>
    /// Returns the length of the protocol header.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function HeaderLength(aFlag:Byte): Word; virtual;

    class function AddHeaderInfo(aLevel:Byte;const aLabel, aDescription:String;aValue:Variant;aPacketInfo:PByte;aPacketInfoSize:Word;aRaWData: Integer=-1 ;aEnrichmentType : TWpcapEnrichmentType=WetNone):THeaderString;static;

    /// <summary>
    /// Checks whether the packet has the default port for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function IsValidByDefaultPort(aSrcPort, aDstPort: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;overload; virtual;
    
    {Event}
    /// <summary>
    /// Gets or sets event for malformed packet.
    /// </summary>    
    class property OnFoundMalformedPacket : TNotifyEvent   read FOnFoundMalformedPacket write FOnFoundMalformedPacket;
   
    Class function GetPayLoad(const aPacketData: PByte;aPacketSize:Integer;var aSize,aSizeTotal:Integer):PByte;virtual;
  end;
  
implementation

{ TWPcapProtocolBase }


class function TWPcapProtocolBase.DetailInfo: String;
begin
  Result := String.Empty;
end;

class function TWPcapProtocolBase.GetPayLoad(const aPacketData: PByte;aPacketSize: Integer; var aSize,aSizeTotal: Integer): PByte;
begin
  raise Exception.Create('TWPcapProtocolBase.GetPayLoad - Non implemented in base class - please override this method');
end;

class function TWPcapProtocolBase.DefaultPort: Word;
begin
  raise Exception.Create('TWPcapProtocolBase.DefaultPort - Non implemented in base class - please override this method');
end;

class function TWPcapProtocolBase.IDDetectProto: byte;
begin
  raise Exception.Create('TWPcapProtocolBase.IDDetectProto- Non implemented in base class - please override this method');
end;

class function TWPcapProtocolBase.HeaderLength(aFlag:byte): word;
begin
  raise Exception.Create('TWPcapProtocolBase.HeaderLength- Non implemented in base class - please override this method');
end;

class function TWPcapProtocolBase.AcronymName: String;
begin
  raise Exception.Create('TWPcapProtocolBase.AcronymName- Non implemented in base class - please override this method');
end;

class function TWPcapProtocolBase.AddHeaderInfo(aLevel:Byte;const aLabel, aDescription:String;aValue:Variant;aPacketInfo:PByte;aPacketInfoSize:Word;aRaWData: Integer=-1 ;aEnrichmentType : TWpcapEnrichmentType=WetNone):THeaderString;
begin    
  
  Result.Description     := aDescription;
  Result.Labelname       := aLabel;
  Result.Value           := aValue;
  Result.Level           := aLevel;
  Result.Size            := aPacketInfoSize;
  if aRaWData <> -1 then  
    Result.RawValue := aRaWData
  else
    Result.RawValue := aValue;
    
  Result.EnrichmentType  := aEnrichmentType;  
  if (aPacketInfo = nil) or FisFilterMode then      
    Result.Hex := String.Empty
  else
    Try
      Result.Hex := String.Join(sLineBreak,DisplayHexData(aPacketInfo,aPacketInfoSize,False)).Trim;
    Except on E: Exception do
      begin
        FisMalformed := true; 
      end;
    End;
end;   

class function TWPcapProtocolBase.IsValidByPort(aTestPort,aSrcPort,aDstPort: Integer;
  var aAcronymName: String; var aIdProtoDetected: Byte): Boolean;
begin
  Result := False;
  if aTestPort = 0 then Exit;
  
   Result := ( aSrcPort = aTestPort ) or ( aDstPort = aTestPort );

   if not Result then exit;

   aAcronymName     := AcronymName;
   aIdProtoDetected := IDDetectProto;   
end;

class function TWPcapProtocolBase.IsValidByDefaultPort(aSrcPort, aDstPort: integer;
  var aAcronymName: String; var aIdProtoDetected: Byte): Boolean;
begin
  Result := IsValidByPort(DefaultPort,aSrcPort,aDstPort,aAcronymName,aIdProtoDetected);
end;

class function TWPcapProtocolBase.ProtoName: String;
begin
  Result := String.Empty;
end;

class Function TWPcapProtocolBase.ParserUint8Value(const aPacketData:PByte;aLevel:byte; aMaxLen:Integer;
        const aLabel,aCaption : String;AListDetail: TListHeaderString;
        aToStringFunction:TWpcapUint8ToString;isBigEndian:Boolean;
        var aCurrentPos:Integer):Uint8;
begin
  Result := 0;
  if not isValidLen(aCurrentPos,aMaxLen,SizeOf(Result)) then Exit;
  
  Result :=  PUint8(aPacketData+aCurrentPos )^;

  if Assigned(AListDetail) then
  begin
    if Assigned(aToStringFunction) then
      AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, aToStringFunction(Result), @Result,sizeOf(Result), Result ))
    else  
      AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, Result, @Result,sizeOf(Result) ));
    Inc(aCurrentPos,SizeOf(Result));
  end;
end;

class function TWPcapProtocolBase.ParserUint12Value(const aPacketData: PByte;
  aLevel: byte; aMaxLen: Integer; const aLabel, aCaption: String;
  AListDetail: TListHeaderString; aToStringFunction: TWpcapUint16ToString;
  isBigEndian: Boolean; var aCurrentPos: Integer): Uint16;
var LBytes  : TIdBytes;
begin
  result := 0;
  if not isValidLen(aCurrentPos,aMaxLen+1,2) then Exit;
  
  SetLength(LBytes,2);
  Move( (aPacketData + aCurrentPos)^,LBytes[0],2);   

  // convert the bytes to a UInt12 value example 44 D0 = 4 D0
  Result := MakeWord(LBytes[0] and $0F,LBytes[1] );
  
  if isBigEndian then  
     Result :=  wpcapntohs(Result);

  if Assigned(aToStringFunction) then
    AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, aToStringFunction(Result), PByte(LBytes),2,Result ))
  else      
    AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, Result, PByte(LBytes),2));
    
  Inc(aCurrentPos,2);
end;

class Function TWPcapProtocolBase.ParserUint16Value(const aPacketData:PByte;aLevel:byte; aMaxLen:Integer;
          const aLabel,aCaption : String;AListDetail: TListHeaderString;
          aToStringFunction:TWpcapUint16ToString;isBigEndian:Boolean;
          var aCurrentPos:Integer):Uint16;
begin
  if not isValidLen(aCurrentPos,aMaxLen+1,SizeOf(Result)) then Exit;
  
  if isBigEndian then
     Result :=  wpcapntohs(PUint16(aPacketData+aCurrentPos )^)
  else
     Result :=  PUint16(aPacketData+aCurrentPos )^;

  if Assigned(aToStringFunction) then
    AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, aToStringFunction(Result), @Result,sizeOf(Result), Result ))   
  else  
    AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, Result, @Result,sizeOf(Result) ));
  Inc(aCurrentPos,SizeOf(Result));
end;

class Function TWPcapProtocolBase.ParserUint32Value(const aPacketData:PByte;aLevel:byte; aMaxLen : Integer;
        const aLabel,aCaption : String;AListDetail: TListHeaderString;
        aToStringFunction:TWpcapUint32ToString;isBigEndian:Boolean;
        var aCurrentPos:Integer;isIP:Boolean=False):Uint32;
var LEnrichment : TWpcapEnrichmentType;
    LTmpValue   : String;
begin
  if not isValidLen(aCurrentPos,aMaxLen+1,SizeOf(Result)) then Exit;
  
  if isBigEndian then  
     Result :=  wpcapntohl(PUint32(aPacketData+aCurrentPos )^)
  else
     Result :=  PUint32(aPacketData+aCurrentPos )^;
    
  if Assigned(aToStringFunction) then
  begin
    LEnrichment := WetNone;    
    LTmpValue   := aToStringFunction(Result);
    if isIP and IsValidPublicIP(LTmpValue) then
      LEnrichment := WetIP;
    AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, aToStringFunction(Result), @Result,sizeOf(Result), Result,LEnrichment ))
  end
  else      
    AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, Result, @Result,sizeOf(Result)));
    
  Inc(aCurrentPos,SizeOf(Result));
end;

class function TWPcapProtocolBase.ParserGenericBytesValue(const aPacketData:PByte;aLevel:byte; aMaxLen,aLen : Integer;
        const aLabel,aCaption : String;AListDetail: TListHeaderString;
        aToStringFunction:TWpcapBytesToString;isBigEndian:Boolean;
        var aCurrentPos:Integer;isIP:Boolean=False): String;
var LBytes      : TIdBytes; 
    LEnrichment : TWpcapEnrichmentType;       
begin 
  Result := String.Empty;       
  if not isValidLen(aCurrentPos,aMaxLen+1,aLen) then Exit;
    
  SetLength(LBytes,aLen);
  Move(aPacketData[aCurrentPos],LBytes[0],aLen);
  if assigned(aToStringFunction) then  
  begin
    Result      := aToStringFunction(LBytes); 
    LEnrichment := WetNone;    
    if isIP and IsValidPublicIP(Result) then
      LEnrichment := WetIP;     
    AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption,Result ,PByte(LBytes),aLen,-1,LEnrichment ))
  end
  else
  begin
    Result := 'RAW value';
    AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, null, PByte(LBytes),aLen ));
  end;
    
  Inc(aCurrentPos,aLen);    
  SetLength(LBytes,0);
end;

class Function TWPcapProtocolBase.ParserBytesToInteger(const aPacketData:PByte;aLevel:byte; aMaxLen,aLen : Integer;
        const aLabel,aCaption : String;AListDetail: TListHeaderString; isBigEndian:Boolean;
        var aCurrentPos:Integer):Integer;
var LBytes : TIdBytes;
    
begin 
  Result := 0;       
  if not isValidLen(aCurrentPos,aMaxLen+1,aLen) then Exit;
    
  SetLength(LBytes,aLen);
  Move( (aPacketData + aCurrentPos)^,LBytes[0],aLen);             

  if isBigEndian then  
     Result :=  wpcapntohl(BytesToInt32(LBytes))
  else
     Result :=  BytesToInt32(LBytes);
        
  AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, Result, PByte(LBytes),aLen ));
    
  Inc(aCurrentPos,aLen);    
  SetLength(LBytes,0);
end;

class Function TWPcapProtocolBase.ParserUint24Value(const aPacketData:PByte;aLevel:byte; aMaxLen : Integer;
        const aLabel,aCaption : String;AListDetail: TListHeaderString;
        aToStringFunction:TWpcapUint32ToString;isBigEndian:Boolean;
        var aCurrentPos:Integer):Uint32;
var LBytes : TIdBytes;
begin
  result := 0;
  if not isValidLen(aCurrentPos,aMaxLen+1,3) then Exit;
  
  SetLength(LBytes,3);
  Move( (aPacketData + aCurrentPos)^,LBytes[0],3);   

  // convert the bytes to a UInt24 value
  Result := MakeULong( MakeWord(0,LBytes[0]),MakeWord(LBytes[1], LBytes[2] ));
  
  if isBigEndian then  
     Result :=  wpcapntohl(Result);

  if Assigned(aToStringFunction) then
    AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, aToStringFunction(Result), PByte(LBytes),3,Result ))
  else      
    AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, Result, PByte(LBytes),3));
    
  Inc(aCurrentPos,3);
end;

class Function TWPcapProtocolBase.ParserUint64Value(const aPacketData:PByte;aLevel:byte; aMaxLen : Integer;
        const aLabel,aCaption : String;AListDetail: TListHeaderString;
        aToStringFunction:TWpcapUint64ToString;isBigEndian:Boolean;
        var aCurrentPos:Integer):Uint64;

begin
  if not isValidLen(aCurrentPos,aMaxLen+1,SizeOf(Result)) then Exit;
  
  if isBigEndian then  
     Result :=  wpcapntohl(PUint64(aPacketData+aCurrentPos )^)
  else
     Result :=  PUint64(aPacketData+aCurrentPos )^;
    
  if Assigned(aToStringFunction) then
    AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, aToStringFunction(Result), @Result,sizeOf(Result), Result ))
  else      
    AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, Result, @Result,sizeOf(Result)));
    
  Inc(aCurrentPos,SizeOf(Result));
end;

Class function TWPcapProtocolBase.isValidLen(const aActualPos,aMaxLen : Integer; aLen:Integer):Boolean;
begin
  Result := (aLen > 0);
  if Result then
    Result := aActualPos +  aLen <=  aMaxLen;
    
  if not Result and (aLen > 0) then
  begin
    if assigned(FOnFoundMalformedPacket) then
      FOnFoundMalformedPacket(nil);
  end;
end;
                                                
class function TWPcapProtocolBase.ParserByEndOfLine(aStartLevel,aPayLoadLen: Integer; aPayLoad: PByte; AListDetail: TListHeaderString; var aStartOffSet: Integer;aAdditionalParameters: PTAdditionalParameters): Boolean;
CONST HTTP_COMPRESS_CONTENT_VALUE : array [0..3] of string= ( 'gzip','deflate','identity','br');
var LCopYStart       : Integer;
    LValue           : String;
    LExt             : String;  
    LBytes           : TIdBytes;
    LtmpLen          : Integer;
    LCompressType    : ShortInt;
    LEnrichmentType  : TWpcapEnrichmentType;
    LInfoProtocol    : String;

    Function ParserValue(const aSep:String): Boolean;
    var LValueArray : Tarray<String>; 
        LField      : String;
        LValueField : String;
        I           : Integer;
    begin 
      Result := False;
      if LValue.Contains(aSep) then
      begin          
        Result      := True;
        LValueArray := LValue.Split([aSep]); 
        LField      := LValueArray[0].Trim;
        LValueField := LValue.Replace(Format('%s%s',[LValueArray[0],aSep]),String.Empty);
        
        if not LField.IsEmpty then
        begin
          if LInfoProtocol.IsEmpty then
            LInfoProtocol := LValue.Trim;
          
          if SameText(LField,'Content-Type') then
          begin
            LInfoProtocol                     := Format('%s %s',[LInfoProtocol,LValue.Trim]).Trim;
            aAdditionalParameters.EnrichmentPresent := True;
            LEnrichmentType                   := WetContent;
            LExt                              :=LValueField.Trim;
            if LExt.Contains(';') then
              LExt := LExt.Split([';'])[0];
            if LExt.Contains('/') then
              LExt := LExt.Split(['/'])[1].Trim;
            aAdditionalParameters.ContentExt := LExt;              
          end;

          if SameText(LField,'User-Agent') then
            LInfoProtocol := Format('%s %s',[LInfoProtocol,LValue.Trim]).Trim;
            
          AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%S.%s',[AcronymName,LField]),LField,LValueField, @LBytes, Length(LBytes),-1,LEnrichmentType ));              
          if LCompressType = -1 then
          begin
            if SameText(LField,'Content-Encoding') then
            begin
               LInfoProtocol :=  Format('%s %s',[LInfoProtocol,LValue.Trim]).Trim;
               for I := Low(HTTP_COMPRESS_CONTENT_VALUE) to High(HTTP_COMPRESS_CONTENT_VALUE) do
               begin
                 if LValueField.ToLower.Contains(HTTP_COMPRESS_CONTENT_VALUE[I]) then
                 begin
                   aAdditionalParameters.CompressType := I; 
                   LCompressType                := I;
                   DoLog('TWPcapProtocolBase.ParserByEndOfLine',Format('Found zip content [%s]',[HTTP_COMPRESS_CONTENT_VALUE[I]]),TWLLWarning);
                   break;
                 end;

               end;
            end;
          end;
        end
        else
          AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%S.line',[AcronymName]),'Line:',LValue.Trim, @LBytes, Length(LBytes),-1,WetContent ));              
      end
    end;
begin
  LCopYStart    := 0;
  LCompressType := -1;
  while aStartOffSet+1 < aPayLoadLen do
  begin
    if (aPayLoad[aStartOffSet+1] = $0A )  then
    begin
      Inc(aStartOffSet); 
      LtmpLen := aStartOffSet-LCopYStart;
       
      if isValidLen(LCopYStart,aPayLoadLen,LtmpLen)  then 
      begin
        SetLength(LBytes,LtmpLen);
        Move(aPayLoad[LCopYStart],LBytes[0],LtmpLen);             
        LValue          := BytesToString(LBytes);
        LEnrichmentType := WetNone;
        if not LValue.Trim.IsEmpty then  
        begin
          if not ParserValue(':') then
          begin
            if not ParserValue(' /')  then
            begin
              if LInfoProtocol.IsEmpty then
                LInfoProtocol := LValue.Trim;            
              AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%S.line',[AcronymName]),'Line:',LValue.Trim, @LBytes, Length(LBytes),-1,LEnrichmentType ));            
            end;  
          end;
        end
        else break;         
        Inc(LCopYStart,LtmpLen)
      end;
    end;

    Inc(aStartOffSet);
  end;

  aAdditionalParameters.Info := Format('%s %s',[LInfoProtocol,aAdditionalParameters.Info]).Trim;
  Result := True;
end;

class function TWPcapProtocolBase.SizeCardinalToStr(const aCardinal:UInt32):String;
begin
  Result := SizeToStr(aCardinal);
end;

class function TWPcapProtocolBase.SizeaUint8ToStr(const aUint8:UInt8):String;
begin
  Result := SizeToStr(aUint8);
end;

class function TWPcapProtocolBase.SizeWordToStr(const aWord:UInt16):String;
begin
  Result := SizeToStr(aWord);
end;

class function TWPcapProtocolBase.ByteToBooleanStr(const aValue: Uint8): String;
begin
  Result := 'False';
  if aValue = 1 then
    Result := 'True';
end;

class function TWPcapProtocolBase.ByteToBinaryStringInternal(
  const AByte: UInt8): string;
begin
  Result := ByteToBinaryString(AByte);
end;

class function TWPcapProtocolBase.BytesToHex(const ABytes: TidBytes): string;
begin
  Result := ToHex(ABytes)
end;

class function TWPcapProtocolBase.BytesToStringRawInternal(const ABytes: TidBytes): string;
begin
  Result := BytesToStringRaw(ABytes)
end;

class function TWPcapProtocolBase.MakeUint32IntoIPv4AddressInternal(const aValue: UInt32): string;
begin
  Result :=  MakeUInt32IntoIPv4Address(aValue)
end;

class function TWPcapProtocolBase.IPv6AddressToStringInternal(const ABytes: TidBytes): string;
begin
  Result := IPv6AddressToString(ABytes)
end;

end.
