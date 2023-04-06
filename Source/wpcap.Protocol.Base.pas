﻿unit wpcap.Protocol.Base;

interface

uses
  System.SysUtils, WinSock, System.Types, wpcap.Level.Eth, wpcap.StrUtils,idGlobal,
  System.Variants,wpcap.Types,wpcap.BufferUtils,System.Classes;

Type


  /// <summary>
  /// Base class for all protocols in a packet capture. 
  /// This class defines the base behavior that each protocol should implement.
  /// </summary>
  TWPcapProtocolBase = class(TWpcapEthHeader)
  private


  protected
     class var FIsFilterMode           : Boolean;
     class var FOnFoundMalformedPacket : TNotifyEvent;
     class function SizeaUint8ToStr(const aUint8: UInt8): String;
     class function SizeCardinalToStr(const aCardinal: UInt32): String; 
     class function ByteToBinaryStringInternal(const AByte: UInt8): string;     
     class function SizeWordToStr(const aWord: UInt16): String;
     class Function ByteToBooleanStr(const aValue:Uint8):String;
     class function MakeDWordIntoIPv4AddressInternal(const ADWord: UInt32): string;
     class function isValidLen(const aActualPos, aMaxLen: Integer; aLen: Integer): Boolean; static;
     class function IsValidByPort(aTestPort, aSrcPort, aDstPort: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; virtual;
     class function ParserUint8Value(const aPacketData:PByte; aLevel:byte; aMaxLen:Integer; const aLabel,aCaption : String; AListDetail: TListHeaderString; aToStringFunction:TWpcapUint8ToString; isBigIndian:Boolean;var aCurrentPos:Integer):Uint8;  
     class function ParserUint16Value(const aPacketData:PByte; aLevel:byte; aMaxLen:Integer; const aLabel,aCaption : String; AListDetail: TListHeaderString; aToStringFunction:TWpcapUint16ToString; isBigIndian:Boolean;var aCurrentPos:Integer):Uint16;
     class function ParserUint32Value(const aPacketData:PByte; aLevel:byte; aMaxLen:Integer; const aLabel,aCaption : String; AListDetail: TListHeaderString; aToStringFunction:TWpcapUint32ToString; isBigIndian:Boolean;var aCurrentPos:Integer):Uint32;
     class function ParserUint64Value(const aPacketData:PByte; aLevel:byte; aMaxLen:Integer; const aLabel,aCaption : String; AListDetail: TListHeaderString; aToStringFunction:TWpcapUint64ToString; isBigIndian:Boolean;var aCurrentPos:Integer):Uint64;     
     class function ParserByEndOfLine(aStartLevel,aPayLoadLen:Integer; aPayLoad: PByte; AListDetail: TListHeaderString;var aStartOffSet: Integer): Boolean;        
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


    class function AddHeaderInfo(aLevel:Byte;const aLabel, aDescription:String;aValue:Variant;aPacketInfo:PByte;aPacketInfoSize:Word;aRaWData: Integer=-1 ;aEnrichmentType : TWcapEnrichmentType=WetNone):THeaderString;static;
    /// <summary>
    /// Checks whether the packet has the default port for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function IsValidByDefaultPort(aSrcPort, aDstPort: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;overload; virtual;
    
    {Property}
    class property IsFilterMode           : Boolean        read FIsFilterMode           write FIsFilterMode default false;
    
    {Event}
    class property OnFoundMalformedPacket : TNotifyEvent   read FOnFoundMalformedPacket write FOnFoundMalformedPacket;
  end;
  
implementation

{ TWPcapProtocolBase }


class function TWPcapProtocolBase.DetailInfo: String;
begin
  Result := String.Empty;
end;

class function TWPcapProtocolBase.DefaultPort: Word;
begin
  raise Exception.Create('TWPcapProtocolBase.DefaultPort- Non implemented in base class - please override this method');
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

class function TWPcapProtocolBase.AddHeaderInfo(aLevel:Byte;const aLabel, aDescription:String;aValue:Variant;aPacketInfo:PByte;aPacketInfoSize:Word;aRaWData: Integer=-1 ;aEnrichmentType : TWcapEnrichmentType=WetNone):THeaderString;
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
    Result.Hex := String.Join(sLineBreak,DisplayHexData(aPacketInfo,aPacketInfoSize,False)).Trim;
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
        aToStringFunction:TWpcapUint8ToString;isBigIndian:Boolean;
        var aCurrentPos:Integer):Uint8;
begin
  Result := 0;
  if not isValidLen(aCurrentPos,aMaxLen,SizeOf(Result)) then Exit;
  
  Result :=  PUint8(aPacketData+aCurrentPos )^;
  if Assigned(aToStringFunction) then
    AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, aToStringFunction(Result), @Result,sizeOf(Result), Result ))
  else  
    AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, Result, @Result,sizeOf(Result) ));
  Inc(aCurrentPos,SizeOf(Result));
end;

class Function TWPcapProtocolBase.ParserUint16Value(const aPacketData:PByte;aLevel:byte; aMaxLen:Integer;
          const aLabel,aCaption : String;AListDetail: TListHeaderString;
          aToStringFunction:TWpcapUint16ToString;isBigIndian:Boolean;
          var aCurrentPos:Integer):Uint16;
begin
  if not isValidLen(aCurrentPos,aMaxLen+1,SizeOf(Result)) then Exit;
  
  if isBigIndian then
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
        aToStringFunction:TWpcapUint32ToString;isBigIndian:Boolean;
        var aCurrentPos:Integer):Uint32;

begin
  if not isValidLen(aCurrentPos,aMaxLen+1,SizeOf(Result)) then Exit;
  
  if isBigIndian then  
     Result :=  wpcapntohl(PUint32(aPacketData+aCurrentPos )^)
  else
     Result :=  PUint32(aPacketData+aCurrentPos )^;
    
  if Assigned(aToStringFunction) then
    AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, aToStringFunction(Result), @Result,sizeOf(Result), Result ))
  else      
    AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, Result, @Result,sizeOf(Result)));
    
  Inc(aCurrentPos,SizeOf(Result));
end;

class Function TWPcapProtocolBase.ParserUint64Value(const aPacketData:PByte;aLevel:byte; aMaxLen : Integer;
        const aLabel,aCaption : String;AListDetail: TListHeaderString;
        aToStringFunction:TWpcapUint64ToString;isBigIndian:Boolean;
        var aCurrentPos:Integer):Uint64;

begin
  if not isValidLen(aCurrentPos,aMaxLen+1,SizeOf(Result)) then Exit;
  
  if isBigIndian then  
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
                                                
class function TWPcapProtocolBase.ParserByEndOfLine(aStartLevel,
  aPayLoadLen: Integer; aPayLoad: PByte; AListDetail: TListHeaderString; var aStartOffSet: Integer): Boolean;
var LCopYStart  : Integer;
    aValue      : String;
    LBytes      : TIdBytes;
    LtmpLen     : Integer;
    aValueArray : Tarray<String>;      
begin
  LCopYStart := 0;
  Result     := False;
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
         aValue := BytesToString(LBytes);

         if aValue.Contains(':') then
         begin
           aValueArray := aValue.Split([':']); 
           if not aValueArray[0].Trim.IsEmpty then
            AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%S.%s',[AcronymName,aValueArray[0].Trim]),aValueArray[0].Trim,aValueArray[1].Trim, @LBytes, Length(LBytes) ))
         end
         else if aValue.Contains('/')  then
         begin
           aValueArray := aValue.Split(['/']); 
           if not aValueArray[0].Trim.IsEmpty then
            AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%S.%s',[AcronymName,aValue.Split(['/'])[0]]),aValue.Split(['/'])[0],aValue.Split(['/'])[1], @LBytes, Length(LBytes) ))
         end
         else if not aValue.Trim.IsEmpty then              
           AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%S.%s',[AcronymName,aValue.Trim]),aValue.Trim,null, @LBytes, Length(LBytes) ));
         
         Inc(LCopYStart,LtmpLen)
       end;
    end;

    Inc(aStartOffSet);
  end;

  Result := True;
end;

class function TWPcapProtocolBase.MakeDWordIntoIPv4AddressInternal(const ADWord: UInt32): string;
begin
  Result :=  MakeUInt32IntoIPv4Address(ADWord)
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

end.
