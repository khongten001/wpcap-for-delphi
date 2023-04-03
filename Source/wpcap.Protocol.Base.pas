unit wpcap.Protocol.Base;

interface

uses
  System.SysUtils, WinSock, System.Types, wpcap.Level.Eth, wpcap.StrUtils,idGlobal,
  System.Variants,wpcap.Types,wpcap.BufferUtils;

Type


  /// <summary>
  /// Base class for all protocols in a packet capture. 
  /// This class defines the base behavior that each protocol should implement.
  /// </summary>
  TWPcapProtocolBase = class(TWpcapEthHeader)
  private


  protected
     class var FIsFilterMode : Boolean;
     class function IsValidByPort(aTestPort, aSrcPort, aDstPort: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; virtual;
     class procedure ParserWordValue(const aPacketData:PByte;aLevel:byte;const aLabel,aCaption : String;AListDetail: TListHeaderString;var aCurrentPos:Integer);
     class procedure ParserCardinalValue(const aPacketData:PByte;aLevel:byte;const aLabel,aCaption : String;AListDetail: TListHeaderString;var aCurrentPos:Integer);
     class procedure ParserByteValue(const aPacketData:PByte;aLevel:byte;const aLabel,aCaption : String;AListDetail: TListHeaderString;var aCurrentPos:Integer);  
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
    class property IsFilterMode  : Boolean read FIsFilterMode write FIsFilterMode default false;
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

class procedure TWPcapProtocolBase.ParserCardinalValue(const aPacketData: PByte;
  aLevel:byte;const aLabel, aCaption: String; AListDetail: TListHeaderString;
  var aCurrentPos: Integer);
var LCardinalValue : Cardinal;  
begin
  LCardinalValue :=  PCardinal(aPacketData+aCurrentPos )^;
  AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, wpcapntohl( LCardinalValue ), @LCardinalValue,sizeOf(LCardinalValue)));
  Inc(aCurrentPos,SizeOf(LCardinalValue));
end;

class procedure TWPcapProtocolBase.ParserWordValue(const aPacketData: PByte;
  aLevel: byte; const aLabel, aCaption: String; AListDetail: TListHeaderString;
  var aCurrentPos: Integer);
var LWordValue : Word;  
begin
  LWordValue :=  PWord(aPacketData+aCurrentPos )^;
  AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, wpcapntohs( LWordValue ), @LWordValue,sizeOf(LWordValue)));
  Inc(aCurrentPos,SizeOf(LWordValue));
end;

class procedure TWPcapProtocolBase.ParserByteValue(const aPacketData: PByte;
  aLevel: byte; const aLabel, aCaption: String; AListDetail: TListHeaderString;
  var aCurrentPos: Integer);
var LByteValue : Byte;    
begin
  LByteValue :=  PByte(aPacketData+aCurrentPos )^;
  AListDetail.Add(AddHeaderInfo(aLevel, aLabel,aCaption, wpcapntohl( LByteValue ), @LByteValue,sizeOf(LByteValue)));
  Inc(aCurrentPos,SizeOf(LByteValue));
end;
                                                
class function TWPcapProtocolBase.ParserByEndOfLine(aStartLevel,
  aPayLoadLen: Integer; aPayLoad: PByte; AListDetail: TListHeaderString; var aStartOffSet: Integer): Boolean;
var LCopYStart         : Integer;
    aValue             : String;
    LBytes             : TIdBytes;
    aValueArray        : Tarray<String>;      
begin
  LCopYStart := 0;

  while aStartOffSet+1 < aPayLoadLen do
  begin
    if (aPayLoad[aStartOffSet+1] = $0A )  then
    begin
       Inc(aStartOffSet); 
       if aStartOffSet-LCopYStart > 0 then
       begin
         SetLength(LBytes,aStartOffSet-LCopYStart);
         Move(aPayLoad[LCopYStart],LBytes[0],aStartOffSet-LCopYStart);             
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
         
         Inc(LCopYStart,aStartOffSet-LCopYStart)
       end;
    end;

    Inc(aStartOffSet);
  end;
end;

end.
