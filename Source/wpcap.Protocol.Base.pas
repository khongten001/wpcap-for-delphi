unit wpcap.Protocol.Base;

interface

uses
  System.SysUtils, WinSock, System.Types, wpcap.Level.Eth, wpcap.StrUtils,
  System.Variants,wpcap.Types;

Type


  /// <summary>
  /// Base class for all protocols in a packet capture. 
  /// This class defines the base behavior that each protocol should implement.
  /// </summary>
  TWPcapProtocolBase = class(TWpcapEthHeader)
  protected
    class function IsValidByPort(aTestPort, aSrcPort, aDstPort: Integer;
      var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; virtual;
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

    class function AddHeaderInfo(aLevel:Byte;const aDescription:String;aValue:Variant;aPacketInfo:PByte;aPacketInfoSize:Word):THeaderString;static;
    /// <summary>
    /// Checks whether the packet has the default port for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function IsValidByDefaultPort(aSrcPort, aDstPort: Integer; var aAcronymName: String;
      var aIdProtoDetected: Byte): Boolean;overload; virtual;

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

class function TWPcapProtocolBase.AddHeaderInfo(aLevel:Byte;const aDescription:String;aValue:Variant;aPacketInfo:PByte;aPacketInfoSize:Word):THeaderString;
begin    
  Result.Description := aDescription;
  Result.Value       := aValue;
  Result.Level       := aLevel;
  if aPacketInfo = nil then      
    Result.Hex := String.Empty
  else
    Result.Hex := String.Join(sLineBreak,DisplayHexData(aPacketInfo,aPacketInfoSize,False)).Trim;
  Result.Size := aPacketInfoSize;
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

end.
