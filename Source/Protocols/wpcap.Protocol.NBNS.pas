unit wpcap.Protocol.NBNS;

interface

uses
  wpcap.Protocol.DNS, wpcap.Conts, wpcap.Types, wpcap.BufferUtils,WinApi.Windows,
  System.SysUtils, System.Variants,System.Math,winsock,wpcap.StrUtils;

type



  /// <summary>
  /// Represents the NetBIOS Name Service(NBNS) protocol for WireShark.
  /// </summary>
  TWPcapProtocolNBNS = class(TWPcapProtocolDNS)
  private
    class function NBNSNameToString(const ABytes: TBytes): string;
  protected
    class function ApplyConversionName(const aName: String): String; override;  
  public
    /// <summary>
    /// Returns the default port number used by the NBNS protocol.
    /// </summary>
    class function DefaultPort: Word; override;

    /// <summary>
    /// Return Intenal protocol ID
    /// </summary>
    class function IDDetectProto: byte; override;

    /// <summary>
    /// Returns the name of the protocol for the NBNS protocol
    /// </summary>
    class function ProtoName: String; override;

    /// <summary>
    /// Returns the acronym name for the NBNS protocol.
    /// </summary>
    class function AcronymName: String; override;
    /// <summary>
    /// This function returns a TListHeaderString of strings representing the fields in the NBNS header. 
    //  It takes a pointer to the packet data and an integer representing the size of the packet as parameters, and returns a dictionary of strings.
    /// </summary>    
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; override;  

    /// <summary>
    ///  Returns a string representation of a NBNS question class.
    /// </summary>
    /// <param name="aType">
    ///   The NBNS question class to convert.
    /// </param>
    /// <returns>
    ///   A string representation of the NBNS question class.
    /// </returns>
    class function QuestionClassToStr(aType: Word): string;override;      
end;


implementation

class function TWPcapProtocolNBNS.DefaultPort: Word;
begin
  Result := PROTO_NBNS_PORT;
end;

class function TWPcapProtocolNBNS.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_NBNS;
end;

class function TWPcapProtocolNBNS.ProtoName: String;
begin
  Result := 'NetBIOS Name Service'
end;

class function TWPcapProtocolNBNS.AcronymName: String;
begin
  Result := 'NBNS';
end;

class function TWPcapProtocolNBNS.NBNSNameToString(const ABytes: TBytes): string;
var LName : string;
    LIndex: Integer;
    LLen  : Byte;
begin
  LName  := '';
  LIndex := 1;
  while (LIndex < Length(ABytes)) and (ABytes[LIndex] <> 0) do
  begin
    LLen := ABytes[LIndex];
    Inc(LIndex);
    LName := LName + Copy(TEncoding.ASCII.GetString(ABytes, LIndex, LLen), 1, LLen) + '.';
    Inc(LIndex, LLen);
  end;
  // remove the last '.'
  if LName.EndsWith('.') then
    LName := Copy(LName, 1, Length(LName)-1);
  Result := LName;
end;

class function TWPcapProtocolNBNS.IsValid(const aPacket: PByte;aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var LAcronymNameTmp     : String;  
    LIdProtoDetectedTmp : Byte;
  //  aHederIPv6          : PIpv6Header;
  //  aIPClass            : TIpClaseType;  
begin
  Result  := inherited IsValid(aPacket,aPacketSize,LAcronymNameTmp,LIdProtoDetectedTmp);  
        
  if result then
  begin
    aAcronymName     := LAcronymNameTmp;
    aIdProtoDetected := LIdProtoDetectedTmp;
  end;    
end;

class function TWPcapProtocolNBNS.QuestionClassToStr(aType: Word): string;
begin
  Result := String.Empty;

  case aType of
    TYPE_DNS_QUESTION_NIMLOC : Result := 'NB';
  end;
  
  if Result.IsEmpty then  
    Result := inherited QuestionClassToStr(aType)  
  else
    Result := Format('%s [%d]',[Result,aType])    
end;

class function TWPcapProtocolNBNS.ApplyConversionName(const aName: String): String;
var LBytes: TBytes;
    LName : string;
begin
  Try
    {TODO ???}
    LBytes  := HexStrToBytes(aName.Trim);
    Result  := NBNSNameToString(LBytes);
  Except
    Result := aName;
  End;
end;

end.
