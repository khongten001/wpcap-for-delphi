unit wpcap.Protocol.MDNS;

interface

uses
  wpcap.Protocol.DNS, wpcap.Conts, System.SysUtils,wpcap.Types;

type
  
  
  /// <summary>
  ///  mDNS (Multicast DNS) protocol class, subclass of TWPcapProtocolDNS.
  /// </summary>
  TWPcapProtocolMDNS = Class(TWPcapProtocolDNS)
  private
    class function IsMulticastIPv6Address(const aAddress: TIPv6AddrBytes): Boolean; static;
  protected
    class function GetDNSQClass(LDataQuestions: TBytes; aOffset: Integer): Word; override;
  public

    /// <summary>
    ///  Returns the default port number for mDNS protocol, which is 5353.
    /// </summary>
    class Function DefaultPort: Word; override;
    
    /// <summary>
    ///  Returns the unique ID for mDNS protocol, which is 6.
    /// </summary>
    class Function IDDetectProto: byte; override;
    
    /// <summary>
    ///  Returns the name of the mDNS protocol, which is "Multicast DNS".
    /// </summary>
    class function ProtoName: String; override;
    
    /// <summary>
    ///  Returns the acronym name for the mDNS protocol, which is "MDNS".
    /// </summary>
    class function AcronymName: String; override;

    /// <summary>
    /// This function returns a TListHeaderString of strings representing the fields in the MDSNS header. 
    //It takes a pointer to the packet data and an integer representing the size of the packet as parameters, and returns a dictionary of strings.
    /// </summary>

    class function IsValid(const aPacket:PByte;aPacketSize:Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean; override;

  end;

implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolMDNS }

class function TWPcapProtocolMDNS.DefaultPort: Word;
begin
  Result := PROTO_MDNS_PORT;
end;

class function TWPcapProtocolMDNS.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_MDNS
end;

class function TWPcapProtocolMDNS.ProtoName: String;
begin
  Result := 'Multicast Domain Name System';
end;

class function TWPcapProtocolMDNS.AcronymName: String;
begin
  Result := 'MDNS';
end;

class function TWPcapProtocolMDNS.GetDNSQClass(LDataQuestions: TBytes; aOffset: Integer): Word;
var LQClass: Word;
begin
  // Read the QClass field as a big-endian 16-bit integer
  LQClass := inherited GetDNSQClass(LDataQuestions,aOffset);
  
  // Check if the QClass value is a MDNS-specific class
  case LQClass of
    32769: Result := TYPE_DNS_QUESTION_PTR;    // PTR (Reverse DNS)
    32770: Result := TYPE_DNS_QUESTION_HINFO; // HINFO (Host Info)
    32771: Result := TYPE_DNS_QUESTION_MINFO; // MINFO (Mailbox Info)
    32772: Result := TYPE_DNS_QUESTION_MX; // MX (Mail Exchange)
    32773: Result := TYPE_DNS_QUESTION_TXT; // TXT (Text)
    49152: Result := 255; // ANY (Wildcard)
  else
    // If the QClass value is not a MDNS-specific class, return it as is
    Result := LQClass;
  end;
end;

class function TWPcapProtocolMDNS.IsMulticastIPv6Address(const aAddress: TIPv6AddrBytes): Boolean;
{IPv6 Dest = F02::FB}
const MulticastPrefix: TIPv6AddrBytes = (255, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,251); 
begin
  Result := CompareMem(@aAddress, @MulticastPrefix, SizeOf(MulticastPrefix));
end;  

class function TWPcapProtocolMDNS.IsValid(const aPacket: PByte;
  aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var LAcronymNameTmp     : String;  
    LIdProtoDetectedTmp : Byte;
    aHederIPv6          : PIpv6Header;
    aIPClass            : TIpClaseType;  
begin
  Result  := inherited IsValid(aPacket,aPacketSize,LAcronymNameTmp,LIdProtoDetectedTmp);  
  aIPClass:= IpClassType(aPacket,aPacketSize); 
  if result then
  begin
    if aIPClass = imtIpv6 then
    begin
      aHederIPv6 := TWpcapIPHeader.HeaderIPv6(aPacket,aPacketSize);
      Result     := IsMulticastIPv6Address(aHederIPv6.DestinationAddress);
    end;
  end
  else if aIPClass = imtIpv6 then
  begin
    aHederIPv6 := TWpcapIPHeader.HeaderIPv6(aPacket,aPacketSize);
    Result     := IsMulticastIPv6Address(aHederIPv6.DestinationAddress);  
  end;
        
  if result then
  begin
    aAcronymName     := LAcronymNameTmp;
    aIdProtoDetected := LIdProtoDetectedTmp;
  end;  
  
end;

end.
