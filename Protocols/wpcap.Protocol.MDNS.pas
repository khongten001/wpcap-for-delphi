unit wpcap.Protocol.MDNS;

interface

uses wpcap.Protocol.DNS,wpcap.Conts;

type
  /// <summary>
  ///  mDNS (Multicast DNS) protocol class, subclass of TWPcapProtocolDNS.
  /// </summary>
  TWPcapProtocolMDNS = Class(TWPcapProtocolDNS)
  public
    /// <summary>
    ///  Returns the default port number for mDNS protocol, which is 5353.
    /// </summary>
    class Function DefaultPort: Word; override;
    
    /// <summary>
    ///  Returns the unique ID for mDNS protocol, which is 6.
    /// </summary>
    class Function IDDetectProto: Integer; override;
    
    /// <summary>
    ///  Returns the name of the mDNS protocol, which is "Multicast DNS".
    /// </summary>
    class function ProtoName: String; override;
    
    /// <summary>
    ///  Returns the acronym name for the mDNS protocol, which is "MDNS".
    /// </summary>
    class function AcronymName: String; override;
  end;

implementation

{ TWPcapProtocolMDNS }

class function TWPcapProtocolMDNS.DefaultPort: Word;
begin
  Result := PROTO_MDNS_PORT;
end;

class function TWPcapProtocolMDNS.IDDetectProto: Integer;
begin
  Result := DETECT_PROTO_MDNS
end;

class function TWPcapProtocolMDNS.ProtoName: String;
begin
  Result := 'Multicast DNS';
end;

class function TWPcapProtocolMDNS.AcronymName: String;
begin
  Result := 'MDNS';
end;

end.
