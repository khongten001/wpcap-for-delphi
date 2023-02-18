unit wpcap.Protocol.LLMNR;

interface

uses wpcap.Protocol.DNS,wpcap.Conts;

type
  /// <summary>
  /// The LLMNR protocol implementation class.
  /// </summary>
  TWPcapProtocolLLMNR = Class(TWPcapProtocolDNS)
  public
    /// <summary>
    /// Returns the default LLMNR port (5355).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the LLMNR protocol.
    /// </summary>
    class function IDDetectProto: Integer; override;
    /// <summary>
    /// Returns the name of the LLMNR protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the LLMNR protocol.
    /// </summary>
    class function AcronymName: String; override;
  end;


implementation

{ TWPcapProtocolMDNS }
class function TWPcapProtocolLLMNR.DefaultPort: Word;
begin
  Result := PROTO_LLMNR_PORT;
end;

class function TWPcapProtocolLLMNR.IDDetectProto: Integer;
begin
  Result := DETECT_PROTO_LLMNR
end;

class function TWPcapProtocolLLMNR.ProtoName: String;
begin
  Result := 'Link-Local Multicast Name Resolution';
end;

class function TWPcapProtocolLLMNR.AcronymName: String;
begin
  Result := 'LLMNR';
end;

end.
                                                 
