unit wpcap.Protocol.LLMNR;

interface

uses wpcap.Protocol.DNS,wpcap.Conts;

type

  //TODO When LLMNR is used with IPv6, it is transmitted to a specific multicast address FF02::1:3.
  {
    // Check if the packet is using the LLMNR multicast address
    if (LIPv6Hdr.ip6_dst.u6_addr32[0] = 0xFF020000) and
       (LIPv6Hdr.ip6_dst.u6_addr32[1] = 0x00000000) and
       (LIPv6Hdr.ip6_dst.u6_addr32[2] = 0x00000000) and
       (LIPv6Hdr.ip6_dst.u6_addr32[3] = 0x000000FB) and
       (LIPv6Hdr.ip6_dst.u6_addr32[2] = 0x00000000) and
       (LIPv6Hdr.ip6_dst.u6_addr32[3] = 0x000000FB) and       
       then
    begin
  }
  
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
    class function IDDetectProto: byte; override;
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

class function TWPcapProtocolLLMNR.IDDetectProto: byte;
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
                                                 
