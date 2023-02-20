unit wpcap.Protocol.MDNS;

interface

uses wpcap.Protocol.Base,wpcap.Conts;

type

  //TODO When mDNS is used with IPv6, it is transmitted to a specific multicast address (FF02::FB).
  {
    // Check if the packet is using the mDNS multicast address
    if (LIPv6Hdr.ip6_dst.u6_addr32[0] = 0xFF020000) and
       (LIPv6Hdr.ip6_dst.u6_addr32[1] = 0x00000000) and
       (LIPv6Hdr.ip6_dst.u6_addr32[2] = 0x00000000) and
       (LIPv6Hdr.ip6_dst.u6_addr32[3] = 0x000000FB) then
    begin
  }
  

  TmDNSHeader = packed record
    ID           : Word;  // An identifier assigned by the program that generates any kind of query
    Flags        : Word;  // Various bit flags
    Questions    : Word;  // Number of questions in the Question Section
    AnswerRRs    : Word;  // Number of resource records in the Answer Section
    AuthorityRRs : Word;  // Number of resource records in the Authority Section
    AdditionalRRs: Word;  // Number of resource records in the Additional Section
  end;
  PTmDNSHeader = ^TmDNSHeader;

  /// <summary>
  ///  mDNS (Multicast DNS) protocol class, subclass of TWPcapProtocolDNS.
  /// </summary>
  TWPcapProtocolMDNS = Class(TWPcapProtocolBaseUDP)
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

    /// <summary>
    ///  Returns the length of the mDNS header.
    /// </summary>
    class function HeaderLength: word; override;    

    /// <summary>
    ///  Returns a pointer to the mDNS header.
    /// </summary>
    class function Header(const aUDPPayLoad: PByte): PTmDNSHeader; static;    
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

class function TWPcapProtocolMDNS.HeaderLength: word;
begin
  Result := SizeOf(TmDNSHeader)
end;

class function TWPcapProtocolMDNS.Header(const aUDPPayLoad: PByte): PTmDNSHeader;
begin
  Result := PTmDNSHeader(aUDPPayLoad)
end;

end.
