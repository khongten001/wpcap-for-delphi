unit wpcap.Protocol.LLMNR;

interface

uses wpcap.Protocol.UDP,wpcap.Conts;

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

  PLLMNRHeader = ^TLLMNRHeader;
  TLLMNRHeader = packed record
    QueryID: Word;            // Unique ID of this query
    Flags: Word;              // Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
    Questions: Word;          // Number of Questions
    AnswerRRs: Word;          // Number of Answer Resource Records
    AuthorityRRs: Word;       // Number of Authority Resource Records
    AdditionalRRs: Word;      // Number of Additional Resource Records
    QuestionName: array [0..0] of Byte; // Query name, possibly with compression
    // Commento: The format of the Question Section of the query is an array of Question structures,
    // where each structure consists of the following fields:
    // - Question Name: a domain name represented as a sequence of labels, where
    // each label consists of a length octet followed by that number of octets.
    // The domain name terminates with the zero length octet for the null label of the root.
    // - Question Type: two octets containing one of the RR TYPE codes.
    // - Question Class: two octets containing one of the RR CLASS codes.
  end;
  
  /// <summary>
  /// The LLMNR protocol implementation class.
  /// </summary>
  TWPcapProtocolLLMNR = Class(TWPcapProtocolBaseUDP)
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
    
    /// <summary>
    ///  Returns the length of the LLMNR header.
    /// </summary>
    class function HeaderLength: word; override;    

    /// <summary>
    ///  Returns a pointer to the LLMNR header.
    /// </summary>
    class function Header(const aUDPPayLoad: PByte): PLLMNRHeader; static;        
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

class function TWPcapProtocolLLMNR.HeaderLength: word;
begin
   Result := SizeOf(TLLMNRHeader)
end;

class function TWPcapProtocolLLMNR.Header(const aUDPPayLoad: PByte): PLLMNRHeader;
begin
  Result := PLLMNRHeader(aUDPPayLoad)
end;

end.
                                                 
