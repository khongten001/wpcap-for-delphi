unit wpcap.Protocol.DNS;

interface

uses wpcap.Protocol.Base,wpcap.Conts,wpcap.Protocol.UDP;

type
  TDnsHeader = packed record
    id        : Word; // identification number 2 bytes
    qr        : Byte; // query/response flag
    opcode    : Byte; // purpose of message
    aa        : Byte; // authoritive answer
    tc        : Byte; // truncated message
    rd        : Byte; // recursion desired
    ra        : Byte; // recursion available
    z         : Byte; // its z! reserved
    rcode     : Byte; // response code
    q_count   : Word; // number of question entries
    ans_count : Word; // number of answer entries
    auth_count: Word; // number of authority entries
    add_count : Word; // number of resource entries
  end;
  PTDNSHeader =^TDNSHeader;

  /// <summary>
  ///  Implements a DNS protocol handler to interpret and validate DNS messages captured by WinPcap.
  /// </summary>
  TWPcapProtocolDNS = Class(TWPcapProtocolBaseUDP)
  public
    /// <summary>
    ///  Returns the default port number for the DNS protocol (53).
    /// </summary>
    class Function DefaultPort: Word; override;

    /// <summary>
    /// Return Intenal protocol ID
    /// </summary>
    class function IDDetectProto: Integer; override;
    
    /// <summary>
    ///  Returns the acronym name of the DNS protocol ("DNS").
    /// </summary>
    class function AcronymName: String; override;

    /// <summary>
    ///  Returns the protocol name of the DNS protocol ("Domain Name System").
    /// </summary>
    class function ProtoName: String; override;

    /// <summary>
    ///  Returns the length of the DNS header.
    /// </summary>
    class function HeaderLength: word; override;

    /// <summary>
    ///  Returns a pointer to the DNS header.
    /// </summary>
    class function Header(const aUDPPayLoad: PByte): PTDNSHeader; static;
End;


    {    TODO EXTRACT INFO from DNS https://github.com/ntop/nDPI/blob/dev/src/lib/protocols/dns.c
  /* 0x0000 QUERY */
  if((dns_header->flags & FLAGS_MASK) == 0x0000)
    *is_query = 1;
  /* 0x8000 RESPONSE */
  else
    *is_query = 0;

  if(*is_query) {
    /* DNS Request */
    if((dns_header->num_queries <= NDPI_MAX_DNS_REQUESTS)
       //       && (dns_header->num_answers == 0)
       && (((dns_header->flags & 0x2800) == 0x2800 /* Dynamic DNS Update */)
	   || ((dns_header->flags & 0xFCF0) == 0x00) /* Standard Query */
	   || ((dns_header->flags & 0xFCFF) == 0x0800) /* Inverse query */
	   || ((dns_header->num_answers == 0) && (dns_header->authority_rrs == 0)))) {
      /* This is a good query */}  
  
  
implementation


{ TWPcapProtocolDNS }

class function TWPcapProtocolDNS.DefaultPort: Word;
begin
  Result := PROTO_DNS_PORT;
end;

class function TWPcapProtocolDNS.IDDetectProto: Integer;
begin
  Result := DETECT_PROTO_DNS;
end;

class function TWPcapProtocolDNS.ProtoName: String;
begin
  Result := 'Domain Name System';
end;

class function TWPcapProtocolDNS.AcronymName: String;
begin
  Result := 'DNS';
end;

class function TWPcapProtocolDNS.HeaderLength: word;
begin
  Result:= SizeOf(TDnsHeader)
end;

class function TWPcapProtocolDNS.Header(const aUDPPayLoad: PByte): PTDNSHeader;
begin
  Result := PTDNSHeader(aUDPPayLoad)
end;

end.
