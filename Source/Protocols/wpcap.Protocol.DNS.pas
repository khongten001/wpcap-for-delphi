unit wpcap.Protocol.DNS;

interface                                  

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Protocol.UDP, System.SysUtils,Variants,wpcap.StrUtils,
  wpcap.Types, wpcap.BufferUtils,System.StrUtils,winSock,WinApi.Windows,System.Classes;

type
  {https://www.rfc-editor.org/rfc/rfc1035}

{
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

 } 
  TDnsHeader = packed record
    id           : Word; // identification number 2 bytes
    Flags        : Word;
    Questions    : Word;  // Number of questions in the Question Section
    AnswerRRs    : Word;  // Number of resource records in the Answer Section
    AuthorityRRs : Word;  // Number of resource records in the Authority Section
    AdditionalRRs: Word;  // Number of resource records in the Additional Section
  //  QueryRRs     : Word;  // Number of resource records in the Query Section
  end;
  PTDNSHeader =^TDNSHeader;

  TRRsType = (rtQuestion,rtAnswer,rtAuthority,rtAdditional);
  
  /// <summary>
  ///  Implements a DNS protocol handler to interpret and validate DNS messages captured by WinPcap.
  /// </summary>
  TWPcapProtocolDNS = Class(TWPcapProtocolBaseUDP)
  private
    class function GetQuestions(const aPacketData: PByte;aPacketSize: Integer; AListDetail: TListHeaderString;var aOffSetQuestion : Integer):String;
  protected
    class function GetRSS(const aRRsType:TRRsType;const aPacketData: PByte;aPacketSize: Integer; AListDetail: TListHeaderString;var aOffset : Integer):String;virtual;
    class function GetDNSClass(LDataQuestions: TBytes; aOffset: Integer): byte; virtual;
    class procedure ParserDNSClass(const aRRsType:TRRsType;const aDataRss: TBytes; aInternalOffset: Integer;AListDetail: TListHeaderString); virtual;
    class procedure ParserDNSTTL(const aRRsType: TRRsType;const aDataRss: TBytes; aInternalOffset: Integer;AListDetail: TListHeaderString); virtual;    
    class function ApplyConversionName(const aName: String): String; virtual;
    class function QClassToString(const aQClass: byte): String;virtual;     
  public

    /// <summary>
    ///  Returns the default port number for the DNS protocol (53).
    /// </summary>
    class Function DefaultPort: Word; override;

    /// <summary>
    /// Return Intenal protocol ID
    /// </summary>
    class function IDDetectProto: byte; override;
    
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
    class function HeaderLength(aFlag:Byte): word; override;

    /// <summary>
    ///  Returns a pointer to the DNS header.
    /// </summary>
    class function Header(const aUDPPayLoad: PByte): PTDNSHeader; static;

    /// <summary>
    ///  Parses a DNS name from a byte array and returns it as a string.
    /// </summary>
    /// <param name="AData">
    ///   The byte array to parse.
    /// </param>
    /// <param name="AOffset">
    ///   The starting offset in the byte array.
    /// </param>
    /// <returns>
    ///   The corresponding domain name as a string.
    /// </returns>
    class function ParseDNSName(const aPacket: TBytes; var aOffset,aTotalNameLen: integer): AnsiString;
    /// <summary>
    ///  Returns the DNS flags as a string.
    /// </summary>
    /// <param name="Flags">
    ///   The DNS flags to convert.
    /// </param>
    /// <param name="AListDetail">
    ///   The list of header details to include in the output string.
    /// </param>
    /// <returns>
    ///   A string representation of the DNS flags.
    /// </returns>
    class function GetDNSFlags(aFlags: Word; AListDetail: TListHeaderString): string;

    /// <summary>
    ///  Returns a string representation of a DNS question class.
    /// </summary>
    /// <param name="aType">
    ///   The DNS question class to convert.
    /// </param>
    /// <returns>
    ///   A string representation of the DNS question class.
    /// </returns>
    class function QuestionClassToStr(aType: Word): string;virtual;

    /// <summary>
    ///  Converts the DNS header to a string and adds it to the list of header details.
    /// </summary>
    /// <param name="aPacketData">
    ///   Pointer to the start of the packet data of winpcap.
    /// </param>
    /// <param name="aPacketSize">
    ///   The size of the packet data.
    /// </param>
    /// <param name="AListDetail">
    ///   The list of header details to append to.
    /// </param>
    /// <returns>
    ///   True if the header was successfully added to the list, False otherwise.
    /// </returns>
    class function HeaderToString(const aPacketData: PByte; aPacketSize: Integer; AListDetail: TListHeaderString): Boolean; override;
  End;  
implementation


{ TWPcapProtocolDNS }

class function TWPcapProtocolDNS.DefaultPort: Word;
begin
  Result := PROTO_DNS_PORT;
end;

class function TWPcapProtocolDNS.IDDetectProto: byte;
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

class function TWPcapProtocolDNS.HeaderLength(aFlag:Byte): word;
begin
  Result:= SizeOf(TDnsHeader)
end;

class function TWPcapProtocolDNS.Header(const aUDPPayLoad: PByte): PTDNSHeader;
begin
  Result := PTDNSHeader(aUDPPayLoad)
end;

Class function TWPcapProtocolDNS.QuestionClassToStr(aType:Word):String;
begin
  case aType of
    
    TYPE_DNS_QUESTION_A			   	: Result := 'A';
    TYPE_DNS_QUESTION_NS		   	: Result := 'NS';
    TYPE_DNS_QUESTION_MD		   	: Result := 'MD';
    TYPE_DNS_QUESTION_MF		   	: Result := 'MF';
    TYPE_DNS_QUESTION_CNAME	   	: Result := 'CNAME';
    TYPE_DNS_QUESTION_SOA		   	: Result := 'SOA';
    TYPE_DNS_QUESTION_MB		   	: Result := 'MB';
    TYPE_DNS_QUESTION_MG		   	: Result := 'MG';
    TYPE_DNS_QUESTION_MR		   	: Result := 'MR';
    TYPE_DNS_QUESTION_NULL	   	: Result := 'NULL';
    TYPE_DNS_QUESTION_WKS		   	: Result := 'WKS';
    TYPE_DNS_QUESTION_PTR		   	: Result := 'PTR';
    TYPE_DNS_QUESTION_HINFO	   	: Result := 'HINFO';
    TYPE_DNS_QUESTION_MINFO	   	: Result := 'MINFO';
    TYPE_DNS_QUESTION_MX		   	: Result := 'MX';
    TYPE_DNS_QUESTION_TXT		   	: Result := 'TXT';
    TYPE_DNS_QUESTION_RP		   	: Result := 'RP';
    TYPE_DNS_QUESTION_AFSDB	   	: Result := 'AFSDB';
    TYPE_DNS_QUESTION_X25		   	: Result := 'X25';
    TYPE_DNS_QUESTION_ISDN	   	: Result := 'ISDN';
    TYPE_DNS_QUESTION_RT		   	: Result := 'RT';
    TYPE_DNS_QUESTION_NSAP	   	: Result := 'NSAP';
    TYPE_DNS_QUESTION_NSAP_PTR  : Result := 'NSAP_PTR';
    TYPE_DNS_QUESTION_SIG		  	: Result := 'SIG';
    TYPE_DNS_QUESTION_KEY		  	: Result := 'KEY';
    TYPE_DNS_QUESTION_PX		  	: Result := 'PX';
    TYPE_DNS_QUESTION_GPOS	  	: Result := 'GPOS';
    TYPE_DNS_QUESTION_AAAA	  	: Result := 'AAAA';
    TYPE_DNS_QUESTION_LOC		  	: Result := 'LOC';
    TYPE_DNS_QUESTION_NXT		  	: Result := 'NXT';
    TYPE_DNS_QUESTION_EID		  	: Result := 'EID';
    TYPE_DNS_QUESTION_NIMLOC  	: Result := 'NIMLOC';
    TYPE_DNS_QUESTION_SRV		  	: Result := 'SRV';
    TYPE_DNS_QUESTION_ATMA	  	: Result := 'ATMA';
    TYPE_DNS_QUESTION_NAPTR	  	: Result := 'NAPTR';
    TYPE_DNS_QUESTION_KX		  	: Result := 'KX';
    TYPE_DNS_QUESTION_CERT	  	: Result := 'CERT';
    TYPE_DNS_QUESTION_A6		  	: Result := 'A6';
    TYPE_DNS_QUESTION_DNAME	  	: Result := 'DNAME';
    TYPE_DNS_QUESTION_SINK	  	: Result := 'SINK';
    TYPE_DNS_QUESTION_OPT		  	: Result := 'OPT';
    TYPE_DNS_QUESTION_APL		  	: Result := 'APL';
    TYPE_DNS_QUESTION_DS		  	: Result := 'DS';
    TYPE_DNS_QUESTION_SSHFP	  	: Result := 'SSHFP';
    TYPE_DNS_QUESTION_IPSECKEY	: Result := 'IPSECKEY';
    TYPE_DNS_QUESTION_RRSIG			: Result := 'RRSIG';
    TYPE_DNS_QUESTION_NSEC			: Result := 'NSEC';
    TYPE_DNS_QUESTION_DNSKEY		: Result := 'DNSKEY';
    TYPE_DNS_QUESTION_DHCID			: Result := 'DHCID';
    TYPE_DNS_QUESTION_NSEC3			: Result := 'NSEC3';
    TYPE_DNS_QUESTION_NSEC3PARAM: Result := 'NSEC3PARAM';
    TYPE_DNS_QUESTION_TLSA			: Result := 'TLSA';
    TYPE_DNS_QUESTION_SMIMEA		: Result := 'SMIMEA';
    TYPE_DNS_QUESTION_HIP		  	: Result := 'HIP';
    TYPE_DNS_QUESTION_NINFO			: Result := 'NINFO';
    TYPE_DNS_QUESTION_RKEY			: Result := 'RKEY';
    TYPE_DNS_QUESTION_TALINK		: Result := 'TALINK';
    TYPE_DNS_QUESTION_CDS			  : Result := 'CDS';
    TYPE_DNS_QUESTION_CDNSKEY		: Result := 'CDNSKEY';
    TYPE_DNS_QUESTION_OPENPGPKEY: Result := 'OPENPGPKEY';
    TYPE_DNS_QUESTION_CSYNC			: Result := 'CSYNC';
    TYPE_DNS_QUESTION_SPF		  	: Result := 'SPF';
    TYPE_DNS_QUESTION_UINFO			: Result := 'UINFO';
    TYPE_DNS_QUESTION_UID		  	: Result := 'UID';
    TYPE_DNS_QUESTION_GID		  	: Result := 'GID';
    TYPE_DNS_QUESTION_UNSPEC  	: Result := 'UNSPEC';
    TYPE_DNS_QUESTION_NID		  	: Result := 'NID';
    TYPE_DNS_QUESTION_L32		  	: Result := 'L32';
    TYPE_DNS_QUESTION_L64		  	: Result := 'L64';
    TYPE_DNS_QUESTION_LP		  	: Result := 'LP';
    TYPE_DNS_QUESTION_EUI48	  	: Result := 'EUI48';
    TYPE_DNS_QUESTION_EUI64	  	: Result := 'EUI64';
    TYPE_DNS_QUESTION_URI		  	: Result := 'URI';
    TYPE_DNS_QUESTION_CAA		  	: Result := 'CAA';
    TYPE_DNS_QUESTION_TA		  	: Result := 'TA';
    TYPE_DNS_QUESTION_DLV		  	: Result := 'DLV';
    TYPE_DNS_QUESTION_ALL       : Result := 'Any';
  end;
  Result := Format('%s (%d)',[Result,aType]);
end;


class function TWPcapProtocolDNS.GetDNSFlags(aFlags: Word;AListDetail:TListHeaderString): string;  
var LtmpResult       : String;
    LtmpBooleanValue : Boolean;
    LByte0           : Byte;
begin
  Result := String.Empty;
  LByte0 := GetByteFromWord(aFlags,0);

  {
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  }

   
  //QR  A one bit field that specifies whether this message is a query (0), or a response (1).
  if GetBitValue(LByte0,1) =  0 then
  begin
    Result := 'Query'; // Message is a query
    AddHeaderInfo(2,'Type:','Query',nil,0);
  end  
  else
  begin
    Result := 'Response'; // Message is a response
    AddHeaderInfo(2,'Type:','Response',nil,0);       
  end;

  {
  OPCODE  A four bit field that specifies kind of query in this
          message.  This value is set by the originator of a query
          and copied into the response.  The values are:

          0     a standard query (QUERY)
          1     an inverse query (IQUERY)
          2     a server status request (STATUS)
          3-15  reserved for future use           
  }
  
  LtmpResult := String.Empty;
  case (aFlags and $7800) of
    $7800 : LtmpResult := 'Standard query'; // Standard query
    $0000 : LtmpResult := 'Query (Inverse/Reverse)'; // Inverse query
    $1000 : LtmpResult := 'Server status request'; // Server status request
  else
    LtmpResult := 'Reserved'; // Reserved
  end;

  if not LtmpResult.IsEmpty then
  begin
    Result := Format('%s, %s',[Result,LtmpResult]);
    AddHeaderInfo(2,'OPCode:',LtmpResult,nil,0);  
  end;

  {
  AA Authoritative Answer - this bit is valid in responses,
     and specifies that the responding name server is an
     authority for the domain name in question section.

     Note that the contents of the answer section may have
     multiple owner names because of aliases.  The AA bit
     corresponds to the name which matches the query name, or
     the first owner name in the answer section.
  }
  
  LtmpBooleanValue :=  GetBitValue(LByte0,5)=1;
  AddHeaderInfo(2,'Authoritative answer:',LtmpBooleanValue,nil,0);
  Result := Format('%s, Authoritative answer',[result,BoolToStr(LtmpBooleanValue,True)]);

  {
  TC  TrunCation - specifies that this message was truncated
      due to length greater than that permitted on the
      transmission channel.

  }
  LtmpBooleanValue :=  GetBitValue(LByte0,6)=1;
  AddHeaderInfo(2,'Truncated:',LtmpBooleanValue,nil,0);
  Result := Format('%s, Truncated',[result,BoolToStr(LtmpBooleanValue,True)]);  

  {
  RD  Recursion Desired - this bit may be set in a query and
      is copied into the response.  If RD is set, it directs
      the name server to pursue the query recursively.
      Recursive query support is optional.
  }
  LtmpBooleanValue :=  GetBitValue(LByte0,7)=1;
  AddHeaderInfo(2,'Recursion Desired:',LtmpBooleanValue,nil,0);
  Result := Format('%s, Recursion Desired',[result,BoolToStr(LtmpBooleanValue,True)]);  

  {
  RA Recursion Available - this be is set or cleared in a
     response, and denotes whether recursive query support is
     available in the name server.
  }
  LtmpBooleanValue :=  GetBitValue(LByte0,8)=1;
  AddHeaderInfo(2,'Recursion available:',LtmpBooleanValue,nil,0);
  Result := Format('%s, Recursion available',[result,BoolToStr(LtmpBooleanValue,True)]);  

  {
    Z Reserved for future use.  Must be zero in all queries
      and responses.

  }  

  {RCODE  Response code - this 4 bit field is set as part of
          responses.  The values have the following
          interpretation:

          0   No error condition

          1   Format error - The name server was
              unable to interpret the query.

          2   Server failure - The name server was
              unable to process this query due to a
              problem with the name server.

          3   Name Error - Meaningful only for
              responses from an authoritative name
              server, this code signifies that the
              domain name referenced in the query does
              not exist.

          4   Not Implemented - The name server does
              not support the requested kind of query.

          5   Refused - The name server refuses to
              perform the specified operation for
              policy reasons.  For example, a name
              server may not wish to provide the
              information to the particular requester,
              or a name server may not wish to perform
              a particular operation (e.g., zone     }
  
  LtmpResult := String.Empty;
  case (aFlags and $0070) of
    $0000:     LtmpResult := 'Response code: No error';        // No error condition
    $0010:     LtmpResult := 'Response code: Format error';    // The name server was unable to interpret the query
    $0020:     LtmpResult := 'Response code: Server failure';  // The name server was unable to process this query due to a problem with the name server
    $0030:     LtmpResult := 'Response code: Name error';      // Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist
    $0040:     LtmpResult := 'Response code: Not implemented'; // The name server does not support the requested kind of query
    $0050:     LtmpResult := 'Response code: Refused';         // The name server refuses to perform the specified operation for policy reasons
  end;
  
  if not LtmpResult.IsEmpty then
  begin
    Result := Format('%s, %s',[Result,LtmpResult]);
    AddHeaderInfo(2,'Response code:',LtmpResult.Replace('Response code:',String.Empty).Trim,nil,0);
  end;  
  Result := Result.TrimLeft([',']);
end;

class function TWPcapProtocolDNS.ParseDNSName(const aPacket: TBytes; var aOffset,aTotalNameLen: integer): AnsiString;
var LLen        : integer;
    LCompressPos: integer;
    LCompressed : boolean;
    LastOffset  : Integer;
    
begin
  Result        := String.Empty;
  LCompressed   := False;
  aTotalNameLen := 0;
  LCompressPos  := aOffset;
  LastOffset    := 0;
  while True do 
  begin
    LLen := aPacket[aOffset];

    if (LLen and $C0) = $C0 then 
    begin
      // pointer to compressed name
      if not LCompressed then 
      begin
        // first compression, save current offset
        LCompressPos := aOffset;
        LCompressed  := True;
      end;
      // follow pointer
      aOffset := ((LLen and $3F) shl 8) or aPacket[aOffset+1];
      if LastOffset = aOffset then break;

      LastOffset := aOffset;          
      LLen    := aPacket[aOffset];
    end;
    Inc(aOffset);
    if LLen = 0 then 
    begin
      inc(aTotalNameLen,2);
      Break;
    end;
    
    if not Trim(String(Result)).IsEmpty then
      Result := AnsiString(Format('%s.',[Result]));

    SetLength(Result, Length(Result) + LLen);  
    Move(aPacket[aOffset], Result[Length(Result) - LLen + 1], LLen);
    
    Inc(aOffset, LLen);
    inc(aTotalNameLen,LLen);

  end;
  if LCompressed then
    aOffset := LCompressPos+2; // skip compressed name pointer      

  Result := ApplyConversionName(Result);  
end;

class function TWPcapProtocolDNS.ApplyConversionName(const aName:String):String;
begin
  {NO CONVERSION IN DNS protocol}
  Result := aName;
end;

class function TWPcapProtocolDNS.GetDNSClass(LDataQuestions: TBytes; aOffset: Integer): byte;
begin
  
  // Read the QClass field as a big-endian 16-bit integer
  Result := HIBYTE( wpcapntohs( (LDataQuestions[aOffset] shl 8) or LDataQuestions[aOffset+1]));
end;


class function TWPcapProtocolDNS.GetQuestions(const aPacketData: PByte;aPacketSize: Integer; AListDetail: TListHeaderString;var aOffSetQuestion : Integer):String;
var LPUDPHdr        : PUDPHdr;
    LHeaderDNS      : PTDnsHeader;
    LDataQuestions  : TBytes;
    LUDPPayLoad     : PByte;
    LQType          : Word;
    LQClass         : Word;
    LQName          : string; 
    i               : Integer;    
    LCountQuestion  : Word;  
    LTotalNameLen   : Integer;
begin
  {Question section format

    The question section is used to carry the "question" in most queries,
    i.e., the parameters that define what is being asked.  The section
    contains QDCOUNT (usually 1) entries, each of the following format:

                                        1  1  1  1  1  1
          0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                               |
        /                     QNAME                     /
        /                                               /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     QTYPE                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                     QCLASS                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


    QTYPE           a two octet code which specifies the type of the query.
                    The values for this field include all codes valid for a
                    TYPE field, together with some more general codes which
                    can match more than one type of RR.

  }
  Result := String.Empty;  

  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LUDPPayLoad    := GetUDPPayLoad(aPacketData,aPacketSize);    
  LHeaderDNS     := Header(LUDPPayLoad);
  LCountQuestion := wpcapntohs(LHeaderDNS.Questions);

  SetLength(LDataQuestions,UDPPayLoadLength(LPUDPHdr)-HeaderLength(LHeaderDNS.Flags));
  LDataQuestions := TBytes(LUDPPayLoad+HeaderLength(LHeaderDNS.Flags));

  AListDetail.Add(AddHeaderInfo(1,'Query',NULL,Pbyte(@LDataQuestions),Length(LDataQuestions)));              
  for i := 0 to LCountQuestion -1 do
  begin
    {
        QNAME  a domain name represented as a sequence of labels, where
               each label consists of a length octet followed by that
               number of octets.  The domain name terminates with the
               zero length octet for the null label of the root.  Note
               that this field may be an odd number of octets; no
               padding is used.
    }
  

    
    LQName := String(ParseDNSName(LDataQuestions,aOffSetQuestion,LTotalNameLen));
    AListDetail.Add(AddHeaderInfo(2,'Name',LQName,nil,0));  
    AListDetail.Add(AddHeaderInfo(3,'Name length',LTotalNameLen,nil,0));  

    {
      QTYPE  a two octet code which specifies the type of the query.
             The values for this field include all codes valid for a
             TYPE field, together with some more general codes which
             can match more than one type of RR.
    }
    LQType := Swap(PWord(@LDataQuestions[aOffSetQuestion])^);
    AListDetail.Add(AddHeaderInfo(3,'Type:',QuestionClassToStr(LQType),PByte(@LDataQuestions[aOffSetQuestion]),2));       
    Inc(aOffSetQuestion, SizeOf(Word));
    {
      QCLASS  a two octet code that specifies the class of the query.
              For example, the QCLASS field is IN for the Internet.
    }

    ParserDNSClass(rtQuestion,LDataQuestions,aOffSetQuestion,AListDetail);
    Inc(aOffSetQuestion, SizeOf(Word));    
  end;  
end;

class function TWPcapProtocolDNS.QClassToString(const aQClass : byte):String;
  begin
  case aQClass of
    1  : Result := 'IN [Internet]';
    2  : Result := 'CS [CSNET class (Obsolete)]';
    3  : Result := 'CE [CHAOS class]';
    4  : Result := 'Hesiod [Dyer 87]';   
    255: Result := 'Any class';
  else
    Result := aQClass.ToString
  end;
end;

class function TWPcapProtocolDNS.GetRSS(const aRRsType:TRRsType;const aPacketData: PByte;aPacketSize: Integer; AListDetail: TListHeaderString;var aOffset : Integer):String;
var LPUDPHdr        : PUDPHdr;
    LHeaderDNS      : PTDnsHeader;
    LCountRss       : Integer;
    LDataRss        : TBytes;
    LUDPPayLoad     : PByte;
    LRssType        : Word;
    LRssTTL         : Word;
    LRssName        : string; 
    LAddress        : String;
    i               : Integer;    
    J               : Integer;    
    LRecordLength   : Integer;
    LTotalNameLen   : Integer;
    LInternalOffset : Integer;
    LIPAddr         : LongWord;
    LIPv6Addr       : TIPv6AddrBytes;    
begin
   {
    All RRs have the same top level format shown below:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 }
  Result    := String.Empty;  
  LCountRss := 0;
  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LUDPPayLoad := GetUDPPayLoad(aPacketData,aPacketSize);    
  LHeaderDNS  := Header(LUDPPayLoad);

  case aRRsType of
    rtAnswer     : LCountRss   := wpcapntohs(LHeaderDNS.AnswerRRs);
    rtAuthority  : LCountRss   := wpcapntohs(LHeaderDNS.AuthorityRRs);
    rtAdditional : LCountRss   := wpcapntohs(LHeaderDNS.AdditionalRRs);
  end;  
  
  if LCountRss = 0 then Exit;

  SetLength(LDataRss,UDPPayLoadLength(LPUDPHdr)-HeaderLength(LHeaderDNS.Flags)-aOffset);
  LDataRss := TBytes(LUDPPayLoad+HeaderLength(LHeaderDNS.Flags)+aOffset);

  case aRRsType of
    rtAnswer     : 
                   begin
                      AListDetail.Add(AddHeaderInfo(1,'Answer',NULL,nil,0)); 
                      Result := 'Answer';
                   end;
    rtAuthority  : 
                   begin
                     AListDetail.Add(AddHeaderInfo(1,'Authority',NULL,nil,0));    
                     Result := 'Authority';
                   end;
    rtAdditional : begin
                    AListDetail.Add(AddHeaderInfo(1,'Additional',NULL,nil,0));        
                     Result := 'Additional';                    
                   end;
  end;
  
  LInternalOffset := 0;
  for i := 0 to LCountRss - 1 do
  begin
    {
      NAME an owner name, i.e., the name of the node to which this
           resource record pertains.
    }
  
    LRssName := String(ParseDNSName(LDataRss, LInternalOffset,LTotalNameLen));
    AListDetail.Add(AddHeaderInfo(2, 'Name', ifThen(LRssName.Trim.IsEmpty,'<Root>',LRssName), nil, 0));
    AListDetail.Add(AddHeaderInfo(3, 'Name length',LTotalNameLen,nil,0));    

    {TYPE  two octets containing one of the RR TYPE codes.}    
    LRssType := Swap(PWord(@LDataRss[LInternalOffset])^);
    AListDetail.Add(AddHeaderInfo(3, 'Type:', QuestionClassToStr(LRssType), PByte(@LDataRss[LInternalOffset]), 2));
    Inc(LInternalOffset, SizeOf(Word));

    {CLASS two octets containing one of the RR CLASS codes.}

    ParserDNSClass(aRRsType,LDataRss,LInternalOffset,AListDetail);
    Inc(LInternalOffset, SizeOf(word));    
    
    {
      TTL a 32 bit signed integer that specifies the time interval
          that the resource record may be cached before the source
          of the information should again be consulted.  Zero
          values are interpreted to mean that the RR can only be
          used for the transaction in progress, and should not be
          cached.  For example, SOA records are always distributed
          with a zero TTL to prohibit caching.  Zero values can
          also be used for extremely volatile data.
    }
    
    ParserDNSTTL(aRRsType,LDataRss,LInternalOffset,AListDetail);
    Inc(LInternalOffset, SizeOf(integer));

    {
      RDLENGTH  an unsigned 16 bit integer that specifies the length in
                octets of the RDATA field.
    }    
    LRecordLength := wpcapntohs(PWord(@LDataRss[LInternalOffset])^);
    AListDetail.Add(AddHeaderInfo(3, 'Data length:', LRecordLength,PByte(@LDataRss[LInternalOffset]), 2));    
    Inc(LInternalOffset, SizeOf(word));

    {
      RDATA  a variable length string of octets that describes the
             resource.  The format of this information varies
             according to the TYPE and CLASS of the resource record.  
             }  
      case LRssType of
       { TYPE_DNS_QUESTION_A:
        begin
          Move(LDataRss[LInternalOffdet], LIPAddr, SizeOf(LongWord));
          LRssName := intToIPV4(LIPAddr);
          Inc(LInternalOffdet, SizeOf(LongWord));
        end;
        TYPE_DNS_QUESTION_AAAA:
        begin
          Move(LDataRss[LInternalOffdet], LIPv6Addr, SizeOf(TIPv6AddrBytes));
          LRssName := IPv6AddressToString(LIPv6Addr);
          Inc(LInternalOffdet, SizeOf(TIPv6AddrBytes));
        end;  }
        TYPE_DNS_QUESTION_MX:
        begin
          LRssTTL := wpcapntohl(Pinteger(@LDataRss[LInternalOffset])^);
          AListDetail.Add(AddHeaderInfo(3, 'Time to live MX:', Format('%d seconds', [LRssTTL]),PByte(@LDataRss[LInternalOffset]), 4));    
          Inc(LInternalOffset, SizeOf(Pinteger));


          LRssName := String(ParseDNSName(LDataRss, LInternalOffset,LTotalNameLen));
        end;
        TYPE_DNS_QUESTION_SRV:
        begin
          LRssTTL := wpcapntohl(Pinteger(@LDataRss[LInternalOffset])^);
          Inc(LInternalOffset, SizeOf(Pinteger));
          AListDetail.Add(AddHeaderInfo(3, 'Time to live MX:', Format('%d seconds', [LRssTTL]),PByte(@LDataRss[LInternalOffset]), 4)); 
          LRssName := String(ParseDNSName(LDataRss, LInternalOffset,LTotalNameLen));
        end;
      else
        LRssName := String(ParseDNSName(LDataRss, LInternalOffset,LTotalNameLen));
      end;
      Result := FOrmat('%s RData[%d] %s',[Result,I+1,LRssName]);
      AListDetail.Add(AddHeaderInfo(3, 'RData name',LRssName, nil, 0));
  end;
  Inc(aOffset,LInternalOffset);
end;

Class procedure TWPcapProtocolDNS.ParserDNSClass(const aRRsType:TRRsType;const aDataRss:TBytes;aInternalOffset:Integer;AListDetail: TListHeaderString);
var LRssClass : Word;
begin
   if not Assigned(AListDetail) then exit;

  LRssClass := GetDNSClass(aDataRss,aInternalOffset);
  AListDetail.Add(AddHeaderInfo(3, 'Class:',QClassToString(LRssClass), PByte(@aDataRss[aInternalOffset]), 2));    
end;


class function TWPcapProtocolDNS.HeaderToString(const aPacketData: PByte;aPacketSize: Integer; AListDetail: TListHeaderString): Boolean;
var LHeaderDNS        : PTDnsHeader;
    LCountQuestion    : Integer;
    LCOuntAnswer      : Integer;
    LCountAuthority   : Integer;
    LUDPPayLoad       : PByte;
    LPUDPHdr          : PUDPHdr;
    LcountAddRrs      : Integer;
    LOffSetQuestion   : Integer;
begin
  Result := False;
  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LUDPPayLoad      := GetUDPPayLoad(aPacketData,aPacketSize);
  LHeaderDNS       := Header(LUDPPayLoad);
  
  LCountQuestion   := wpcapntohs(LHeaderDNS.Questions);
  LcountAddRrs     := wpcapntohs(LHeaderDNS.AdditionalRRs);
  LCountAnswer     := wpcapntohs(LHeaderDNS.AnswerRRs);
  LCountAuthority  := wpcapntohs(LHeaderDNS.AuthorityRRs);   
  
  AListDetail.Add(AddHeaderInfo(0,Format('%s (%s)',[ProtoName,AcronymName]),NULL,PByte(LHeaderDNS),HeaderLength(LHeaderDNS.Flags)));            
  AListDetail.Add(AddHeaderInfo(1,'ID:',wpcapntohs(LHeaderDNS.ID),PByte(@LHeaderDNS.ID),SizeOf(LHeaderDNS.ID)));        
  AListDetail.Add(AddHeaderInfo(1,'Flags:',Format('%s %s',[ByteToBinaryString(GetByteFromWord(LHeaderDNS.Flags,0)),
                                                           ByteToBinaryString(GetByteFromWord(LHeaderDNS.Flags,1))]),PByte(@LHeaderDNS.Flags),SizeOf(LHeaderDNS.Flags)));      
  GetDNSFlags(LHeaderDNS.Flags,AListDetail);  

  AListDetail.Add(AddHeaderInfo(1,'Questions:',LCountQuestion,PByte(@LHeaderDNS.Questions),SizeOf(LHeaderDNS.Questions)));      
  AListDetail.Add(AddHeaderInfo(1,'Answer RRs:',LCountAnswer,PByte(@LHeaderDNS.AnswerRRs),SizeOf(LHeaderDNS.AnswerRRs)));
  AListDetail.Add(AddHeaderInfo(1,'Authority RRs:',LCountAuthority,PByte(@LHeaderDNS.AuthorityRRs),SizeOf(LHeaderDNS.AuthorityRRs))); 
  AListDetail.Add(AddHeaderInfo(1,'Additional RRs:',LcountAddRrs,PByte(@LHeaderDNS.AdditionalRRs),SizeOf(LHeaderDNS.AdditionalRRs)));       

  {QUESTION}
  LOffSetQuestion := 0;
  if LCountQuestion > 0 then
    GetQuestions(aPacketData,aPacketSize,AListDetail,LOffSetQuestion);
   
  {ANSWER}
  if LCountAnswer > 0 then
    GetRSS(rtAnswer,aPacketData,aPacketSize,AListDetail,LOffSetQuestion);

  {AUTHORITY}
  if LCountAuthority > 0 then
    GetRSS(rtAuthority,aPacketData,aPacketSize,AListDetail,LOffSetQuestion);
  
  {Additional Record} 
  if LcountAddRrs > 0 then
    GetRSS(rtAdditional,aPacketData,aPacketSize,AListDetail,LOffSetQuestion);

  Result := True;
end;

class procedure TWPcapProtocolDNS.ParserDNSTTL(const aRRsType: TRRsType;const aDataRss: TBytes; aInternalOffset: Integer;AListDetail: TListHeaderString);
begin
  AListDetail.Add(AddHeaderInfo(3, 'Time to live:', Format('%d seconds', [wpcapntohl(PInteger(@aDataRss[aInternalOffset])^)]),PByte(@aDataRss[aInternalOffset]), 4));    
end;

end.
