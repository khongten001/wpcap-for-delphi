//*************//*************************************************************
//                        WPCAP FOR DELPHI                    *
//				                                        			      *
//                     Freeware Library                       *
//                       For Delphi 10.4                      *
//                            by                              *
//                     Alessandro Mancini                     *
//				                                        			      *
//*************************************************************
{LICENSE:
THIS SOFTWARE IS PROVIDED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND,
EITHER EXPRESSED OR IMPLIED INCLUDING BUT NOT LIMITED TO THE APPLIED
WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
YOU ASSUME THE ENTIRE RISK AS TO THE ACCURACY AND THE USE OF THE SOFTWARE
AND ALL OTHER RISK ARISING OUT OF THE USE OR PERFORMANCE OF THIS SOFTWARE
AND DOCUMENTATION. PRODUCTIONS DOES NOT WARRANT THAT THE SOFTWARE IS ERROR-FREE
OR WILL OPERATE WITHOUT INTERRUPTION. THE SOFTWARE IS NOT DESIGNED, INTENDED
OR LICENSED FOR USE IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE CONTROLS,
INCLUDING WITHOUT LIMITATION, THE DESIGN, CONSTRUCTION, MAINTENANCE OR
OPERATION OF NUCLEAR FACILITIES, AIRCRAFT NAVIGATION OR COMMUNICATION SYSTEMS,
AIR TRAFFIC CONTROL, AND LIFE SUPPORT OR WEAPONS SYSTEMS. PRODUCTIONS SPECIFICALLY
DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF FITNESS FOR SUCH PURPOSE.

You may use/change/modify the component under 1 conditions:
1. In your application, add credits to "WPCAP FOR DELPHI"
{*******************************************************************************}

unit wpcap.Protocol.DNS;

interface                                  

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Protocol.UDP, System.SysUtils,IdGlobal,wpcap.packet,
  Variants, wpcap.StrUtils, wpcap.Types, wpcap.BufferUtils, System.StrUtils,System.Math,
  winSock, WinApi.Windows, System.Classes, wpcap.IpUtils,System.AnsiStrings;

 CONST
  {DNS QUESTION TYPE}
  TYPE_DNS_QUESTION_A			      = 1;
  TYPE_DNS_QUESTION_NS		     	= 2;
  TYPE_DNS_QUESTION_MD		     	= 3;
  TYPE_DNS_QUESTION_MF		     	= 4;
  TYPE_DNS_QUESTION_CNAME	     	= 5;
  TYPE_DNS_QUESTION_SOA		     	= 6;
  TYPE_DNS_QUESTION_MB		     	= 7;
  TYPE_DNS_QUESTION_MG		     	= 8;
  TYPE_DNS_QUESTION_MR		     	= 9;
  TYPE_DNS_QUESTION_NULL	     	= 10;
  TYPE_DNS_QUESTION_WKS		     	= 11;
  TYPE_DNS_QUESTION_PTR		     	= 12;
  TYPE_DNS_QUESTION_HINFO	     	= 13;
  TYPE_DNS_QUESTION_MINFO	     	= 14;
  TYPE_DNS_QUESTION_MX		     	= 15;
  TYPE_DNS_QUESTION_TXT		     	= 16;
  TYPE_DNS_QUESTION_RP		     	= 17;
  TYPE_DNS_QUESTION_AFSDB	     	= 18;
  TYPE_DNS_QUESTION_X25		     	= 19;
  TYPE_DNS_QUESTION_ISDN	     	= 20;
  TYPE_DNS_QUESTION_RT		     	= 21;
  TYPE_DNS_QUESTION_NSAP	     	= 22;
  TYPE_DNS_QUESTION_NSAP_PTR    = 23;
  TYPE_DNS_QUESTION_SIG		     	= 24;
  TYPE_DNS_QUESTION_KEY		     	= 25;
  TYPE_DNS_QUESTION_PX		     	= 26;
  TYPE_DNS_QUESTION_GPOS	     	= 27;
  TYPE_DNS_QUESTION_AAAA	     	= 28;
  TYPE_DNS_QUESTION_LOC		     	= 29;
  TYPE_DNS_QUESTION_NXT		     	= 30;
  TYPE_DNS_QUESTION_EID		     	= 31;
  TYPE_DNS_QUESTION_NIMLOC     	= 32;
  TYPE_DNS_QUESTION_SRV		     	= 33;
  TYPE_DNS_QUESTION_ATMA	     	= 34;
  TYPE_DNS_QUESTION_NAPTR	     	= 35;
  TYPE_DNS_QUESTION_KX		     	= 36;
  TYPE_DNS_QUESTION_CERT	     	= 37;
  TYPE_DNS_QUESTION_A6		     	= 38;
  TYPE_DNS_QUESTION_DNAME	     	= 39;
  TYPE_DNS_QUESTION_SINK	     	= 40;
  TYPE_DNS_QUESTION_OPT		     	= 41;
  TYPE_DNS_QUESTION_APL		     	= 42;
  TYPE_DNS_QUESTION_DS		     	= 43;
  TYPE_DNS_QUESTION_SSHFP	     	= 44;
  TYPE_DNS_QUESTION_IPSECKEY    = 45;
  TYPE_DNS_QUESTION_RRSIG	     	= 46;
  TYPE_DNS_QUESTION_NSEC	     	= 47;
  TYPE_DNS_QUESTION_DNSKEY     	= 48;
  TYPE_DNS_QUESTION_DHCID	     	= 49;
  TYPE_DNS_QUESTION_NSEC3	     	= 50;
  TYPE_DNS_QUESTION_NSEC3PARAM	= 51;
  TYPE_DNS_QUESTION_TLSA		   	= 52;
  TYPE_DNS_QUESTION_SMIMEA			= 53;
  TYPE_DNS_QUESTION_HIP		    	= 55;
  TYPE_DNS_QUESTION_NINFO	   		= 56;
  TYPE_DNS_QUESTION_RKEY	   		= 57;
  TYPE_DNS_QUESTION_TALINK			= 58;
  TYPE_DNS_QUESTION_CDS		    	= 59;
  TYPE_DNS_QUESTION_CDNSKEY			= 60;
  TYPE_DNS_QUESTION_OPENPGPKEY	= 61;
  TYPE_DNS_QUESTION_CSYNC			  = 62;
  TYPE_DNS_QUESTION_SPF			    = 99;
  TYPE_DNS_QUESTION_UINFO			  = 100;
  TYPE_DNS_QUESTION_UID		     	= 101;
  TYPE_DNS_QUESTION_GID		     	= 102;
  TYPE_DNS_QUESTION_UNSPEC			= 103;
  TYPE_DNS_QUESTION_NID		     	= 104;
  TYPE_DNS_QUESTION_L32		     	= 105;
  TYPE_DNS_QUESTION_L64		     	= 106;
  TYPE_DNS_QUESTION_LP		     	= 107;
  TYPE_DNS_QUESTION_EUI48	     	= 108;
  TYPE_DNS_QUESTION_EUI64	     	= 109;
  TYPE_DNS_QUESTION_ALL         = 255;
  TYPE_DNS_QUESTION_URI		     	= 256;
  TYPE_DNS_QUESTION_CAA		     	= 257;
  TYPE_DNS_QUESTION_TA		     	= 32768;
  TYPE_DNS_QUESTION_DLV		     	= 32769; 
 
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
    id           : Uint16; // identification number 2 bytes
    Flags        : Uint16;
    Questions    : Uint16;  // Number of questions in the Question Section
    AnswerRRs    : Uint16;  // Number of resource records in the Answer Section
    AuthorityRRs : Uint16;  // Number of resource records in the Authority Section
    AdditionalRRs: Uint16;  // Number of resource records in the Additional Section
  //  QueryRRs     : Word;  // Number of resource records in the Query Section
  end;
  PTDNSHeader =^TDNSHeader;

  TRRsType = (rtQuestion,rtAnswer,rtAuthority,rtAdditional);
  
  /// <summary>
  ///  Implements a DNS protocol handler to interpret and validate DNS messages captured by WinPcap.
  /// </summary>
  TWPcapProtocolDNS = Class(TWPcapProtocolBaseUDP)
  private
    CONST MAX_RSS_AND_QUESTIONS = 65535;
    class function GetQuestions(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;var aOffSetQuestion : Integer;aAdditionalParameters: PTAdditionalParameters):String;
  protected
    class function RSSTypeToString(const aRRsType: TRRsType): String; static;
    class procedure GetRSS(const aRRsType:TRRsType;const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aAdditionalParameters: PTAdditionalParameters;var aOffset : Integer);virtual;
    class function GetDNSClass(LDataQuestions: TBytes; aOffset: Integer): Uint8; virtual;
    class procedure ParserDNSClass(const aQuestionClass:String;const aRRsType:TRRsType;const aDataRss: TBytes; aInternalOffset,aStartLevel: Integer;AListDetail: TListHeaderString); virtual;
    class procedure ParserDNSTTL(const aQuestionClass:String;const aRRsType: TRRsType;const aDataRss: TBytes; aInternalOffset,aStartLevel: Integer;AListDetail: TListHeaderString); virtual;    
    class function ApplyConversionName(const aName: AnsiString): AnsiString; virtual;
    class function QClassToString(const aQClass: Uint8): String;virtual;     
    class function DecodeDNS_RSS_SRV(const aQuestionClass:String;const aRRsType:TRRsType;const aPacket: TBytes; var aOffset,aTotalNameLen: integer; AListDetail: TListHeaderString;aStartLevel:Integer): AnsiString; virtual;    
    class function DecodeDNS_RSS_NIMLOC(const aQuestionClass:String; const aRRsType:TRRsType;const aPacket: TBytes; var aOffset,aTotalNameLen: integer; AListDetail: TListHeaderString;aAdditionalParameters: PTAdditionalParameters;aStartLevel:Integer): AnsiString; virtual;
  public

    /// <summary>
    ///  Returns the default port number for the DNS protocol (53).
    /// </summary>
    class Function DefaultPort: word; override;

    /// <summary>
    /// Return Intenal protocol ID
    /// </summary>
    class function IDDetectProto: Uint8; override;
    
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
    class function ParseDNSName(const aPacket: TBytes;aMaxLen:Integer;var aOffset,aTotalNameLen: integer;aApplyyConversion:Boolean=True): AnsiString;
    
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
    class procedure GetDNSFlags(aFlags: Uint16;aStartLevel:Integer; AListDetail: TListHeaderString;aAdditionalParameters: PTAdditionalParameters);virtual;

    /// <summary>
    ///  Returns a string representation of a DNS question class.
    /// </summary>
    /// <param name="aType">
    ///   The DNS question class to convert.
    /// </param>
    /// <returns>
    ///   A string representation of the DNS question class.
    /// </returns>
    class function QuestionClassToStr(aType: Uint16): string;virtual;

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
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean; override;

    /// <summary>
    /// Checks whether the packet is valid for the protocol DNS.
    /// </summary>
    class function IsValid(const aPacket:PByte;aPacketSize:Integer; var aAcronymName: String;var aIdProtoDetected: byte): Boolean; override;    
  End;  
implementation

uses wpcap.level.IP;

{ TWPcapProtocolDNS }

class function TWPcapProtocolDNS.DefaultPort: word;
begin
  Result := PROTO_DNS_PORT;
end;

class function TWPcapProtocolDNS.IDDetectProto: Uint8;
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

class function TWPcapProtocolDNS.HeaderLength(aFlag:Byte): Word;
begin
  Result:= SizeOf(TDnsHeader)
end;

class function TWPcapProtocolDNS.Header(const aUDPPayLoad: PByte): PTDNSHeader;
begin
  Result := PTDNSHeader(aUDPPayLoad)
end;

Class function TWPcapProtocolDNS.QuestionClassToStr(aType:Uint16):String;
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
end;


class procedure TWPcapProtocolDNS.GetDNSFlags(aFlags: Uint16;aStartLevel:Integer;AListDetail:TListHeaderString;aAdditionalParameters: PTAdditionalParameters);  
var LtmpResult  : String;
    LByteValue  : Uint8;
    LByte0      : Uint8;
    LIsQuery    : Boolean;
begin
  LByte0 := GetByteFromWord(aFlags,0);

  {
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
  }

   
  //QR  A one bit field that specifies whether this message is a query (0), or a response (1).
  LByteValue := GetBitValue(LByte0,1);
  LIsQuery   := LByteValue = 0;
  if LIsQuery then
  begin
    aAdditionalParameters.Info := 'Query';
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.Type',[AcronymName]), 'Type:','Query',@LByte0,1, LByteValue ));
  end
  else
  begin
    aAdditionalParameters.Info := 'Response';
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.Type',[AcronymName]), 'Type:','Response',@LByte0,1,LByteValue ));       
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
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.OPCode',[AcronymName]), 'OPCode:',LtmpResult,@aFlags,2,(aFlags and $7800)));  

  {
  AA Authoritative Answer - this bit is valid in responses,
     and specifies that the responding name server is an
     authority for the domain name in question section.

     Note that the contents of the answer section may have
     multiple owner names because of aliases.  The AA bit
     corresponds to the name which matches the query name, or
     the first owner name in the answer section.
  }
  if not LIsQuery then
  begin
    LByteValue :=  GetBitValue(LByte0,6);
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.AuthoritativeAnswer',[AcronymName]), 'Authoritative answer:',LByteValue=1,@LByte0,1,LByteValue ));
  end;

  {
  TC  TrunCation - specifies that this message was truncated
      due to length greater than that permitted on the
      transmission channel.

  }
  LByteValue :=  GetBitValue(LByte0,7);
  AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.Truncated',[AcronymName]), 'Truncated:',LByteValue=1,@LByte0,1, LByteValue  ));

  {
  RD  Recursion Desired - this bit may be set in a query and
      is copied into the response.  If RD is set, it directs
      the name server to pursue the query recursively.
      Recursive query support is optional.
  }
  LByteValue :=  GetBitValue(LByte0,8);
  AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.RecursionDesired',[AcronymName]), 'Recursion Desired:',LByteValue=1,@LByte0,1, LByteValue ));

  {
  RA Recursion Available - this be is set or cleared in a
     response, and denotes whether recursive query support is
     available in the name server.
  }
  if not LIsQuery then
  begin
    LByte0     := GetByteFromWord(aFlags,1);
    LByteValue := GetBitValue(LByte0,1);
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.RecursionAvailable',[AcronymName]), 'Recursion available:',LByteValue=1, @LByte0,1, LByteValue ));
  end;

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
  if not LIsQuery then
  begin
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
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.ResponseCode',[AcronymName]), 'Response code:',LtmpResult.Replace('Response code:',String.Empty).Trim,@aFlags,2,(aFlags and $0070) ));
  end;
end;

class function TWPcapProtocolDNS.ParseDNSName(const aPacket: TBytes;aMaxLen:Integer; var aOffset,aTotalNameLen: integer;aApplyyConversion:Boolean=True): AnsiString;
CONST MAX_LEN_NAME_DNS = 255;
var LLen             : integer;
    LCompressPos     : integer;
    LCompressed      : boolean;
    LastOffset       : Integer;  
    LNewLen          : Integer;  
    LStartOffset     : Integer;
    LIsExtendedLabel : Boolean;
    LLabelLen        : Integer;
    LFixLenResult    : Integer;
begin
  Result           := String.Empty;
  LCompressed      := False;

  LCompressPos     := aOffset;
  LStartOffset     := aOffset;
  LastOffset       := -1;
  LLabelLen        := 0;
  LIsExtendedLabel := False;
  aTotalNameLen    := -1;
  while True do 
  begin
    if(aOffset - LStartOffset > MAX_LEN_NAME_DNS-1) then Break;

    LLen := aPacket[aOffset];
    if LLen > MAX_LEN_NAME_DNS then 
    begin
      DoLog('TWPcapProtocolDNS.ParseDNSName',Format('Length [%d] is greater than the maximum length of 255 characters',[LLen]),TWLLError);    
      break;
    end;

    if aTotalNameLen + LLen > MAX_LEN_NAME_DNS then
    begin
      DoLog('TWPcapProtocolDNS.ParseDNSName',Format('Length [%d] + current len [%d] is greater than the maximum length of 255 characters',[LLen,aTotalNameLen]),TWLLError);    
      break;
    end;
        
    if aOffset > aMaxLen then Break;
    
    case (LLen and $C0) of
      $C0  :
            begin
              // pointer to compressed name
              if not LCompressed then 
              begin
                // first compression, save current offset
                LCompressPos := aOffset;
                LCompressed  := True;
              end;
              // follow pointer
              if (aTotalNameLen < 0) then
              begin
                aTotalNameLen := aOffset+1 - LStartOffset;
                aOffset       := 0;//LStartOffset - ( ( (LLen and not $C0) shl 8 ) or aPacket[aOffset+1] ) - 9;
              end
              else
                aOffset :=  LStartOffset- ( ( (LLen and not $C0) shl 8 ) or aPacket[aOffset+1] );
               

              if aOffset < 0 then
              begin 
                Break;
              end;
            
              if( LastOffset > -1) and ( ( LastOffset+2 = aOffset) or ( LastOffset = aOffset)) then 
              begin
                aTotalNameLen := Length(Result);
                break;
              end;

              LastOffset       := aOffset;          
              LLen             := aPacket[aOffset];      
              LIsExtendedLabel := false;
            end;     
            
      $40:  begin 
               { // Extended label (RFC 2673)
                LIsExtendedLabel := True;
                LLabelLen        := aPacket[aOffset + 1];
                LLen             := 1;  }
            end;
            
      $80:  begin
              DoLog('TWPcapProtocolDNS.ParseDNSName','Invalid parser DNS name',TWLLError);         
              Break;
            end;
    end;
    
    Inc(aOffset);
    if LLen = 0 then 
    begin
      inc(aTotalNameLen,2);
      Break;
    end;
    
    if aTotalNameLen+LLen > aMaxLen then 
    begin
      DoLog('TWPcapProtocolDNS.ParseDNSName',Format( 'Invalid parser DNS name [Big total len] total len [%d] current len [%d] max len [%d]',[aTotalNameLen,LLen,aMaxLen]),TWLLError);         
      break;    
    end;

    if not Trim(String(Result)).IsEmpty then
      Result := AnsiString(Format('%s.',[Result]));
      
    if not LIsExtendedLabel  then
    begin
      LNewLen :=  Length(Result)+LLen -1;
      if (aOffset > 0) and (aOffset+LLen-1 <= aMaxLen) then
      begin
        SetLength(Result,LNewLen+1);  
        Move(aPacket[aOffset], Result[Length(Result) - LLen + 1], LLen);
        Result := System.AnsiStrings.StringReplace(Result,#0,'',[rfReplaceAll]) ;
      end;
    end
    else
    begin
      // Handle extended label
      if aOffset + LLabelLen - 1 <= aMaxLen then
      begin
        SetLength(Result, Length(Result) + LLabelLen + 1);
        Move(aPacket[aOffset], Result[Length(Result) - LLabelLen - 1], LLabelLen + 1);
        Result := System.AnsiStrings.StringReplace(Result, #0, '', [rfReplaceAll]);
      end;
    end;    

    Inc(aOffset, LLen);
    if LLen > 0 then    
      inc(aTotalNameLen,LLen);

    LIsExtendedLabel  := False;
  end;
  
  if LCompressed then
    aOffset := LCompressPos+2; // skip compressed name pointer         

  if (aTotalNameLen < 0) then
    aTotalNameLen := aOffset - LStartOffset;
    
  if aApplyyConversion then    
    Result := ApplyConversionName(Result);  

  LFixLenResult := Length(Result) - aTotalNameLen;  
  if LFixLenResult > 2 then
    DoLog('TWPcapProtocolDNS.ParseDNSName',Format('Invalid parser DNS name length result [%d] > calculate Length [%d]',[Length(Result), aTotalNameLen]),TWLLDebug)
  else if LFixLenResult > 0 then
    Inc(aTotalNameLen,LFixLenResult);       
  
end;

class function TWPcapProtocolDNS.ApplyConversionName(const aName:AnsiString):AnsiString;
begin
  {NO CONVERSION IN DNS protocol}
  Result := aName;
end;

class function TWPcapProtocolDNS.GetDNSClass(LDataQuestions: TBytes; aOffset: Integer): Uint8;
begin
  
  // Read the QClass field as a big-endian 16-bit integer
  Result := HIBYTE( wpcapntohs( (LDataQuestions[aOffset] shl 8) or LDataQuestions[aOffset+1]));
end;


class function TWPcapProtocolDNS.GetQuestions(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;var aOffSetQuestion : Integer;aAdditionalParameters: PTAdditionalParameters):String;
var LPUDPHdr        : PUDPHdr;
    LHeaderDNS      : PTDnsHeader;
    LDataQuestions  : TBytes;
    LUDPPayLoad     : PByte;
    LQType          : Uint16;    
    LQName          : string; 
    i               : Integer;    
    LCountQuestion  : Integer;  
    LTotalNameLen   : Integer;
    LLenQuestion    : Integer;
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
  LLenQuestion   := UDPPayLoadLength(LPUDPHdr)-HeaderLength(LHeaderDNS.Flags)-8;
  if LLenQuestion <= 0 then  exit;
  if not isValidLen(aOffSetQuestion,LLenQuestion,LCountQuestion)  then exit;
  
  SetLength(LDataQuestions,LLenQuestion);
  LDataQuestions := TBytes(LUDPPayLoad+HeaderLength(LHeaderDNS.Flags));
  LTotalNameLen  := 0;
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Questions.Query',[AcronymName]), 'Query',NULL,Pbyte(@LDataQuestions),Length(LDataQuestions)));              
  for i := 0 to LCountQuestion -1 do
  begin
    if aOffSetQuestion > LLenQuestion then  break;

    {
        QNAME  a domain name represented as a sequence of labels, where
               each label consists of a length octet followed by that
               number of octets.  The domain name terminates with the
               zero length octet for the null label of the root.  Note
               that this field may be an odd number of octets; no
               padding is used.
    }
  

    
    LQName := String(ParseDNSName(LDataQuestions,LLenQuestion,aOffSetQuestion,LTotalNameLen));
    AListDetail.Add(AddHeaderInfo(aStartLevel+2,Format('%s.Questions.Name',[AcronymName]), 'Name',LQName,nil,LQName.Length));  

    aAdditionalParameters.Info := Format('%s %s',[aAdditionalParameters.Info,LQName]);
    
    AListDetail.Add(AddHeaderInfo(aStartLevel+3,Format('%s.Questions.Name.Len',[AcronymName]), 'Name length',Max(LQName.Length,LTotalNameLen),nil,0));  

    {
      QTYPE  a two octet code which specifies the type of the query.
             The values for this field include all codes valid for a
             TYPE field, together with some more general codes which
             can match more than one type of RR.
    }
    LQType := Swap(PUint16(@LDataQuestions[aOffSetQuestion])^);
    AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Questions.Name.Type',[AcronymName]), 'Type:',QuestionClassToStr(LQType),PByte(@LDataQuestions[aOffSetQuestion]),2 ,LQType ));       
    Inc(aOffSetQuestion, SizeOf(Uint16));
    {
      QCLASS  a two octet code that specifies the class of the query.
              For example, the QCLASS field is IN for the Internet.
    }

    ParserDNSClass(QuestionClassToStr(LQType),rtQuestion,LDataQuestions,aOffSetQuestion,aStartLevel,AListDetail);
    Inc(aOffSetQuestion, SizeOf(Uint16));    
  end;  
end;

class function TWPcapProtocolDNS.QClassToString(const aQClass : Uint8):String;
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

class function TWPcapProtocolDNS.RSSTypeToString(const aRRsType : TRRsType):String;
begin
  case aRRsType of
    rtAnswer     : Result := 'Answer';
    rtAuthority  : Result := 'Authority';
    rtAdditional : Result := 'Additional';  
    rtQuestion   : Result := 'Questions'; 
  end;  
end;

class procedure TWPcapProtocolDNS.GetRSS(const aRRsType:TRRsType;const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aAdditionalParameters: PTAdditionalParameters;var aOffset : Integer);
var LPUDPHdr        : PUDPHdr;
    LHeaderDNS      : PTDnsHeader;
    LCountRss       : Integer;
    LDataRss        : TBytes;
    LUDPPayLoad     : PByte;
    LRssType        : Uint16;
    LRssTTL         : Uint16;
    LRssName        : AnsiString; 
    LAddress        : String;
    LCaption        : String;
    aLabelForName   : String;
    LQuestionClass  : String;
    i               : Integer;    
    J               : Integer;    
    LLength         : Integer;
    LRecordLength   : uint16;
    LTotalNameLen   : Integer;
    LInternalOffset : Integer;
    LIPAddr         : Uint32;
    LIPv6Addr       : TIPv6AddrBytes;   
    LEnrichment     : TWpcapEnrichmentType;
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

  
  LCountRss     := 0;
  LTotalNameLen := 0;
  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LUDPPayLoad := GetUDPPayLoad(aPacketData,aPacketSize);    
  LHeaderDNS  := Header(LUDPPayLoad);

  case aRRsType of
    rtAnswer     : LCountRss   := wpcapntohs(LHeaderDNS.AnswerRRs);
    rtAuthority  : LCountRss   := wpcapntohs(LHeaderDNS.AuthorityRRs);
    rtAdditional : LCountRss   := wpcapntohs(LHeaderDNS.AdditionalRRs);
  end;  
  
  if LCountRss = 0 then Exit;
  LLength := UDPPayLoadLength(LPUDPHdr)-HeaderLength(LHeaderDNS.Flags)-8;

  if LLength < 1 then Exit;
  
  
  SetLength(LDataRss,LLength);
  LDataRss := TBytes(LUDPPayLoad+HeaderLength(LHeaderDNS.Flags));

  aLabelForName  := Format('%s.%s',[AcronymName,RSSTypeToString(aRRsType)]);
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, aLabelForName, RSSTypeToString(aRRsType), NULL,nil,0 ));      
  
  LInternalOffset := aOffset;
  for i := 0 to LCountRss - 1 do
  begin
    if LInternalOffset > aPacketSize  then
    begin
      FisMalformed := True;
      Exit;
    end;
    LEnrichment := wetNone;
    {
      NAME an owner name, i.e., the name of the node to which this
           resource record pertains.                                            
    }
  
    LRssName := ParseDNSName(LDataRss,LLength, LInternalOffset,LTotalNameLen);
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Name',[aLabelForName]),'Name:', ifThen( System.AnsiStrings.Trim( LRssName) = '','<Root>',String(LRssName) ), nil, Length(LRssName) ));
    AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Len',[aLabelForName]), 'Name length:',LTotalNameLen,nil,0));    

    {TYPE  two octets containing one of the RR TYPE codes.}    
    LRssType       := Swap(Puint16(@LDataRss[LInternalOffset])^);
    LQuestionClass := QuestionClassToStr(LRssType);
    AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.%s.Type',[aLabelForName,LQuestionClass]), 'Type:',LQuestionClass , PByte(@LDataRss[LInternalOffset]), 2, LRssType ));
    Inc(LInternalOffset, SizeOf(Uint16));

    {CLASS two octets containing one of the RR CLASS codes.}

    ParserDNSClass(LQuestionClass,aRRsType,LDataRss,LInternalOffset,aStartLevel,AListDetail);
    Inc(LInternalOffset, SizeOf(Uint16));    
    
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
    
    ParserDNSTTL(LQuestionClass,aRRsType,LDataRss,LInternalOffset,aStartLevel,AListDetail);
    Inc(LInternalOffset, SizeOf(integer));

    {
      RDLENGTH  an unsigned 16 bit integer that specifies the length in
                octets of the RDATA field.
    }    
    LRecordLength := wpcapntohs(Puint16(@LDataRss[LInternalOffset])^);
    AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.%s.DataLen',[aLabelForName,LQuestionClass]), 'Data length:', LRecordLength,PByte(@LDataRss[LInternalOffset]), 2));    
    Inc(LInternalOffset, SizeOf(Uint16));

    {
      RDATA  a variable length string of octets that describes the
             resource.  The format of this information varies
             according to the TYPE and CLASS of the resource record.  
             }  
      LCaption := 'RDData';
      case LRssType of
      
        TYPE_DNS_QUESTION_A:
        begin

          LIPAddr  := wpcapntohl(PUint32(@LDataRss[LInternalOffset])^);
          LCaption := 'A address';
          LRssName := AnsiString(MakeUint32IntoIPv4AddressInternal(LIPAddr));
          if IsValidPublicIP(String(LRssName)) then
          begin
            LEnrichment                       := wetIP;          
            aAdditionalParameters.EnrichmentPresent := True;
          end;
          Inc(LInternalOffset, SizeOf(LIPAddr));
        end;
        
       TYPE_DNS_QUESTION_NS :
        begin
          LCaption := 'Name server';
          LRssName := ParseDNSName(LDataRss,LLength, LInternalOffset,LTotalNameLen,False);              
        end;

        TYPE_DNS_QUESTION_CNAME :
        begin
          LCaption := 'CNAME';
          LRssName := ParseDNSName(LDataRss,LLength, LInternalOffset,LTotalNameLen,False);            
        end;
        
        TYPE_DNS_QUESTION_AAAA:
        begin
          LIPv6Addr  := PTIPv6AddrBytes(@LDataRss[LInternalOffset])^;
          LCaption   := 'AAAA address';
          LRssName   := AnsiString(IPv6AddressToString(LIPv6Addr));
          if IsValidPublicIP(String(LRssName)) then
          begin
            LEnrichment                       := wetIP;          
            aAdditionalParameters.EnrichmentPresent := True;
          end;
          
          Inc(LInternalOffset, SizeOf(LIPv6Addr));
        end;
        
        TYPE_DNS_QUESTION_MX:
        begin
          LRssTTL := wpcapntohl(Pinteger(@LDataRss[LInternalOffset])^);
          AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.%s.TTL',[aLabelForName,LQuestionClass]), 'Time to live MX:', Format('%d seconds', [LRssTTL]),PByte(@LDataRss[LInternalOffset]), 4));    
          Inc(LInternalOffset, SizeOf(Pinteger));
          LRssName := ParseDNSName(LDataRss,LLength, LInternalOffset,LTotalNameLen);
        end;
        
        TYPE_DNS_QUESTION_SRV    : LRssName := DecodeDNS_RSS_SRV(LQuestionClass,aRRsType,LDataRss,LInternalOffset,LTotalNameLen,AListDetail,aStartLevel);
        TYPE_DNS_QUESTION_NIMLOC : LRssName := DecodeDNS_RSS_NIMLOC(LQuestionClass,aRRsType,LDataRss,LInternalOffset,LTotalNameLen,AListDetail,aAdditionalParameters,aStartLevel);       
      else
        LRssName := ParseDNSName(LDataRss,LLength, LInternalOffset,LTotalNameLen,False);
      end;

     if Trim(LRssName) <> '' then
        AListDetail.Add(AddHeaderInfo(aStartLevel+3,Format('%s.%s.%s',[aLabelForName,LQuestionClass,LCaption.Replace(' ','')]), Format('%s:',[LCaption]),String(LRssName), @LRssName, Length(LRssName)-1, -1 ,LEnrichment));
  end;
  Inc(aOffset,LInternalOffset-aOffset);
end;

class function TWPcapProtocolDNS.DecodeDNS_RSS_NIMLOC(const aQuestionClass:String; const aRRsType:TRRsType;const aPacket: TBytes; var aOffset,aTotalNameLen: integer;AListDetail: TListHeaderString;aAdditionalParameters: PTAdditionalParameters;aStartLevel:Integer): AnsiString;
begin
  Result := ParseDNSName(aPacket,Length(aPacket), aOffset,aTotalNameLen);
end;

class function TWPcapProtocolDNS.DecodeDNS_RSS_SRV(const aQuestionClass:String;const aRRsType:TRRsType;const aPacket: TBytes; var aOffset,aTotalNameLen: integer;AListDetail: TListHeaderString;aStartLevel:Integer): AnsiString;
var LRssTTL : Uint16;
begin
  LRssTTL := wpcapntohl(Pinteger(@aPacket[aOffset])^);
  Inc(aOffset, SizeOf(Pinteger));
          
  AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.%s.Name.TTLMX',[AcronymName,RSSTypeToString(aRRsType),aQuestionClass]), 'Time to live MX:', Format('%d seconds', [LRssTTL]),PByte(@aPacket[aOffset]), 4)); 
  Result := ParseDNSName(aPacket,Length(aPacket), aOffset,aTotalNameLen);
end;

Class procedure TWPcapProtocolDNS.ParserDNSClass(const aQuestionClass:String;const aRRsType:TRRsType;const aDataRss:TBytes;aInternalOffset,aStartLevel:Integer;AListDetail: TListHeaderString);
var LRssClass : Uint16;
begin
   if not Assigned(AListDetail) then exit;

  LRssClass := GetDNSClass(aDataRss,aInternalOffset);
  AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.%s.Name.Class',[AcronymName,RSSTypeToString(aRRsType),aQuestionClass]), 'Class:',QClassToString(LRssClass), PByte(@aDataRss[aInternalOffset]), 2));    
end;

class procedure TWPcapProtocolDNS.ParserDNSTTL(const aQuestionClass:String;const aRRsType: TRRsType;const aDataRss: TBytes; aInternalOffset,aStartLevel: Integer;AListDetail: TListHeaderString);
begin
  AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.%s.Name.TTL',[AcronymName,RSSTypeToString(aRRsType),aQuestionClass]),  'Time to live:', Format('%d seconds', [wpcapntohl(PInteger(@aDataRss[aInternalOffset])^)]),PByte(@aDataRss[aInternalOffset]), 4));    
end;

class function TWPcapProtocolDNS.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean;
var LHeaderDNS        : PTDnsHeader;
    LCountQuestion    : Integer;
    LCOuntAnswer      : Integer;
    LCountAuthority   : Integer;
    LUDPPayLoad       : PByte;
    LPayLoadLen       : Integer;
    LPUDPHdr          : PUDPHdr;
    LcountAddRrs      : Integer;
    LOffSetQuestion   : Integer;
    LSessionID        : Uint16;
    LBckInfo          : String;
    LInternalIP       : TInternalIP;
begin
  Result := False;
  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LUDPPayLoad      := GetUDPPayLoad(aPacketData,aPacketSize);
  LPayLoadLen      := UDPPayLoadLength(LPUDPHdr)-8;
  LHeaderDNS       := Header(LUDPPayLoad);
  FIsFilterMode    := aIsFilterMode;
    
  LCountQuestion   := wpcapntohs(LHeaderDNS.Questions);
  LcountAddRrs     := wpcapntohs(LHeaderDNS.AdditionalRRs);
  LCountAnswer     := wpcapntohs(LHeaderDNS.AnswerRRs);
  LCountAuthority  := wpcapntohs(LHeaderDNS.AuthorityRRs);   
  LSessionID       := wpcapntohs(LHeaderDNS.ID);
  LBckInfo         := aAdditionalParameters.Info;
  AListDetail.Add(AddHeaderInfo(aStartLevel, AcronymName, Format('%s (%s)',[ProtoName,AcronymName]),NULL, LUDPPayLoad,LPayLoadLen ));            
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.ID',[AcronymName]), 'Session ID:',LSessionID,PByte(@LHeaderDNS.ID),SizeOf(LHeaderDNS.ID)));        
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Flags',[AcronymName]), 'Flags:',Format('%s %s',[ByteToBinaryString(GetByteFromWord(LHeaderDNS.Flags,0)),
                                                                                                          ByteToBinaryString(GetByteFromWord(LHeaderDNS.Flags,1))]),
                  PByte(@LHeaderDNS.Flags), SizeOf(LHeaderDNS.Flags) ,LHeaderDNS.Flags));    

  if IsFilterMode then  
  begin
    TWpcapIPHeader.InternalIP(aPacketData,aPacketSize,nil,@LInternalIP,False,False);
    UpdateFlowInfo(LSessionID.ToString,LInternalIP.Src,LInternalIP.Dst,SrcPort(LPUDPHdr),DstPort(LPUDPHdr),0,aAdditionalParameters);
  end;                      
  
  GetDNSFlags(LHeaderDNS.Flags,aStartLevel,AListDetail,aAdditionalParameters);  
  aAdditionalParameters.Info := Format('%s Session ID %d',[aAdditionalParameters.Info,LSessionID]);    
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Questions',[AcronymName]), 'Questions:',LCountQuestion,PByte(@LHeaderDNS.Questions),SizeOf(LHeaderDNS.Questions) ));      
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.AnswerRRs',[AcronymName]), 'Answer RRs:',LCountAnswer,PByte(@LHeaderDNS.AnswerRRs),SizeOf(LHeaderDNS.AnswerRRs) ));
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.AuthorityRRs',[AcronymName]), 'Authority RRs:',LCountAuthority,PByte(@LHeaderDNS.AuthorityRRs),SizeOf(LHeaderDNS.AuthorityRRs) )); 
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.AdditionalRRs',[AcronymName]), 'Additional RRs:',LcountAddRrs,PByte(@LHeaderDNS.AdditionalRRs),SizeOf(LHeaderDNS.AdditionalRRs) ));       

  {QUESTION}
  LOffSetQuestion := 0;
  if ( LCountQuestion > 0) and (LCountQuestion <= MAX_RSS_AND_QUESTIONS) then
    GetQuestions(aPacketData,aPacketSize,aStartLevel,AListDetail,LOffSetQuestion,aAdditionalParameters);
   
  {ANSWER}
  if LCountAnswer > 0 then
    GetRSS(rtAnswer,aPacketData,aPacketSize,aStartLevel,AListDetail,aAdditionalParameters,LOffSetQuestion);

  {AUTHORITY}
  if LCountAuthority > 0 then
    GetRSS(rtAuthority,aPacketData,aPacketSize,aStartLevel,AListDetail,aAdditionalParameters,LOffSetQuestion);
  
  {Additional Record} 
  if LcountAddRrs > 0 then
    GetRSS(rtAdditional,aPacketData,aPacketSize,aStartLevel,AListDetail,aAdditionalParameters,LOffSetQuestion);

   aAdditionalParameters.Info := Format('%s %S',[aAdditionalParameters.Info,LBckInfo]);               
  Result := True;
end;

class function TWPcapProtocolDNS.IsValid(const aPacket: PByte;aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: byte): Boolean;  
begin
  Result := inherited IsValid(aPacket,aPacketSize,aAcronymName,aIdProtoDetected);
end;

end.
