unit wpcap.Protocol.DNS;

interface                                  

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Protocol.UDP, System.SysUtils,Variants,
  wpcap.Types, WinSock,System.StrUtils;

type
  TDnsHeader = packed record
    id           : Word; // identification number 2 bytes
    Flags        : Word;
    Questions    : Word;  // Number of questions in the Question Section
    AnswerRRs    : Word;  // Number of resource records in the Answer Section
    AuthorityRRs : Word;  // Number of resource records in the Authority Section
    AdditionalRRs: Word;  // Number of resource records in the Additional Section
    QueryRRs     : Word;  // Number of resource records in the Query Section
  end;
  PTDNSHeader =^TDNSHeader;
  
  /// <summary>
  ///  Implements a DNS protocol handler to interpret and validate DNS messages captured by WinPcap.
  /// </summary>
  TWPcapProtocolDNS = Class(TWPcapProtocolBaseUDP)
  private


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
    class function HeaderLength: word; override;

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
    class function ParseDNSName(const AData: TBytes; var AOffset: Integer): string; static;

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
    class function GetDNSFlags(Flags: Word; AListDetail: TListHeaderString): string; static;

    /// <summary>
    ///  Returns a string representation of a DNS question class.
    /// </summary>
    /// <param name="aType">
    ///   The DNS question class to convert.
    /// </param>
    /// <returns>
    ///   A string representation of the DNS question class.
    /// </returns>
    class function QuestionClassToStr(aType: Word): string; static;

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

class function TWPcapProtocolDNS.HeaderLength: word;
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
  end;
  Result := Format('%s (%d)',[Result,aType]);
end;


class function TWPcapProtocolDNS.GetDNSFlags(Flags: Word;AListDetail:TListHeaderString): string;

  Procedure AddHeaderInfo(const aDescription,aValue:Variant);
  var LHederInfo : THeaderString;
  begin
    if not Assigned(AListDetail) then Exit;
    
    LHederInfo.Description := aDescription;
    LHederInfo.Value       := aValue;
    LHederInfo.Hex         := String.Empty;
    LHederInfo.Level       := 2;
    AListDetail.Add(LHederInfo);   
  end;
  
var tmpResult : String;  
begin
  Result := '';
  if (Flags and $8000) = $8000 then
  begin
    Result := 'Query'; // Message is a query
    AddHeaderInfo('Type:','Query');
  end  
  else
  begin
    Result := 'Response'; // Message is a response
    AddHeaderInfo('Type:','Response');       
  end;

  tmpResult := String.Empty;
  case (Flags and $7800) of
    $7800 : tmpResult := 'Standard query'; // Standard query
    $0000 : tmpResult := 'Query (Inverse/Reverse)'; // Inverse query
    $1000 : tmpResult := 'Server status request'; // Server status request
    $2000 : tmpResult := 'Reserved'; // Reserved
  end;

  if not tmpResult.IsEmpty then
  begin
    Result := Format('%s, %s',[Result,tmpResult]);
    AddHeaderInfo('Query type:',tmpResult);  
  end;

  if (Flags and $0400) = $0400 then
  begin
    Result := Result + ', Authoritative answer';
    AddHeaderInfo('Authoritative answer:',True);  
  end
  else
    AddHeaderInfo('Authoritative answer:',False);    

  if (Flags and $0200) = $0200 then
  begin
    Result := Result + ', Truncated'; 
    AddHeaderInfo('Truncated:',True);  
  end
  else
    AddHeaderInfo('Truncated:',False);

  if (Flags and $0100) = $0100 then
  begin
    Result := Result + ', Recursion desired';
    AddHeaderInfo('Recursion desired:',True);     
  end
  else
    AddHeaderInfo('Recursion desired:',False);
  
  if (Flags and $0080) = $0080 then
  begin
    Result := Result + ', Recursion available';
    AddHeaderInfo('Recursion available:',True);
  end
  else
    AddHeaderInfo('Recursion available:',False);

  tmpResult := String.Empty;
  case (Flags and $0070) of
    $0000:     tmpResult := 'Response code: No error';        // No error condition
    $0010:     tmpResult := 'Response code: Format error';    // The name server was unable to interpret the query
    $0020:     tmpResult := 'Response code: Server failure';  // The name server was unable to process this query due to a problem with the name server
    $0030:     tmpResult := 'Response code: Name error';      // Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist
    $0040:     tmpResult := 'Response code: Not implemented'; // The name server does not support the requested kind of query
    $0050:     tmpResult := 'Response code: Refused';         // The name server refuses to perform the specified operation for policy reasons
  end;
  
  if not tmpResult.IsEmpty then
  begin
    Result := Format('%s, %s',[Result,tmpResult]);
    AddHeaderInfo('Response code:',tmpResult.Replace('Response code:',String.Empty).Trim);  
  end;  
  Result := Result.TrimLeft([',']);
end;

class function TWPcapProtocolDNS.HeaderToString(const aPacketData: PByte;aPacketSize: Integer; AListDetail: TListHeaderString): Boolean;
var LHeaderDNS        : PTDnsHeader;
    LCountQuestion    : Integer;
    LUDPPayLoad       : PByte;
    LDataMDNS         : TBytes;
    LOffSetQuestion   : Integer;
    i                 : Integer;
    J                 : Integer;    
    LName             : string;  
    LPUDPHdr          : PUDPHdr;
    LType             : Word;
    LClass            : Word;
    LRecordLength     : word; 
    LcountAddRrs      : Integer;
    LTTL              : Integer;
    LAddress          : String;
begin
  Result := False;
  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;
  LUDPPayLoad := GetUDPPayLoad(aPacketData,aPacketSize);

  LHeaderDNS     := Header(LUDPPayLoad);
  LCountQuestion := ntohs(LHeaderDNS.Questions);
  LcountAddRrs   := ntohs(LHeaderDNS.AdditionalRRs);  
  AListDetail.Add(AddHeaderInfo(0,Format('%s (%s)',[ProtoName,AcronymName]),NULL,PByte(LHeaderDNS),HeaderLength));            
  AListDetail.Add(AddHeaderInfo(1,'ID:',ntohs(LHeaderDNS.ID),PByte(@LHeaderDNS.ID),SizeOf(LHeaderDNS.ID)));      
  
  AListDetail.Add(AddHeaderInfo(1,'Flags:',ntohs(LHeaderDNS.Flags),PByte(@LHeaderDNS.Flags),SizeOf(LHeaderDNS.Flags)));      
  GetDNSFlags(LHeaderDNS.Flags,AListDetail);  

  AListDetail.Add(AddHeaderInfo(1,'Questions:',LCountQuestion,PByte(@LHeaderDNS.Questions),SizeOf(LHeaderDNS.Questions)));      
  AListDetail.Add(AddHeaderInfo(1,'Answer RRs:',ntohs(LHeaderDNS.AnswerRRs),PByte(@LHeaderDNS.AnswerRRs),SizeOf(LHeaderDNS.AnswerRRs)));
  AListDetail.Add(AddHeaderInfo(1,'Authority RRs:',ntohs(LHeaderDNS.AuthorityRRs),PByte(@LHeaderDNS.AuthorityRRs),SizeOf(LHeaderDNS.AuthorityRRs)));     
  AListDetail.Add(AddHeaderInfo(1,'Query RRs:',ntohs(LHeaderDNS.QueryRRs),PByte(@LHeaderDNS.QueryRRs),SizeOf(LHeaderDNS.QueryRRs)));            

  LOffSetQuestion := 0;
  SetLength(LDataMDNS,UDPPayLoadLength(LPUDPHdr)-HeaderLength-2);
  LDataMDNS := TBytes(LUDPPayLoad+HeaderLength-2);
  for i := 0 to LCountQuestion -1 do
  begin

    LName := ParseDNSName(LDataMDNS,LOffSetQuestion);
    
    LType := Swap(PWord(@LDataMDNS[LOffSetQuestion])^);
    Inc(LOffSetQuestion, SizeOf(Word));

    LClass := Swap(PWord(@LDataMDNS[LOffSetQuestion])^);
    Inc(LOffSetQuestion, SizeOf(Word));    
    
    if (LType = TYPE_DNS_QUESTION_A) or (LType = TYPE_DNS_QUESTION_AAAA) then
    begin
      {TODO BUG Position next }
      LRecordLength := Swap(PWord(@LDataMDNS[LOffSetQuestion])^);
      Inc(LOffSetQuestion,LRecordLength);
    end;    
    
    if not LName.Trim.IsEmpty and (LType >0) then
    begin
      AListDetail.Add(AddHeaderInfo(2,'Name',LName,nil,0));   
      if LType <> 0 then
        AListDetail.Add(AddHeaderInfo(3,'Type:',QuestionClassToStr(LType),nil,0));  
      if LClass <> 0 then
        AListDetail.Add(AddHeaderInfo(3,'Class:',ifthen(LClass=1,'IN (1)',LClass.ToString),nil,0));  
    end;   
  end;  
  
  AListDetail.Add(AddHeaderInfo(1,'Additional RRs:',LcountAddRrs,PByte(@LHeaderDNS.AdditionalRRs),SizeOf(LHeaderDNS.AdditionalRRs)));              
  if LcountAddRrs > 0 then
  begin
    for i := 0 to LCountAddRrs - 1 do
    begin
      LName := ParseDNSName(LDataMDNS, LOffSetQuestion);
      LType := Swap(PWord(@LDataMDNS[LOffSetQuestion])^);
      Inc(LOffSetQuestion, SizeOf(Word));
      LTTL := Swap(PInteger(@LDataMDNS[LOffSetQuestion])^);
      Inc(LOffSetQuestion, SizeOf(Integer));
      LRecordLength := Swap(PWord(@LDataMDNS[LOffSetQuestion])^);
      Inc(LOffSetQuestion, SizeOf(Word));

      AListDetail.Add(AddHeaderInfo(2, 'Name', ifThen(LName.IsEmpty,'<Root>',LName), nil, 0));
      if LType <> 0 then
        AListDetail.Add(AddHeaderInfo(3, 'Type:', QuestionClassToStr(LType), nil, 0));
      if LTTL <> 0 then
        AListDetail.Add(AddHeaderInfo(3, 'TTL:', Format('%d seconds', [LTTL]), nil, 0));

      AListDetail.Add(AddHeaderInfo(3, 'Data length:', LRecordLength, nil, 0));

      case LType of
        TYPE_DNS_QUESTION_A:
        begin
          if LRecordLength = 4 then
          begin
            LAddress := Format('%d.%d.%d.%d', [LDataMDNS[LOffSetQuestion], LDataMDNS[LOffSetQuestion + 1], LDataMDNS[LOffSetQuestion + 2], LDataMDNS[LOffSetQuestion + 3]]);
            AListDetail.Add(AddHeaderInfo(3, 'Address:', LAddress, nil, 0));
          end;
          Inc(LOffSetQuestion, LRecordLength);
        end;
        TYPE_DNS_QUESTION_AAAA:
        begin
          if LRecordLength = 16 then
          begin
            LAddress := '';
            for j := 0 to 7 do
              LAddress := LAddress + Format('%x', [Swap(PWord(@LDataMDNS[LOffSetQuestion + j * 2])^)]) + ':';
            SetLength(LAddress, Length(LAddress) - 1);
            AListDetail.Add(AddHeaderInfo(3, 'Address:', LAddress, nil, 0));
          end;
          Inc(LOffSetQuestion, LRecordLength);
        end;
      else
        Inc(LOffSetQuestion, LRecordLength);
      end;
    end;

  end;
  Result := True;
end;

class function TWPcapProtocolDNS.ParseDNSName(const AData: TBytes; var AOffset: Integer): string;
var LNameLen      : Integer;
     LPos         : Integer;
     LText        : String;
     LIsFirstLabel: Boolean;
begin
  Result        := String.Empty;
  LPos          := AOffset;
  LIsFirstLabel := True;
  while True do
  begin
    LNameLen := AData[LPos];

    if LNameLen= 0 then 
    begin
      Inc(LPos);
      break;
    end;
        
    if (LNameLen and $C0) = $C0  then
    begin
      Inc(LPos,2);{compressed domain names}
      break;
    end
    else
    begin
      Inc(LPos);
      Try
        LText := TEncoding.Ansi.GetString(AData, LPos, LNameLen);
      Except 
        LText := Format('Error Pos [%d] data [%d] Len name [%d]',[Lpos,aData[Lpos],LNameLen]);
      End;
      if not LText.Trim.IsEmpty then
      begin
        if LIsFirstLabel then
          LIsFirstLabel := False
        else
          Result := Result + '.';
        Result := Result + LText;
      end;
      Inc(LPos, LNameLen);          
    end;
  end;
  AOffset := LPos;
end;

end.
