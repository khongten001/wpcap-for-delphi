unit wpcap.Protocol.MDNS;

interface

uses
  wpcap.Protocol.DNS, wpcap.Conts, System.SysUtils,wpcap.Types,wpcap.BufferUtils,Winapi.Windows;

type
   {https://tools.ietf.org/html/rfc6762}
  
  /// <summary>
  ///  mDNS (Multicast DNS) protocol class, subclass of TWPcapProtocolDNS.
  /// </summary>
  TWPcapProtocolMDNS = Class(TWPcapProtocolDNS)
  private
    class function IsMulticastIPv6Address(const aAddress: TIPv6AddrBytes): Boolean; static;

  protected
    class procedure ParserDNSClass(const aRRsType:TRRsType;const aDataRss: TBytes; aInternalOffset: Integer;AListDetail: TListHeaderString);override;
    class procedure ParserDNSTTL(const aRRsType: TRRsType;const aDataRss: TBytes; aInternalOffset: Integer;AListDetail: TListHeaderString); override;
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
    //  It takes a pointer to the packet data and an integer representing the size of the packet as parameters, and returns a dictionary of strings.
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

    {224.0.0.251 IP to be test for Ipv4}
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

class procedure TWPcapProtocolMDNS.ParserDNSTTL(const aRRsType:TRRsType;const aDataRss: TBytes; aInternalOffset: Integer;AListDetail: TListHeaderString);
var Lz         : Word;
    LWordValue : Word;
begin

  case aRRsType of
    rtAnswer     : inherited; 
    rtAuthority  : inherited;
    rtAdditional : 
      begin
        Lz          := (aDataRss[aInternalOffset] shl 8) or aDataRss[aInternalOffset+1];
        LWordValue  := ( Lz  and $7FFF);
        AListDetail.Add(AddHeaderInfo(3, 'Higher bits in extended RCODE:',aDataRss[aInternalOffset], PByte(@aDataRss[aInternalOffset]), 2));              
        inc(aInternalOffset,1);
        AListDetail.Add(AddHeaderInfo(3, 'EDNS0 version:',aDataRss[aInternalOffset], PByte(@aDataRss[aInternalOffset]), 1));              
        inc(aInternalOffset,1);
        Lz         := (aDataRss[aInternalOffset] shl 8) or aDataRss[aInternalOffset+1];
        LWordValue  := ( ( Lz  and $7FFF));
      
        AListDetail.Add(AddHeaderInfo(3, 'Z:',Lz, PByte(@aDataRss[aInternalOffset]), 2));
        AListDetail.Add(AddHeaderInfo(4, 'Reserved:',LWordValue, PByte(@aDataRss[aInternalOffset]), 2));
        AListDetail.Add(AddHeaderInfo(4, 'Do bit:',GetBitValue(aDataRss[aInternalOffset],1), PByte(@aDataRss[aInternalOffset]), 2));

      end;
  end;
end;

class procedure TWPcapProtocolMDNS.ParserDNSClass(const aRRsType:TRRsType;const aDataRss: TBytes; aInternalOffset: Integer;AListDetail: TListHeaderString);
var aClass  : TBytes;
    LQClass : Word;
begin
  case aRRsType of
    rtAnswer     : inherited; 
    rtAuthority  : inherited;
    rtAdditional : 
      begin
        LQClass  := (aDataRss[aInternalOffset] shl 8) or aDataRss[aInternalOffset+1];
        LQClass  := ( LQClass  and $7FFF);      
        AListDetail.Add(AddHeaderInfo(3, 'UDP payload size:',LQClass, PByte(@aDataRss[aInternalOffset]), 2));    
        AListDetail.Add(AddHeaderInfo(3, 'Cache flush:',GetBitValue(aDataRss[aInternalOffset],1)=1, PByte(@aDataRss[aInternalOffset]), 2));   
      end;
    rtQuestion   : 
      begin

        {
         To avoid large floods of potentially unnecessary responses in these
         cases, Multicast DNS defines the top bit in the class field of a DNS
         question as the unicast-response bit.  When this bit is set in a
         question, it indicates that the querier is willing to accept unicast
         replies in response to this specific query, as well as the usual
         multicast responses.  These questions requesting unicast responses
         are referred to as "QU" questions, to distinguish them from the more
         usual questions requesting multicast responses ("QM" questions).  A
         Multicast DNS querier sending its initial batch of questions
         immediately on wake from sleep or interface activation SHOULD set the
         unicast-response bit in those questions.
        }

        LQClass  := (aDataRss[aInternalOffset] shl 8) or aDataRss[aInternalOffset+1];
        LQClass  := wpcapntohs( LQClass  and $7FFF);      
        AListDetail.Add(AddHeaderInfo(3, 'Class:',QClassToString(LQClass), PByte(@aDataRss[aInternalOffset]), 2));   
        AListDetail.Add(AddHeaderInfo(3, 'QU:',GetBitValue(aDataRss[aInternalOffset],1)=1, PByte(@aDataRss[aInternalOffset]), 2));
      end;
  end;
end;

end.
