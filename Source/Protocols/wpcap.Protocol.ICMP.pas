unit wpcap.Protocol.ICMP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,System.Classes,
  System.Variants, wpcap.BufferUtils,WinSock,WinSock2,wpcap.IpUtils;

type

  {  https://www.rfc-editor.org/rfc/rfc792
  
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |    Code     |  Checksum of Header ICMP        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Data....
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  }

  TICMPHeader = record
     TypeICMP   : Byte;
     Code       : Byte;
     CheckSum   : Word; 
     ICMP_Unused: Longword    
  end;  
  PTICMPHeader = ^TICMPHeader;
  
  /// <summary>
  /// The ICMP protocol implementation class.
  /// </summary>
  TWPcapProtocolICMP = Class(TWPcapProtocolBase)
  private
    CONST
    
    ICMP_ECHO_REPLY                           = 0;
    ICMP_DEST_UNREACHABLE_IPv6                = 1;
    ICMP_DEST_UNREACHABLE                     = 3;
    ICMP_SOURCE_QUENCH                        = 4;
    ICMP_REDIRECT_MESSAGE                     = 5;
    ICMP_ALTERNATE_HOST_ADDRESS               = 6;
    ICMP_ECHO_REQUEST                         = 8;
    ICMP_ROUTER_ADVERTISEMENT                 = 9;
    ICMP_ROUTER_SELECTION                     = 10;
    ICMP_TIME_EXCEEDED                        = 11;
    ICMP_PARAMETER_PROBLEM                    = 12;
    ICMP_TIMESTAMP_REQUEST                    = 13;
    ICMP_TIMESTAMP_REPLY                      = 14;
    ICMP_INFORMATION_REQUEST                  = 15;
    ICMP_INFORMATION_REPLY                    = 16;
    ICMP_ADDRESS_MASK_REQUEST                 = 17;
    ICMP_ADDRESS_MASK_REPLY                   = 18;
    ICMP_TRACEROUTE                           = 30;
    ICMP_CONVERSION_ERROR                     = 31;
    ICMP_MOBILE_REDIRECT                      = 32;
    ICMP_IPV6_WHERE_ARE_YOU                   = 33;
    ICMP_IPV6_I_AM_HERE                       = 34;
    ICMP_MOBILE_REG_REQUEST                   = 35;
    ICMP_MOBILE_REG_REPLY                     = 36;
    ICMP_DOMAIN_NAME_REQUEST                  = 37;
    ICMP_DOMAIN_NAME_REPLY                    = 38;
    ICMP_MULTICAST_LISTENER_REPORT            = 131;
    ICMP_ROUTER_SOLICITATION                  = 133;
    ICMP_NEIGHBOR_SOLICITATION                = 135;
    ICMP_NEIGHBOR_ADVERTISEMENT               = 136;
    ICMP_MULTICAST_LISTENER_REPORT_MESSAGE_V2 = 143;    

  
    class function CodeToString(const aType, Code: Byte): String; static;
    class function GetNextIpHeader(const aPacketData: PByte; aPacketSize,
      aHeaderPrevLen: Integer; var aNewPacketLen: Integer): PByte; static;
    class function ConvertOptionsToString(aOptions: Integer): string; static;
    class function ConvertRecordTypeToString(const aRecordType: Uint8): string;
  public
    /// <summary>
    /// Returns the default ICMP 0 - No port.
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the ICMP protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the ICMP protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    ///  Returns the length of the ICMP header.
    /// </summary>
    class function HeaderLength(aFlag:Byte): word; override;

    /// <summary>
    ///  Returns a pointer to the ICMP header.
    /// </summary>
    class function Header(const aData: PByte; aSize: Integer;var aICMPHeader: PTICMPHeader): Boolean; static;    
    /// <summary>
    /// Returns the acronym name of the ICMP protocol.
    /// </summary>
    class function AcronymName: String; override;
    class Function TypeToString(const aType:Byte):String;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; static;
    class function HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean; override;      
  end;


implementation

uses wpcap.Level.IP;


{ TWPcapProtocolMDNS }
class function TWPcapProtocolICMP.DefaultPort: Word;
begin
  Result := 0;
end;

class function TWPcapProtocolICMP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_ICMP
end;

class function TWPcapProtocolICMP.ProtoName: String;
begin
  Result := 'Internet Control Message Protocol';
end;

class function TWPcapProtocolICMP.AcronymName: String;
begin
  Result := 'ICMP';
end;

class function TWPcapProtocolICMP.IsValid(const aPacket: PByte;aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var aIPClass : TIpClaseType;  
begin
  result := True;
  aIPClass:= IpClassType(aPacket,aPacketSize); 
  if aIPClass = imtIpv6 then
  begin
      if result then
      begin
        aAcronymName     := Format('%sv6',[AcronymName]);
        aIdProtoDetected := IDDetectProto;
      end;      
  end;
end;

class Function TWPcapProtocolICMP.GetNextIpHeader(const aPacketData: PByte;aPacketSize,aHeaderPrevLen: Integer;var aNewPacketLen: Integer):PByte;
var lHeaderEthLen    : Integer;
begin
  if aHeaderPrevLen = 0 then
      aHeaderPrevLen := TWpcapIPHeader.HeaderIPSize(aPacketData,aPacketSize)+HeaderLength(0);
      
  lHeaderEthLen  := HeaderEthSize;
  aNewPacketLen  := aPacketSize -aHeaderPrevLen; 
  GetMem(Result,aNewPacketLen);
  Move(aPacketData^,Result^,lHeaderEthLen);
  Move(PByte(aPacketData + lHeaderEthLen + aHeaderPrevLen)^,Pbyte(Result + lHeaderEthLen)^, aNewPacketLen- lHeaderEthLen);
end;

  
class function TWPcapProtocolICMP.HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer;AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;
var LHeader         : PTICMPHeader;
    LNewPacketData  : Pbyte;
    LNewPacketLen   : Integer;
    SourceAddress   : TIPv6AddrBytes; 
    LAllHeaderSize  : Integer;
    LOptions        : Byte;
    LOptionsW       : Word;
    LCount          : Word;
    LLink           : TArray<Byte>;
    LCurrentPos     : Integer;
    I               : Integer;
begin
  Result        := False;
  FisFilterMode := aIsFilterMode;
  
  if not Header(aPacketData,aPacketSize,LHeader) then exit;

  AListDetail.Add(AddHeaderInfo(aStartLevel, AcronymName ,Format('%s (%s)',[ProtoName,AcronymName]),NULL, PByte(LHeader),HeaderLength(0)));            
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Type',[AcronymName]), 'Type:',TypeToString(LHeader.TypeICMP), @LHeader.TypeICMP,sizeOf(LHeader.TypeICMP), LHeader.TypeICMP ));
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.HeaderLen',[AcronymName]), 'Code:',CodeToString(LHeader.TypeICMP,LHeader.Code), @LHeader.Code,sizeOf(LHeader.Code), LHeader.Code ));            
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.HeaderLen',[AcronymName]), 'Checksum:',wpcapntohs(LHeader.CheckSum) ,@LHeader.CheckSum,sizeOf(LHeader.CheckSum) )); 
  
  case LHeader.TypeICMP  of
    ICMP_NEIGHBOR_ADVERTISEMENT :
      begin
        LOptions := GetByteFromWord(GetWordFromCardinal(LHeader.ICMP_Unused,0),0);
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.FlagsICMPV6',[AcronymName]), 'Flags ICMPV6:',Format('%s %s',[ByteToBinaryString(LOptions),
                                                                                                                             ByteToBinaryString(GetByteFromWord(LHeader.ICMP_Unused,1))]),
                                      @LHeader.ICMP_Unused, SizeOf(LHeader.ICMP_Unused) ));
                                      
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.FlagsICMPV6.Router',[AcronymName]), 'Router:',GetBitValue(LOptions,1)=1, @LOptions,SizeOf(LOptions), GetBitValue(LOptions,1) ));
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.FlagsICMPV6.Solecited',[AcronymName]), 'Solecited:',GetBitValue(LOptions,2)=1, @LOptions,SizeOf(LOptions), GetBitValue(LOptions,2) ));
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.FlagsICMPV6.Override',[AcronymName]), 'Override:',GetBitValue(LOptions,3)=1, @LOptions,SizeOf(LOptions), GetBitValue(LOptions,3) ));
      end;
    ICMP_MULTICAST_LISTENER_REPORT,
    ICMP_MULTICAST_LISTENER_REPORT_MESSAGE_V2:
      begin    
        LOptionsW := GetWordFromCardinal(LHeader.ICMP_Unused,0);  
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Unused',[AcronymName]), 'Unused:', LOptionsW, @LOptionsW, SizeOf(LOptionsW) ));
      end
  else
    AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Unused',[AcronymName]), 'Unused:', LHeader.ICMP_Unused, @LHeader.ICMP_Unused, SizeOf(LHeader.ICMP_Unused) ));
  end;
  
  LAllHeaderSize := TWpcapIPHeader.EthAndIPHeaderSize(aPacketData,aPacketSize)+HeaderLength(0);   
  
  case LHeader.TypeICMP of
  
    ICMP_ECHO_REPLY, 
    ICMP_ECHO_REQUEST:  
      begin
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.IdentifierBE',[AcronymName]), 'Identifier (BE):',wpcapntohs(GetFistNBit(LHeader.ICMP_Unused ,16) ),nil,0));
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.IdentifierLE',[AcronymName]), 'Identifier (LE):',(GetLastNBit(LHeader.ICMP_Unused ,16) ),nil,0));
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SequenceNumberBE',[AcronymName]), 'Sequence number (BE):', wpcapntohs(LHeader.ICMP_Unused shr 16), @LHeader.ICMP_Unused, 2));        
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SequenceNumberLE',[AcronymName]), 'Sequence number (LE):', (LHeader.ICMP_Unused shr 16), @LHeader.ICMP_Unused, 2));         
      end;

    ICMP_DEST_UNREACHABLE, 
    ICMP_DEST_UNREACHABLE_IPv6,
    ICMP_SOURCE_QUENCH, 
    ICMP_REDIRECT_MESSAGE, 
    ICMP_TIME_EXCEEDED, 
    ICMP_PARAMETER_PROBLEM:    
      begin

        LNewPacketData := GetNextIpHeader(aPacketData,aPacketSize,0,LNewPacketLen);
        Try
          TWpcapIPHeader.HeaderToString( LNewPacketData, LNewPacketLen,aStartLevel+1,AListDetail);
        Finally
          FreeMem(LNewPacketData);
        End;      
        
      end;
      
    ICMP_TIMESTAMP_REQUEST, 
    ICMP_TIMESTAMP_REPLY:      
      begin
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.IdentifierBE',[AcronymName]), 'Identifier (BE):',wpcapntohs(GetFistNBit(LHeader.ICMP_Unused ,16) ), nil,0) );
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.IdentifierLE',[AcronymName]), 'Identifier (LE):',(GetLastNBit(LHeader.ICMP_Unused ,16) ), nil,0));        
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SequenceNumberBE',[AcronymName]), 'Sequence number (BE):', ntohs(LHeader.ICMP_Unused shr 16), nil,0 ));
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SequenceNumberLE',[AcronymName]), 'Sequence number (LE):', (LHeader.ICMP_Unused shr 16), @LHeader.ICMP_Unused, 2 ));                 
      end;
      
    ICMP_INFORMATION_REQUEST:
      begin
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.IdentifierBE',[AcronymName]), 'Identifier (BE):',wpcapntohs(GetFistNBit(LHeader.ICMP_Unused ,16) ),nil,0 ));
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.IdentifierLE',[AcronymName]), 'Identifier (LE):',(GetLastNBit(LHeader.ICMP_Unused ,16) ),nil,0 ));               
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SequenceNumberBE',[AcronymName]), 'Sequence number (BE):', ntohs(LHeader.ICMP_Unused shr 16),nil,0 ));
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SequenceNumberLE',[AcronymName]), 'Sequence number (LE):', (LHeader.ICMP_Unused shr 16), @LHeader.ICMP_Unused, 2 ));                 
      end;
      
    ICMP_NEIGHBOR_ADVERTISEMENT,
    ICMP_NEIGHBOR_SOLICITATION:
      begin
        SourceAddress  := PTIPv6AddrBytes(aPacketData + LAllHeaderSize)^;
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.TargetAddr',[AcronymName]), 'Target address:', IPv6AddressToString(SourceAddress), @SourceAddress, SizeOf(SourceAddress) ));          

        LOptions := PByte(aPacketData + LAllHeaderSize + SizeOf(SourceAddress))^;        
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.OptionsICMPV6',[AcronymName]), 'Options ICMPV6:', ByteToBinaryString(LOptions), @LOptions,SizeOf(LOptions), LOptions ));
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.OptionsICMPV6.Type',[AcronymName]), 'Type',ConvertOptionsToString(LOptions),@LOptions,sizeOf(LOptions)));
        

        LOptions := PByte(aPacketData + LAllHeaderSize + SizeOf(SourceAddress)+1)^;     
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.OptionsICMPV6.Len',[AcronymName]), 'Lenght',LOptions,@LOptions,sizeOf(LOptions)));  
        if LOptions > 0 then
        begin
          SetLength(LLink,(LOptions*8));
          Move(aPacketData[LAllHeaderSize+SizeOf(SourceAddress)+2],LLink[0],(LOptions*8));
          AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.OptionsICMPV6.LinkLayerAddr',[AcronymName]), 'Link-layer address:', IPv6AddressToString(LLink), @LLink, SizeOf(LLink)));                               
        end;
      end;
      
    ICMP_MULTICAST_LISTENER_REPORT,
    ICMP_MULTICAST_LISTENER_REPORT_MESSAGE_V2:
      begin      
        LAllHeaderSize := TWpcapIPHeader.EthAndIPHeaderSize(aPacketData,aPacketSize)+HeaderLength(0); 
        LOptionsW      := PWord(aPacketData + LAllHeaderSize-2)^;
        LCount         := wpcapntohs(LOptionsW);
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.NMulticastAddrRecords',[AcronymName]),  'Number of Multicast Address Records:',LCount,@LOptionsW,sizeOf(LOptionsW)));   
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.NMulticastRecordChangedInclude',[AcronymName]),  'Multicast Address Record Changed to include:',null,nil,0));  
        LCurrentPos := LAllHeaderSize;
        for I := 0 to LCount -1 do
        begin
          ParserUint8Value(aPacketData,aStartLevel+2,aPacketSize,Format('%s.NMulticastRecordChangedInclude.Type',[AcronymName]), 'Record type:',AListDetail,ConvertRecordTypeToString,True,LCurrentPos);
          ParserUint8Value(aPacketData,aStartLevel+2,aPacketSize,Format('%s.NMulticastRecordChangedInclude.AuxLen',[AcronymName]), 'Aux Data Len:',AListDetail,nil,True,LCurrentPos);
          ParserUint16Value(aPacketData,aStartLevel+2,aPacketSize,Format('%s.NMulticastRecordChangedInclude.NSource',[AcronymName]), 'Number of Sources:',AListDetail,nil,True,LCurrentPos);
                  
          SourceAddress  := PTIPv6AddrBytes(aPacketData + LCurrentPos)^;
          AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.NMulticastRecordChangedInclude.Addr',[AcronymName]), 'Multicast address:', IPv6AddressToString(SourceAddress),@SourceAddress, SizeOf(SourceAddress)));  
          inc(LCurrentPos,SizeOf(SourceAddress));                
        end;
      end;
      
    ICMP_ROUTER_SOLICITATION:
      begin
        LAllHeaderSize := TWpcapIPHeader.EthAndIPHeaderSize(aPacketData,aPacketSize)+HeaderLength(0); 
        LOptions       := PByte(aPacketData + LAllHeaderSize)^;

        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.OptionsICMPV6',[AcronymName]),  'Options ICMPV6:', ByteToBinaryString(LOptions), @LOptions,SizeOf(LOptions), LOptions ));
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.OptionsICMPV6.Type',[AcronymName]), 'Type',ConvertOptionsToString(LOptions), @LOptions,sizeOf(LOptions), LOptions ));
        LOptions := PByte(aPacketData + LAllHeaderSize +1)^;     
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.OptionsICMPV6.Len',[AcronymName]), 'Lenght',LOptions, @LOptions,sizeOf(LOptions) ));   
        if LOptions > 0 then
        begin
          SetLength(LLink,LOptions*8);
          Move(aPacketData[LAllHeaderSize+2],LLink[0],LOptions*8);
          AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.OptionsICMPV6.LinkLayerAddr',[AcronymName]), 'Link-layer address:', IPv6AddressToString(LLink), @LLink, SizeOf(LLink) ));        
        end;
      end;

  end;
  
  Result := True;
end;

class function TWPcapProtocolICMP.ConvertOptionsToString(aOptions: Integer): string;
const
  optionStrings: array[0..14] of string = (
    'Reserved', 'Source Link-Layer Address', 'Target Link-Layer Address',
    'Prefix Information', 'Redirected Header', 'MTU', 'Checksum',
    'Hop-by-Hop Options', 'Destination Options','Unknown','Unknown','Unknown','Unknown','Unknown','Nonce'
  );
begin
  if aOptions > High(optionStrings) then
    Result := 'Unknown'
  else
    Result := optionStrings[aOptions];
end;

class function TWPcapProtocolICMP.ConvertRecordTypeToString(const aRecordType: Uint8): string;
begin
  case aRecordType of
    3: Result := 'Changed to Include';
    4: Result := 'Changed to Exclude';
    else Result := 'Unknown';
  end;
end;

class function TWPcapProtocolICMP.CodeToString(const aType, Code: Byte): String;
begin
  case aType of
    ICMP_ECHO_REPLY: 
      case Code of
         0: Result := 'Echo Reply';
         1: Result := 'Reserved';
         2: Result := 'Reserved';
         3: Result := 'Destination Unreachable';
         4: Result := 'Source Quench (Deprecated)';
         5: Result := 'Redirect';
         6: Result := 'Alternate Host Address (Deprecated)';
         7: Result := 'Reserved';
         8: Result := 'Echo Request';
         9: Result := 'Router Advertisement';
        10: Result := 'Router Solicitation';
        11: Result := 'Time Exceeded';
        12: Result := 'Parameter Problem';
        13: Result := 'Timestamp';
        14: Result := 'Timestamp Reply';
        15: Result := 'Information Request (Deprecated)';
        16: Result := 'Information Reply (Deprecated)';
        17: Result := 'Address Mask Request (Deprecated)';
        18: Result := 'Address Mask Reply (Deprecated)';
        else Result := Format('Unknown code: %d', [Code]);
      end;
      
    ICMP_DEST_UNREACHABLE_IPv6 :
      begin     
        case Code of
           1: Result := 'Net Unreachable';
           2: Result := 'Host Unreachable';
           3: Result := 'Protocol Unreachable';
           4: Result := 'Port Unreachable';
           5: Result := 'Fragmentation Needed and DF Set';
           6: Result := 'Source Route Failed';
           7: Result := 'Destination Network Unknown';
           8: Result := 'Destination Host Unknown';
           9: Result := 'Source Host Isolated';
          10: Result := 'Communication with Destination Network is Administratively Prohibited';
          11: Result := 'Communication with Destination Host is Administratively Prohibited';
          12: Result := 'Destination Network Unreachable for Type of Service';
          13: Result := 'Destination Host Unreachable for Type of Service';
          14: Result := 'Communication Administratively Prohibited';
          15: Result := 'Host Precedence Violation';
          16: Result := 'Precedence cutoff in effect';
        else Result := Format('Unknown code: %d', [Code]);
        end;      
      end;
      
    ICMP_DEST_UNREACHABLE: 
      case Code of
         0: Result := 'Net Unreachable';
         1: Result := 'Host Unreachable';
         2: Result := 'Protocol Unreachable';
         3: Result := 'Port Unreachable';
         4: Result := 'Fragmentation Needed and DF Set';
         5: Result := 'Source Route Failed';
         6: Result := 'Destination Network Unknown';
         7: Result := 'Destination Host Unknown';
         8: Result := 'Source Host Isolated';
         9: Result := 'Communication with Destination Network is Administratively Prohibited';
        10: Result := 'Communication with Destination Host is Administratively Prohibited';
        11: Result := 'Destination Network Unreachable for Type of Service';
        12: Result := 'Destination Host Unreachable for Type of Service';
        13: Result := 'Communication Administratively Prohibited';
        14: Result := 'Host Precedence Violation';
        15: Result := 'Precedence cutoff in effect';
      else Result := Format('Unknown code: %d', [Code]);
      end;
      
    ICMP_REDIRECT_MESSAGE: 
      case Code of
        0: Result := 'Redirect Datagram for the Network';
        1: Result := 'Redirect Datagram for the Host';
        2: Result := 'Redirect Datagram for the Type of Service and Network';
        3: Result := 'Redirect Datagram for the Type of Service and Host';
      else Result := Format('Unknown code: %d', [Code]);
      end;
      
    ICMP_TIME_EXCEEDED: 
      case Code of
        0: Result := 'TTL expired in transit';
        1: Result := 'Fragment reassembly time exceeded';
      else Result := Format('Unknown code: %d', [Code]);
      end;

      
    ICMP_PARAMETER_PROBLEM: 
      case Code of
        0: Result := 'Pointer indicates the error';
        1: Result := 'Missing a required option';
        2: Result := 'Bad length';
      else Result := Format('Unknown code: %d', [Code]);
      end;
      
  else 
     if Code = 0 then
        Result := '0'
     else
       Result := Format('Unknown type: %d, code: %d', [aType, Code]);
  end;
end;

class function TWPcapProtocolICMP.TypeToString(const aType: Byte): String;
begin

  case aType of
    ICMP_ECHO_REPLY                            : Result := 'Echo reply';
    ICMP_DEST_UNREACHABLE_IPv6                 : Result := 'Destination unreachable';
    2                                          : Result := 'Reserved (for testing)';
    ICMP_DEST_UNREACHABLE                      : Result := 'Destination unreachable';
    ICMP_SOURCE_QUENCH                         : Result := 'Source quench';
    ICMP_REDIRECT_MESSAGE                      : Result := 'Redirect';
    ICMP_ALTERNATE_HOST_ADDRESS                : Result := 'Alternate host address';
    7                                          : Result := 'Reserved (for testing)';
    ICMP_ECHO_REQUEST                          : Result := 'Echo request';
    ICMP_ROUTER_ADVERTISEMENT                  : Result := 'Router advertisement';
    ICMP_ROUTER_SELECTION                      : Result := 'Router selection';
    ICMP_TIME_EXCEEDED                         : Result := 'Time exceeded';
    ICMP_PARAMETER_PROBLEM                     : Result := 'Parameter problem';
    ICMP_TIMESTAMP_REQUEST                     : Result := 'Timestamp request';
    ICMP_TIMESTAMP_REPLY                       : Result := 'Timestamp reply';
    ICMP_INFORMATION_REQUEST                   : Result := 'Information request';
    ICMP_INFORMATION_REPLY                     : Result := 'Information reply';
    ICMP_ADDRESS_MASK_REQUEST                  : Result := 'Address mask request';
    ICMP_ADDRESS_MASK_REPLY                    : Result := 'Address mask reply';
    19                                         : Result := 'Reserved (for security)';
    20..29                                     : Result := 'Reserved (for testing)';
    ICMP_TRACEROUTE                            : Result := 'Traceroute';
    ICMP_CONVERSION_ERROR                      : Result := 'Conversion error';
    ICMP_MOBILE_REDIRECT                       : Result := 'Mobile host redirect';
    ICMP_IPV6_WHERE_ARE_YOU                    : Result := 'IPv6 Where-Are-You';
    ICMP_IPV6_I_AM_HERE                        : Result := 'IPv6 I-Am-Here';
    ICMP_MOBILE_REG_REQUEST                    : Result := 'Mobile Registration Request';
    ICMP_MOBILE_REG_REPLY                      : Result := 'Mobile Registration Reply';
    ICMP_DOMAIN_NAME_REQUEST                   : Result := 'Domain Name request';
    ICMP_DOMAIN_NAME_REPLY                     : Result := 'Domain Name reply';
    39..130                                    : Result := 'Unassigned';
    ICMP_MULTICAST_LISTENER_REPORT             : Result := 'Multicast Listener Report';
    132                                        : Result := 'Unassigned';    
    ICMP_ROUTER_SOLICITATION                   : Result := 'Router Solicitation';
    ICMP_NEIGHBOR_SOLICITATION                 : Result := 'Neighbor Solicitation';  
    ICMP_NEIGHBOR_ADVERTISEMENT                : Result := 'Neighbor Advertisement';
    137..142                                   : Result := 'unassigned';
    ICMP_MULTICAST_LISTENER_REPORT_MESSAGE_V2  : Result := 'Multicast Listener Report Message v2';
    144..255                                   : Result := 'Unassigned';
  end;
end;


class function TWPcapProtocolICMP.HeaderLength(aFlag: Byte): word;
begin
  Result := SizeOf(TICMPHeader)
end;

class function TWPcapProtocolICMP.Header(const aData: PByte; aSize: Integer; var aICMPHeader: PTICMPHeader): Boolean;
var aSizeEthIP : Word;
begin
  Result     := False;
  aSizeEthIP := TWpcapIPHeader.EthAndIPHeaderSize(AData,aSize);

  // Check if the data size is sufficient for the Ethernet, IP, and UDP headers
  if (aSize < aSizeEthIP + HeaderLength(0)) then Exit;  


  // Parse the Ethernet header
  case TWpcapIPHeader.IpClassType(aData,aSize) of
    imtIpv4 : 
      begin
        // Parse the IPv4 header
        if TWpcapIPHeader.HeaderIPv4(aData,aSize).Protocol <> IPPROTO_ICMP then Exit;

        // Parse the UDP header
        aICMPHeader := PTICMPHeader(aData + aSizeEthIP);
        Result      := True;     
      end;
   imtIpv6:
      begin

        if Not (TWpcapIPHeader.HeaderIPv6(aData,aSize).NextHeader in [IPPROTO_ICMPV6,IPPROTO_HOPOPTS]) then Exit;
        // Parse the UDP header
        aICMPHeader := PTICMPHeader(aData + aSizeEthIP);
        Result      := True;
      end;      
  end;  
end;

end.
                                                 
