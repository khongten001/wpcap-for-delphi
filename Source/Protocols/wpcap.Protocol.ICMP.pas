unit wpcap.Protocol.ICMP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,
  System.Variants, wpcap.BufferUtils,WinSock,WinSock2;

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
    class function CodeToString(const aType, Code: Byte): String; static;
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
    class function HeaderToString(const aPacketData: PByte;aPacketSize: Integer; AListDetail: TListHeaderString): Boolean; override;      
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
  
class function TWPcapProtocolICMP.HeaderToString(const aPacketData: PByte; aPacketSize: Integer;AListDetail: TListHeaderString): Boolean;
var LHeader : PTICMPHeader;
begin
  Result := False;

  if not Header(aPacketData,aPacketSize,LHeader) then exit;

  AListDetail.Add(AddHeaderInfo(0,Format('%s (%s)',[ProtoName,AcronymName]),NULL,PByte(LHeader),HeaderLength(0)));            
  AListDetail.Add(AddHeaderInfo(1,'Type:',TypeToString(LHeader.TypeICMP),@LHeader.TypeICMP,sizeOf(LHeader.TypeICMP)));
  AListDetail.Add(AddHeaderInfo(1,'Code:',CodeToString(LHeader.TypeICMP,LHeader.Code),@LHeader.Code,sizeOf(LHeader.Code)));            
  AListDetail.Add(AddHeaderInfo(1,'Checksum:',wpcapntohs(LHeader.CheckSum),@LHeader.CheckSum,sizeOf(LHeader.CheckSum))); 
  AListDetail.Add(AddHeaderInfo(1, 'Unused:', LHeader.ICMP_Unused, @LHeader.ICMP_Unused, SizeOf(LHeader.ICMP_Unused)));
  case LHeader.TypeICMP of
    0,8 : 
      begin
        AListDetail.Add(AddHeaderInfo(1,'Identifier:(BE):',wpcapntohs(GetFistNBit(LHeader.ICMP_Unused ,16) ),nil,0));
        AListDetail.Add(AddHeaderInfo(1,'Identifier (LE):',(GetLastNBit(LHeader.ICMP_Unused ,16) ),nil,0));
        AListDetail.Add(AddHeaderInfo(1, 'Sequence number (BE):', wpcapntohs(LHeader.ICMP_Unused shr 16), @LHeader.ICMP_Unused, 2));
        
      end;
    3, 4, 5, 11, 12:
      begin

      end;
    13, 14:
      begin
        AListDetail.Add(AddHeaderInfo(1,'Identifier:(BE):',wpcapntohs(GetFistNBit(LHeader.ICMP_Unused ,16) ),nil,0));
        AListDetail.Add(AddHeaderInfo(1, 'Sequence number (BE):', ntohs(LHeader.ICMP_Unused shr 16), nil,0));
      end;
    15:
      begin
        AListDetail.Add(AddHeaderInfo(1,'Identifier:(BE):',wpcapntohs(GetFistNBit(LHeader.ICMP_Unused ,16) ),nil,0));
        AListDetail.Add(AddHeaderInfo(1, 'Sequence number (BE):', ntohs(LHeader.ICMP_Unused shr 16),nil,0));
     //   AListDetail.Add(AddHeaderInfo(1, 'Original Datetime (BE):', ntohl(PDWord(aPacketData + SizeOf(TICMPHeader))^), aPacketData + SizeOf(TICMPHeader), SizeOf(Cardinal)));
     //   AListDetail.Add(AddHeaderInfo(1, 'Receive Datetime (BE):', ntohl(PDWord(aPacketData + SizeOf(TICMPHeader) + SizeOf(Cardinal))^), aPacketData + SizeOf(TICMPHeader) + SizeOf(Cardinal), SizeOf(Cardinal)));
      
      end;
  end;
  
  Result := True;
end;

class function TWPcapProtocolICMP.CodeToString(const aType, Code: Byte): String;
begin
  case aType of
    0: case Code of
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
    3: case Code of
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
    5: case Code of
         0: Result := 'Redirect Datagram for the Network';
         1: Result := 'Redirect Datagram for the Host';
         2: Result := 'Redirect Datagram for the Type of Service and Network';
         3: Result := 'Redirect Datagram for the Type of Service and Host';
         else Result := Format('Unknown code: %d', [Code]);
       end;
    11: case Code of
          0: Result := 'TTL expired in transit';
          1: Result := 'Fragment reassembly time exceeded';
          else Result := Format('Unknown code: %d', [Code]);
        end;
    12: case Code of
          0: Result := 'Pointer indicates the error';
          1: Result := 'Missing a required option';
          2: Result := 'Bad length';
          else Result := Format('Unknown code: %d', [Code]);
        end;
    else Result := Format('Unknown type: %d, code: %d', [aType, Code]);
  end;
end;

class function TWPcapProtocolICMP.TypeToString(const aType: Byte): String;
begin
  case aType of
    0       : Result := 'Echo reply';
    1       : Result := 'Reserved (for testing)';
    2       : Result := 'Reserved (for testing)';
    3       : Result := 'Destination unreachable';
    4       : Result := 'Source quench';
    5       : Result := 'Redirect';
    6       : Result := 'Alternate host address';
    7       : Result := 'Reserved (for testing)';
    8       : Result := 'Echo request';
    9       : Result := 'Router advertisement';
    10      : Result := 'Router selection';
    11      : Result := 'Time exceeded';
    12      : Result := 'Parameter problem';
    13      : Result := 'Timestamp request';
    14      : Result := 'Timestamp reply';
    15      : Result := 'Information request';
    16      : Result := 'Information reply';
    17      : Result := 'Address mask request';
    18      : Result := 'Address mask reply';
    19      : Result := 'Reserved (for security)';
    20..29  : Result := 'Reserved (for testing)';
    30      : Result := 'Traceroute';
    31      : Result := 'Conversion error';
    32      : Result := 'Mobile host redirect';
    33      : Result := 'IPv6 Where-Are-You';
    34      : Result := 'IPv6 I-Am-Here';
    35      : Result := 'Mobile Registration Request';
    36      : Result := 'Mobile Registration Reply';
    37      : Result := 'Domain Name request';
    38      : Result := 'Domain Name reply';
    39..132 : Result := 'Unassigned';
    133     : Result := 'Router Solicitation';
    135     : Result := 'Neighbor Solicitation';    
    136..142: Result := 'unassigned';
    143     : Result := 'Multicast Listener Report Message v2';
    144..255: Result := 'Unassigned';
  end;

  Result := Format('%s [%d]',[Result, aType]).Trim;
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
                                                 
