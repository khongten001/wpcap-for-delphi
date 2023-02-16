unit wpcap.protocol;

interface              

uses wpcap.Conts,WinSock,System.SysUtils,wpcap.Types,Winapi.Winsock2;

/// <summary>
/// This function takes a 16-bit IPv6 protocol number and returns its name as a string. 
/// The function checks if the protocol number matches one of the well-known protocols defined by IANA and returns the corresponding name, 
//  otherwise it returns the hexadecimal representation of the protocol number. 
///
/// The well-known protocols include ICMP, TCP, UDP, and more.
/// </summary>
function GetIPv6ProtocolName(const Protocol: Byte): string;

/// <summary>
/// This function takes a 16-bit IPv4 protocol number and returns its name as a string. 
/// The function checks if the protocol number matches one of the well-known protocols defined by IANA and returns the corresponding name, 
//  otherwise it returns the hexadecimal representation of the protocol number. 
///
/// The well-known protocols include ICMP, TCP, UDP, and more.
/// </summary>
function GetIPv4ProtocolName(protocol: Word): string;
 
/// <summary>
/// Functions that recognize the NTP protocol   TODO dosnt work
/// </summary>
function IsNTPPacket(packet: PByte; packetLen: Integer): Boolean;

/// <summary>
/// This function takes a pointer to the packet and its length in bytes e
/// returns True if packet is L2TP Data (does not handle l2TP Command), False otherwise.
/// It is assumed that the ethernet header is not included in the packet.
/// </summary>
function IsL2TPPacketData(const aData: PByte; aSize: Integer): Boolean;

/// <summary>
///  Returns a string representing of acronym of the Ethernet protocol identified by the given protocol value.
///  The protocol value is a 16-bit unsigned integer in network byte order.
///  Supported protocols are listed in the "Assigned Internet Protocol Numbers" registry maintained by IANA.
///  If the protocol is not recognized, the string "<unknown>" is returned.
/// </summary>
function GetEthAcronymName(protocol: Word): string;

implementation

function GetIPv6ProtocolName(const Protocol: Byte): string;
const
  IPv6Protocols: array[0..129] of string = (
    'ICMPv6', 'IGMP', 'Reserved', 'IPIP', 'TCP',
    'Reserved', 'UDP', 'Reserved', 'Reserved', 'Reserved', 'Reserved',
    'Reservation-1', 'Reservation-2', 'Reservation-3', 'Reservation-4',
    'Reservation-5', 'Reservation-6', 'Reservation-7', 'Reservation-8',
    'Reservation-9', 'Reservation-10', 'Reservation-11', 'Reservation-12',
    'Reservation-13', 'Reservation-14', 'Reservation-15', 'Reservation-16',
    'Reservation-17', 'Reservation-18', 'Reservation-19', 'Reservation-20',
    'Reservation-21', 'Reservation-22', 'Reservation-23', 'Reservation-24',
    'Reservation-25', 'Reservation-26', 'Reservation-27', 'Reservation-28',
    'Reservation-29', 'Reservation-30', 'Reservation-31', 'Reservation-32',
    'Destination Options', 'Reserved', 'Mobility Header', 'Reserved', 'Reserved',
    'Reserved', 'Reserved', 'ICMPv6', 'No Next Header', 'Destination Options',
    'Reserved', 'IPv6 Route', 'IPv6 Frag', 'Reserved', 'Reserved',
    'Reservation-49', 'Reservation-50', 'Reservation-51', 'Reservation-52',
    'Reservation-53', 'Reservation-54', 'Reservation-55', 'Reservation-56',
    'Reservation-57', 'Reservation-58', 'Reservation-59', 'Reservation-60',
    'Reservation-61', 'Reservation-62', 'Reservation-63', 'Reservation-64',
    'Reservation-65', 'Reservation-66', 'Reservation-67', 'Reservation-68',
    'Reservation-69', 'Reservation-70', 'Reservation-71', 'Reservation-72',
    'Reservation-73', 'Reservation-74', 'Reservation-75', 'Reservation-76',
    'Reservation-77', 'Reservation-78', 'Reservation-79', 'Reservation-80',
    'Reservation-81', 'Reservation-82', 'Reservation-83', 'Reservation-84',
    'Reservation-85', 'Reservation-86', 'Reservation-87', 'Reservation-88',
    'Reservation-89', 'Reservation-90', 'Reservation-91', 'Reservation-92',
    'Reservation-93', 'Reservation-94', 'Reservation-95', 'Reservation-96',
    'Reserved', 'Reserved', 'Reserved', 'Reserved', 'Reserved', 'Reserved',
    'Reserved', 'Reserved', 'Experimental-1', 'Experimental-2', 'Experimental-3',
    'Experimental-4', 'Experimental-5', 'Experimental-6', 'Experimental-7',
    'Experimental-8', 'Experimental-9', 'Experimental-10', 'Experimental-11',
    'Experimental-12', 'Experimental-13', 'Experimental-14', 'ICMPv6',
    'Experimental-16');
begin
  if Protocol <= High(IPv6Protocols) then
    Result := IPv6Protocols[Protocol]
  else
    Result := 'Unknown';
end;


function GetIPv4ProtocolName(protocol: Word): string;
begin
  case protocol of
    IPPROTO_ICMP    : Result := 'ICMP';
    IPPROTO_IGMP    : Result := 'IGMP';
    IPPROTO_GGP     : Result := 'GGP';
    IPPROTO_TCP     : Result := 'TCP';
    IPPROTO_UDP     : Result := 'UDP';
    IPPROTO_IPV6    : Result := 'IPv6';
    IPPROTO_ICMPV6  : Result := 'ICMPv6';
    IPPROTO_PUP     : Result := 'PUP';   // ETH ??
    IPPROTO_IDP     : Result := 'xns idp';
    IPPROTO_GRE     : Result := 'GRE';
    IPPROTO_ESP     : Result := 'ESP';
    IPPROTO_AH      : Result := 'AH';    
    IPPROTO_ROUTING : Result := 'ROUTING';
    IPPROTO_PGM     : Result := 'PGM';
    IPPROTO_SCTP    : Result := 'SCTP';
    IPPROTO_RAW     : Result := 'RAW';
    else Result := Format('Unknown %d',[protocol]);
  end;
end;

function GetEthAcronymName(protocol: Word): string;
begin
  case protocol of
    ETH_P_LOOP: Result := 'LOOP';
    ETH_P_PUP: Result := 'PUP';
    ETH_P_PUPAT: Result := 'PUPAT';
    ETH_P_IP: Result := 'IP';
    ETH_P_X25: Result := 'X25';
    ETH_P_ARP: Result := 'ARP';
    ETH_P_BPQ: Result := 'BPQ';
    ETH_P_IEEEPUP: Result := 'IEEEPUP';
    ETH_P_IEEEPUPAT: Result := 'IEEEPUPAT';
    ETH_P_DEC: Result := 'DEC';
    ETH_P_DNA_DL: Result := 'DNA_DL';
    ETH_P_DNA_RC: Result := 'DNA_RC';
    ETH_P_DNA_RT: Result := 'DNA_RT';
    ETH_P_LAT: Result := 'LAT';
    ETH_P_DIAG: Result := 'DIAG';
    ETH_P_CUST: Result := 'CUST';
    ETH_P_SCA: Result := 'SCA';
    ETH_P_RARP: Result := 'RARP';
    ETH_P_ATALK: Result := 'ATALK';
    ETH_P_AARP: Result := 'AARP';
    ETH_P_8021Q: Result := '802.1Q';
    ETH_P_IPX: Result := 'IPX';
    ETH_P_IPV6: Result := 'IPv6';
    ETH_P_PAUSE: Result := 'PAUSE';
    ETH_P_SLOW: Result := 'SLOW';
    ETH_P_WCCP: Result := 'WCCP';
    ETH_P_PPP_DISC: Result := 'PPP_DISC';
    ETH_P_PPP_SES: Result := 'PPP_SES';
    ETH_P_MPLS_UC: Result := 'MPLS_UC';
    ETH_P_ATMMPOA: Result := 'ATMMPOA';
    ETH_P_LINK_CTL: Result := 'LINK_CTL';
    ETH_P_ATMFATE: Result := 'ATMFATE';
    ETH_P_PAE: Result := 'PAE';
    ETH_P_AOE: Result := 'AOE';
    ETH_P_8021AD: Result := '802.1AD';
//    ETH_P_802_EX1: Result := '802_EX1';
    ETH_P_TIPC: Result := 'TIPC';
    //ETH_P_8021AH: Result := '802.1AH';
    ETH_P_IEEE1588: Result := 'IEEE1588';
    ETH_P_FCOE: Result := 'FCoE';
    ETH_P_FIP: Result := 'FIP';
    ETH_P_EDSA: Result := 'EDSA';
    ETH_P_802_3: Result := '802.3';
    ETH_P_AX25: Result := 'AX25';
    ETH_P_ALL: Result := 'ALL';
    else Result := 'Unknown protocol (' + IntToStr(protocol) + ')';
  end;
end;


function IsNTPPacket(packet: PByte; packetLen: Integer): Boolean;
type
  TNTPHeader = packed record
    LI_VN_MODE    : Byte;
    Stratum       : Byte;
    Poll          : Byte;
    Precision     : Byte;
    RootDelay     : Cardinal;
    RootDispersion: Cardinal;
    ReferenceID   : Cardinal;
    ReferenceTS   : array[0..7] of Byte;
    OriginateTS   : array[0..7] of Byte;
    ReceiveTS     : array[0..7] of Byte;
    TransmitTS    : array[0..7] of Byte;
  end;
  PNTPHeader = ^TNTPHeader;
  
var ntpHeader: PNTPHeader;
begin
  Result := False;
  if packetLen < SizeOf(TNTPHeader) then Exit;

  ntpHeader := PNTPHeader(packet);
  if (ntpHeader^.LI_VN_MODE and $38) = $18 then // Check the value of the LI_VN_MODE field
    Result := True;
end;


function IsL2TPPacketData(const aData: PByte; aSize: Integer): Boolean;
const L2TP_MAGIC_COOKIE = 3355574314; 
      L2TP_VERSION      = 2;  
type
  PL2TPHdr = ^TL2TPHdr;
  TL2TPHdr = packed record
    Flags     : Byte;      
    Version   : Byte;
    Length    : Word;
    TunnelId  : Word;
    SessionId : Word; 
    Ns        : Byte;
    Nr        : Byte;
    OffsetSize: Word;
  end;

var LEthHdr  : PETHHdr;
    LIPHdr   : PIPHeader;
    LIPv6Hdr : PIPv6Header;
    LUDPPtr  : PUDPHdr;
    LL2TPHdr : PL2TPHdr;
    Lcoockie : Pcardinal;
begin
  Result := False;

  if (aSize < ETH_HEADER_LEN + SizeOf(TIPHeader) + SizeOf(TUDPHdr)) then  Exit;

  LEthHdr := PETHHdr(aData);
  if ntohs(LEthHdr.EtherType) = ETH_P_IP then
  begin
    LIPHdr := PIPHeader(aData + ETH_HEADER_LEN);
    if LIPHdr.Protocol <> IPPROTO_UDP then Exit;

    LUDPPtr   := PUDPHdr(AData + ETH_HEADER_LEN + SizeOf(TIPHeader));    
    LL2TPHdr  := PL2TPHdr(AData +ETH_HEADER_LEN + SizeOf(TIPHeader)+ SizeOf(TUDPHdr));
    {4 byte after UDP header for test L2TP_MAGIC_COOKIE}
    Lcoockie  := PCardinal(AData + ETH_HEADER_LEN + SizeOf(TIPHeader)+SizeOf(TUDPHdr));
    
    if ntohl(Lcoockie^) <> L2TP_MAGIC_COOKIE then Exit;

    Result := ( LL2TPHdr.version = L2TP_VERSION) and 
              ( ntohs(LL2TPHdr.length) = ntohs(LUDPPtr.Lenght)-8)  
  end
  else if ntohs(LEthHdr.EtherType) = ETH_P_IPV6 then
  begin
    {TODO PCAP for test}
    if aSize < ETH_HEADER_LEN + SizeOf(TIPv6Header) then Exit;

    LIPv6Hdr := PIPv6Header(aData + ETH_HEADER_LEN);
    if LIPv6Hdr.NextHeader = IPPROTO_L2TP then
      Result := True;
  end;
end;


end.
