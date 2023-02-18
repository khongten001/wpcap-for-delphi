unit wpcap.protocol;

interface              

uses
  wpcap.Conts, WinSock, System.SysUtils, wpcap.Types, Winapi.Winsock2, wpcap.Protocol.Base,
  vcl.Graphics, wpcap.Graphics,wpcap.Protocol.DNS, wpcap.Protocol.UDP,System.Generics.Collections,
  wpcap.Protocol.L2TP,wpcap.Protocol.NTP,wpcap.Protocol.MDNS,wpcap.Protocol.LLMNR;


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
///  Returns a string representing of acronym of the Ethernet protocol identified by the given protocol value.
///  The protocol value is a 16-bit unsigned integer in network byte order.
///  Supported protocols are listed in the "Assigned Internet Protocol Numbers" registry maintained by IANA.
///  If the protocol is not recognized, the string "<unknown>" is returned.
/// </summary>
function GetEthAcronymName(protocol: Word): string;

/// <summary>
/// Returns the color associated with a given IP protocol value, limited to a specific set of protocols.
/// </summary>
/// <param name="aEthType">The ETH type value to get the color for.</param>
/// <param name="aprotocol">The IP protocol value to get the color for.</param>
/// <param name="aBackGroundColor">Return TColor</param>
/// <param name="aFontColor">Return TColor for font</param>///
/// <returns>True if found a color for Protocol</returns>
function GetProtocolColor(aEthType,aProtocol: Word;var aBackGroundColor:TColor;var aFontColor:TColor): boolean;


function IsDropboxPacket(const aUDPPtr: PUDPHdr): Boolean;

function AnalyzeUDPProtocol(const aData:Pbyte;aSize:Integer;var aArcronymName:String;var aIdProtoDetected:Byte):boolean;



implementation

function GetProtocolColor(aEthType,aProtocol: Word;var aBackGroundColor:TColor;var aFontColor:TColor): boolean;
CONST TCP_COLOR   = 16704998;
      UDP_COLOR   = 16772826;
      COLOR_ICMP  = 16769276;
begin
  Result := True;

  case aEthType of
     ETH_P_IP : 
      begin
        case aProtocol of
          IPPROTO_ICMPV6,
          IPPROTO_ICMP   : aBackGroundColor := COLOR_ICMP;
          IPPROTO_IGMP   : aBackGroundColor := $00FFFF; // Cyan
          IPPROTO_GGP    : aBackGroundColor := $FFD700; // Gold
          IPPROTO_TCP    : aBackGroundColor := TCP_COLOR; 
          IPPROTO_UDP    : aBackGroundColor := UDP_COLOR; 
          IPPROTO_IPV6   : aBackGroundColor := $B0C4DE; // LightSteelBlue
          IPPROTO_PUP    : aBackGroundColor := $FFE4E1; // MistyRose
          IPPROTO_IDP    : aBackGroundColor := $9370DB; // MediumPurple
          IPPROTO_GRE    : aBackGroundColor := $FFC0CB; // Pink
          IPPROTO_ESP    : aBackGroundColor := $D8BFD8; // Thistle
          IPPROTO_AH     : aBackGroundColor := $FFB6C1; // LightPink
          IPPROTO_ROUTING: aBackGroundColor := $FFFACD; // LemonChiffon
          IPPROTO_PGM    : aBackGroundColor := $D2B48C; // Tan
          IPPROTO_SCTP   : aBackGroundColor := $87CEEB; // SkyBlue
          IPPROTO_RAW    : aBackGroundColor := $F5DEB3; // Wheat
        else
          Result := False;
        end;      
      end;
     ETH_P_IPV6 :
      case aProtocol of
          0,
          129 : aBackGroundColor := COLOR_ICMP; //ICMP
          4   : aBackGroundColor := TCP_COLOR;  //TCP
          6   : aBackGroundColor := UDP_COLOR;  //TCP
      else
        Result := False;              
      end;
      ETH_P_ARP : aBackGroundColor := 14151930; //ARP

  else
    Result := False;
  end;

  if Result then
    aFontColor := GetFontColor(aBackGroundColor);
end;


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

function AnalyzeUDPProtocol(const aData:Pbyte;aSize:Integer;var aArcronymName:String;var aIdProtoDetected:Byte):boolean;
var LUDPPtr        : PUDPHdr;
    LUDPPayLoad    : PByte;
    I              : Integer;
begin
  Result        := False;
  if not GetHeaderUDP(aData,aSize,LUDPPtr) then exit;
  
  aIdProtoDetected := DETECT_PROTO_UDP;
  LUDPPayLoad      := GetUDPPayLoad(aData);

  {HOW can use a List ??}  
  if TWPcapProtocolL2TP.IsValid(LUDPPtr,LUDPPayLoad,aArcronymName,aIdProtoDetected) then
  begin
    Result := true;
    Exit;
  end;

  if IsDropboxPacket(LUDPPtr) then
  begin
    Result := true;
    Exit;
  end;  

  if TWPcapProtocolDNS.IsValid(LUDPPtr,LUDPPayLoad,aArcronymName,aIdProtoDetected) then
  begin
    Result := true;
    Exit;
  end;  

  if TWPcapProtocolNTP.IsValid(LUDPPtr,LUDPPayLoad,aArcronymName,aIdProtoDetected) then
  begin
    Result := True;
    Exit;
  end;  

  if TWPcapProtocolMDNS.IsValid(LUDPPtr,LUDPPayLoad,aArcronymName,aIdProtoDetected) then
  begin
    Result := True;
    Exit;
  end;  

  if TWPcapProtocolLLMNR.IsValid(LUDPPtr,LUDPPayLoad,aArcronymName,aIdProtoDetected) then
  begin
    Result := True;
    Exit;
  end;  
  
end;

function IsDropboxPacket(const aUDPPtr: PUDPHdr): Boolean;
begin
  {  by NDPI reader
   if(protocol == IPPROTO_UDP) {
    if((sport == dport) && (sport == 17500)) {
      return(NDPI_PROTOCOL_DROPBOX);
  }
  Result := (aUDPPtr.SrcPort = aUDPPtr.DstPort) and (aUDPPtr.SrcPort = 17500);    
end;


end.
