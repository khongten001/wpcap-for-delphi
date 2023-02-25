unit wpcap.Protocol.L2TP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, WinSock2, wpcap.Protocol.UDP, wpcap.Types,System.StrUtils,
  System.SysUtils, System.Variants,WinApi.Windows,wpcap.BufferUtils,System.Win.ScktComp;

type
  {https://datatracker.ietf.org/doc/html/rfc2661#section-5.1}

{
   |T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Tunnel ID           |           Session ID          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             Ns (opt)          |             Nr (opt)          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Offset Size (opt)        |    Offset pad... (opt)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Figure 3.1 L2TP Message Header

}  

  /// <summary>
  /// Represents the header for the Layer 2 Tunneling Protocol (L2TP).
  /// </summary>
  PL2TPHdr = ^TL2TPHdr;
  TL2TPHdr = packed record
    Flags     : byte;      // Flags for the L2TP header.
    Version   : byte;
  end;

  PTL2TPHdrInternal = ^TL2TPHdrInternal;
  TL2TPHdrInternal = packed record
    Flags     : byte;      // Flags for the L2TP header.
    Version   : byte;
    Length    : Word;      // Length of the L2TP header and payload.
    TunnelId  : Word;      // Identifier for the L2TP tunnel.
    SessionId : Word;      // Identifier for the L2TP session.
    Ns        : Word;      // Next sequence number for this session.
    Nr        : Word;      // Next received sequence number for this session.
    OffsetSize: Word;      // Size of the optional offset field in the header.
    OffsetPad: Word;       // Size of the optional offset field in the header.    
  end;

  
  /// <summary>
  /// Represents the Layer 2 Tunneling Protocol (L2TP) implementation for the WPcap library, which provides access to network traffic on Windows.
  /// </summary>
  TWPcapProtocolL2TP = Class(TWPcapProtocolBaseUDP)
  private
    class function GetL2TPFlag(aFlags: Word;AListDetail: TListHeaderString): string; static;
    class function ParseL2TPControlAVP(PayloadData: PByte;
      AListDetail: TListHeaderString;aLengthPayload:word): string; static;
    class function L2TPAVPTypeToString(AVPType: Word): string; static;
    class function LenghtIsPresent(aFlags: Word): Boolean; static;
    class function SequencePresent(aFlags: Word): Boolean; static;
    class function OffSetIsPresent(aFlags: Word): Boolean; static;
  public
    /// <summary>
    /// Returns the default port number used by the L2TP protocol (1701).
    /// </summary>
    class Function DefaultPort: Word;override;

    /// <summary>
    /// Return Intenal protocol ID
    /// </summary>
    class function IDDetectProto: byte; override;
    
    /// <summary>
    /// Returns the name of the protocol for the L2TP protocol
    /// </summary>
    class function ProtoName: String; override;

    /// <summary>
    /// Returns the acronym name for the L2TP protocol ("L2TP").
    /// </summary>
    class function AcronymName: String; override;

    /// <summary>
    /// Returns the length of the L2TP header in bytes.
    /// </summary>
    class function HeaderLength(aFlag:Byte): word; override;

    /// <summary>
    /// Determines whether the given UDP packet contains a valid L2TP header and payload.
    /// </summary>
    class function IsValid(const aPacket:PByte;aPacketSize:Integer;var aAcronymName:String;var aIdProtoDetected:Byte): Boolean;override;

    /// <summary>
    /// Returns a pointer to the L2TP header within the given UDP payload.
    /// </summary>
    class Function Header(const aUDPPayLoad:PByte):PTL2TPHdrInternal;   
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
  end;  



implementation


{ TWPcapProtocolDNS }

class function TWPcapProtocolL2TP.DefaultPort: Word;
begin
  Result := PROTO_L2TP_PORT;
end;

class function TWPcapProtocolL2TP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_L2TP;
end;

class function TWPcapProtocolL2TP.ProtoName: String;
begin
  Result := 'Layer 2 Tunneling Protocol';
end;

class function TWPcapProtocolL2TP.AcronymName: String;
begin
  Result := 'L2TP';
end;

class function TWPcapProtocolL2TP.HeaderLength(aFlag:Byte): word;
begin
  Result := SizeOf(TL2TPHdr)+ (SizeOf(word)*2); // lenght structure fixed

  if LenghtIsPresent(aFlag) then
    inc(Result,SizeOf(word));
  
  if SequencePresent(aFlag) then
    inc(Result,SizeOf(word));

  if OffSetIsPresent(aFlag) then
    inc(Result,SizeOf(word));  
end;

class function TWPcapProtocolL2TP.IsValid(const aPacket:PByte;aPacketSize:Integer;var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
const L2TP_MAGIC_COOKIE = 3355574314; 
      L2TP_VERSION      = 2;  
var LL2TPHdr    : PTL2TPHdrInternal;
    Lcoockie    : Pcardinal;
    LPUDPHdr    : PUDPHdr;
    LUDPPayLoad : Pbyte;
begin
  Result := False;
  if not HeaderUDP(aPacket,aPacketSize,LPUDPHdr) then Exit;
  if not PayLoadLengthIsValid(LPUDPHdr) then  Exit;
  LUDPPayLoad := GetUDPPayLoad(aPacket,aPacketSize);
    
  LL2TPHdr := Header(LUDPPayLoad);
  Try
    {4 byte after UDP header for test L2TP_MAGIC_COOKIE}
    Lcoockie  := PCardinal(LUDPPayLoad);
    
    if ntohl(Lcoockie^) <> L2TP_MAGIC_COOKIE then Exit;

    Result := ( LL2TPHdr.Version = L2TP_VERSION) and
              ( wpcapntohs(LL2TPHdr.Length) = UDPPayLoadLength(LPUDPHdr)-8);
    if Result then
    begin
      aAcronymName     := AcronymName;
      aIdProtoDetected := IDDetectProto;
    end;
  Finally
    Dispose(LL2TPHdr);
  End;
end;


class function TWPcapProtocolL2TP.Header(const aUDPPayLoad: PByte): PTL2TPHdrInternal;
var aBaseStructure : PL2TPHdr;
    aCurrentPos    : Word;
begin

{
   |T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Tunnel ID           |           Session ID          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             Ns (opt)          |             Nr (opt)          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      Offset Size (opt)        |    Offset pad... (opt)
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   Figure 3.1 L2TP Message Header

}  
  aBaseStructure := PL2TPHdr(aUDPPayLoad);
  aCurrentPos    := SizeOf(TL2TPHdr);
  
  New(Result);
  Result.Flags   := aBaseStructure.Flags;
  Result.Version := aBaseStructure.Version;
    
  if LenghtIsPresent(aBaseStructure.Flags) then
  begin
    Result.Length := Pword(aUDPPayLoad +aCurrentPos)^; 
    inc(aCurrentPos,SizeOf(Result.TunnelId));
  end;

  Result.TunnelId := Pword(aUDPPayLoad +aCurrentPos)^; 
  inc(aCurrentPos,SizeOf(Result.SessionId));

  Result.SessionId :=Pword(aUDPPayLoad +aCurrentPos)^; 
  inc(aCurrentPos,SizeOf(Result.Ns));
  
  if SequencePresent(aBaseStructure.Flags) then
  begin    
    Result.Ns := Pword(aUDPPayLoad +aCurrentPos)^; 
    inc(aCurrentPos,SizeOf(Result.Nr));
    Result.Nr := Pword(aUDPPayLoad +aCurrentPos)^; 
    inc(aCurrentPos,SizeOf(Result.Nr));
  end;

  if OffSetIsPresent(aBaseStructure.Flags) then
  begin    
    Result.OffsetSize := Pword(aUDPPayLoad +aCurrentPos)^; 
    inc(aCurrentPos,SizeOf(Result.OffsetPad));
    Result.OffsetPad := Pword(aUDPPayLoad +aCurrentPos)^; 
    inc(aCurrentPos,SizeOf(Result.OffsetSize));
  end;

end;

class function TWPcapProtocolL2TP.L2TPAVPTypeToString(AVPType: Word): string;
begin
  case AVPType of
    0:   Result := 'Control message';
    1:   Result := 'Message Type';
    2:   Result := 'Result Code';
    3:   Result := 'Protocol Version';
    4:   Result := 'Framing Capabilities';
    5:   Result := 'Bearer Capabilities';
    6:   Result := 'Tie Breaker';
    7:   Result := 'Firmware Revision';
    8:   Result := 'Host Name';
    9:   Result := 'Vendor Name';
    10:  Result := 'Assigned Tunnel ID';
    11:  Result := 'Receive Window Size';
    12:  Result := 'Challenge';
    13:  Result := 'Challenge Response';
    14:  Result := 'Assigned Session ID';
    15:  Result := 'Call Serial Number';
    16:  Result := 'Minimum BPS';
    17:  Result := 'Maximum BPS';
    18:  Result := 'Bearer Type';
    19:  Result := 'Framing Type';
    20:  Result := 'Called Number';
    21:  Result := 'Calling Number';
    22:  Result := 'Sub-Address';
    23:  Result := 'Tx Connect Speed';
    24:  Result := 'Physical Channel ID';
    25:  Result := 'Initial Receive Conf';
    26:  Result := 'Last Sent Conf';
    27:  Result := 'Proxy Authen Type';
    28:  Result := 'Proxy Authen Name';
    29:  Result := 'Proxy Authen Challenge';
    30:  Result := 'Proxy Authen ID';
    31:  Result := 'Proxy Authen Response';
    32:  Result := 'Call Errors';
    33:  Result := 'Accm';
    34:  Result := 'Random Vector';
    35:  Result := 'Private Group ID';
    36:  Result := 'Proxy Type';
    37:  Result := 'Proxy Length';
    38:  Result := 'Bearer Specific Extensions';
    39:  Result := 'Receive Sequence Number';
    40:  Result := 'Circuit Status';
    41:  Result := 'Class';
    42:  Result := 'Vendor Specific';
    43:  Result := 'Session ID';
    44:  Result := 'Bearer Information';
    45:  Result := 'Framing Information';
    46:  Result := 'Connect Speed';
    47:  Result := 'Calling Sub-Address';
    48:  Result := 'Called Sub-Address';
    49:  Result := 'Tx Connect Time';
    50:  Result := 'Proxy Authen Window';
    51:  Result := 'Status Info';
    52:  Result := 'Acct Session ID';
    53:  Result := 'Acct Multi-Session ID';
    54:  Result := 'Acct Link Count';
    55:  Result := 'Acct Input Octets';
    56:  Result := 'Acct Output Octets';
    57:  Result := 'Acct Input Packets';
    58:  Result := 'Acct Output Packets';
    59:  Result := 'Acct Terminate Cause';
    60:  Result := 'Acct Multi-Session ID Valid';
    61:  Result := 'Acct Primary Session ID';
    62:  Result := 'Acct Secondary Session ID';
    63:  Result := 'Acct Orig Session ID';
    64:  Result := 'Acct Session Time';
    65:  Result := 'Acct Authentic';
    66:  Result := 'Acct Session Chargeable';
    67:  Result := 'Acct Interim Interval';
    68:  Result := 'Acct Output Gigawords';
    69:  Result := 'Acct Input Gigawords';
    70:  Result := 'Event Timestamp';
    71:  Result := 'Egress VRF Name';
    72:  Result := 'Ingress VRF Name';
    73:  Result := 'Source IPv6 Address';
    74:  Result := 'Destination IPv6 Address';
    75:  Result := 'Source IPv6 Prefix';
    76:  Result := 'Destination IPv6 Prefix';
    77:  Result := 'MPLS Label Stack';
    78:  Result := 'MPLS Label Stack Depth';
    79:  Result := 'MPLS Top Label';
    80:  Result := 'MPLS TTL';
    81:  Result := 'MPLS BOS';
    82:  Result := 'MPLS Label Range';
    83:  Result := 'MPLS Upstream Label';
    84:  Result := 'MPLS Downstream Label';
    85:  Result := 'MPLS Pseudowire ID';
    86:  Result := 'MPLS Access Loop ID';
    87:  Result := 'MPLS Type';
    88:  Result := 'Source MAC Address';
    89:  Result := 'Destination MAC Address';
    90:  Result := 'Flow ID';
    91:  Result := 'ECID';
    92:  Result := 'Bypass ID';
    93:  Result := 'Remote Endpoint ID';
    94:  Result := 'Local Endpoint ID';
    95:  Result := 'Local Session ID';
    96:  Result := 'Remote Session ID';
    97:  Result := 'IPv4 Rate Limit';
    98:  Result := 'IPv4 Bucket Size';
    99:  Result := 'IPv4 Tokens';
    100: Result := 'IPv6 Rate Limit';
    101: Result := 'IPv6 Bucket Size';
    102: Result := 'IPv6 Tokens';
    103: Result := 'NAT Information';
    104: Result := 'Remote Endpoint IP Information';
    105: Result := 'Local Endpoint IP Information';
    106: Result := 'Service ID';
    107: Result := 'QoS Parameters';
    108: Result := 'Transit VLAN ID';
    109: Result := 'Transit Service Name';
    110: Result := 'IPv6 Prefix Pool';
    111: Result := 'Subscriber Information';
    112: Result := 'Subscription ID';
    113: Result := 'Remote MAC Address';
    114: Result := 'Session Priority';
    115: Result := 'Home Gateway IP Address';
    116: Result := 'Home Gateway IPv6 Address';
    117: Result := 'IPv4 MTU';
    118: Result := 'IPv6 MTU';
    119: Result := 'Outer VLAN ID';
    120: Result := 'Inner VLAN ID';
    121: Result := 'Originating Line Info';
    122: Result := 'NAS-Port-Type';
    123: Result := 'Source Port';
    124: Result := 'Destination Port';
    125: Result := 'Message Authenticator';
    126: Result := 'Proxy State';
    127: Result := 'Proxy Information';
    128: Result := 'NAS-Identifier';
    129: Result := 'Proxy Action';
    130: Result := 'Location ID';
    131: Result := 'Location Name';
    132: Result := 'Location Type';
    133: Result := 'Location Data';
    134: Result := 'ATM VC';
    135: Result := 'ATM VC Type';
    136: Result := 'ATM CLP';
    137: Result := 'ATM NNI';
    138: Result := 'ATM OAM VPI';
    139: Result := 'ATM OAM VCI';
    140: Result := 'IP Technology Type';
    141: Result := 'IPv6 ND Cache Parameters';
    142: Result := 'Framed Pool ID';
    143: Result := 'Class of Service';
    144: Result := 'Tunnel Type';
    145: Result := 'Tunnel Medium Type';
    146: Result := 'Tunnel Client Endpoint';
    147: Result := 'Tunnel Server Endpoint';
    148: Result := 'Acct Tunnel Connection';
    149: Result := 'Tunnel Password';
    150: Result := 'Tunnel Private Group ID';
    151: Result := 'Tunnel Assignment ID';
    152: Result := 'Tunnel Preference';
    153: Result := 'ARAP Password';
    154: Result := 'ARAP Features';
    155: Result := 'ARAP Zone Access';
    156: Result := 'ARAP Security';
    157: Result := 'ARAP Security Data';
    158: Result := 'Password Retry';
    159: Result := 'Prompt';
    160: Result := 'Connect Info';
    161: Result := 'Configuration Token';
    162: Result := 'EAP-Message';
    163: Result := 'Signature';
    164: Result := 'ARAP Challenge Response';
    165: Result := 'Acct Interim Interval Valid';
    166: Result := 'ARAP Password Change Reason';
    167: Result := 'ARAP Password Change Date';
    168: Result := 'Protocol Support';
    169: Result := 'Framed Management Protocol';
    170: Result := 'Management Transport Protection';
    171: Result := 'Management Policy ID';
    172: Result := 'Management Privilege Level';
    173: Result := 'PKINIT Anchor';
    174: Result := 'CoA Information';
    175: Result := 'Effective Policy ID';
    176: Result := 'Effective Policy Name';
    177: Result := 'User Profile';
    178: Result := 'Acct Input Octets64';
    179: Result := 'Acct Output Octets64';
    180: Result := 'Access Point Name';
    181: Result := 'Event Sub Type';
    182: Result := 'Circuit ID';
    183: Result := 'Vendor-Specific';
    184: Result := 'Dialout Allowed';
    185: Result := 'Filter ID';
    186: Result := 'Prompt Time';
    187: Result := 'Idle Timeout';
    188: Result := 'Connect Progress';
    189: Result := 'Disconnect Cause';
    190: Result := 'Calling Station ID';
    191: Result := 'Called Station ID';
    192: Result := 'NAS-Port-Id';
    193: Result := 'Framed-IP-Address';
    194: Result := 'Framed-IP-Netmask';
    195: Result := 'Framed-IP-Route';
    196: Result := 'Filter-Id';
    197: Result := 'Framed-AppleTalk-Link';
    198: Result := 'Framed-AppleTalk-Network';
    199: Result := 'Framed-AppleTalk-Zone';
    200: Result := 'Acct-Input-Packets';
    201: Result := 'Acct-Output-Packets';
    202: Result := 'Acct-Session-Id';
    203: Result := 'Acct-Authentic';
    204: Result := 'Acct-Session-Time';
    205: Result := 'Acct-Input-Gigawords';
    206: Result := 'Acct-Output-Gigawords';
    207: Result := 'Unassigned';
    208: Result := 'Event-Timestamp';
    209: Result := 'Egress-VLANID';
    210: Result := 'Ingress-Filters';
    211: Result := 'Egress-VLAN-Name';
    212: Result := 'User-Name';
    213: Result := 'VLAN-Name';
    214: Result := 'Filter-Name';
    215: Result := 'IPv6-Interface-ID';
    216: Result := 'IPv6-Client-IP-Address';
    217: Result := 'IPv6-Server-IP-Address';
    218: Result := 'RADIUS-IPv6-Prefix';
    219: Result := 'Framed-IPv6-Prefix';
    220: Result := 'Login-IPv6-Host';
    221: Result := 'Framed-IPv6-Route';
    222: Result := 'Framed-IPv6-Pool';
    223: Result := 'Error-Cause';
    224: Result := 'EAP-Key-Name';
    225: Result := 'Digest-Response';
    226: Result := 'Digest-Realm';
    227: Result := 'Digest-Nonce';
    228: Result := 'Digest-Response-Auth';
    229: Result := 'Digest-Nextnonce';
    230: Result := 'Digest-Method';
    231: Result := 'Digest-URI';
    232: Result := 'Digest-Qop';
    233: Result := 'Digest-Algorithm';
    234: Result := 'Digest-Entity-Body-Hash';
    235: Result := 'Digest-CNonce';
    236: Result := 'Digest-Nonce-Count';
    237: Result := 'Digest-Username';
    238: Result := 'Digest-Opaque';
    239: Result := 'Digest-Auth-Param';
    240: Result := 'Digest-AKA-Auts';
    241: Result := 'Digest-Domain';
    242: Result := 'Digest-Stale';
    243: Result := 'Digest-HA1';
    244: Result := 'SIP-AOR';
    245: Result := 'Delegated-IPv6-Prefix';
    246: Result := 'MIP6-Feature-Vector';
    247: Result := 'MIP6-Home-Link-Prefix';
    248: Result := 'Operator-Name';
    249: Result := 'Location-Information';
    250: Result := 'Location';
    251: Result := 'Location-Data';
    252: Result := 'Basic-Location-Policy-Rules';
    253: Result := 'Extended-Location-Policy-Rules';
    254: Result := 'Location-Capable';
    255: Result := 'Requested-Location-Info';    
  end;
end;

class function TWPcapProtocolL2TP.LenghtIsPresent(aFlags:Word):Boolean;
begin
  Result := GetBitValue(aFlags,2) =1;
end;

class function TWPcapProtocolL2TP.SequencePresent(aFlags:Word):Boolean;
begin
  Result := GetBitValue(aFlags,5) =1;
end;

class function TWPcapProtocolL2TP.OffSetIsPresent(aFlags:Word):Boolean;
begin
  Result := GetBitValue(aFlags,7) =1;
end;

class function TWPcapProtocolL2TP.GetL2TPFlag(aFlags: Word;AListDetail:TListHeaderString): string;
begin
{
   |T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)         |

   The Type (T) bit indicates the type of message. It is set to 0 for a
   data message and 1 for a control message.

   If the Length (L) bit is 1, the Length field is present. This bit
   MUST be set to 1 for control messages.

   The x bits are reserved for future extensions. All reserved bits MUST
   be set to 0 on outgoing messages and ignored on incoming messages.

   If the Sequence (S) bit is set to 1 the Ns and Nr fields are present.
   The S bit MUST be set to 1 for control messages.

   If the Offset (O) bit is 1, the Offset Size field is present. The O
   bit MUST be set to 0 (zero) for control messages.

   If the Priority (P) bit is 1, this data message should receive
   preferential treatment in its local queuing and transmission.  LCP
   echo requests used as a keepalive for the link, for instance, should
   generally be sent with this bit set to 1. Without it, a temporary
   interval of local congestion could result in interference with
   keepalive messages and unnecessary loss of the link. This feature is
   only for use with data messages. The P bit MUST be set to 0 for all
   control messages.
}
  Result := Format('Message type [%d]',[GetBitValue(aFlags,1)]);
  AListDetail.Add(AddHeaderInfo(2, 'Message type:',ifthen(GetBitValue(aFlags,1)=1,'control message','data message'),nil,0));  
  
  Result :=  Format('%s LengthIncluded %s ',[Result,BoolToStr(LenghtIsPresent(aFlags),True)]);
  AListDetail.Add(AddHeaderInfo(2, 'Length is present:',LenghtIsPresent(aFlags),nil,0));

  Result :=  Format('%s SequenceIncluded %s ',[Result,BoolToStr(SequencePresent(aFlags),True)]);
  AListDetail.Add(AddHeaderInfo(2, 'Sequence is present:',SequencePresent(aFlags),nil,0));

  Result :=  Format('%s OffsetIncluded %s ',[Result,BoolToStr(OffSetIsPresent(aFlags),True)]);
  AListDetail.Add(AddHeaderInfo(2, 'Offset is present:',OffSetIsPresent(aFlags),nil,0));

  Result :=  Format('%s Priority %s ',[Result,BoolToStr(GetBitValue(aFlags,8)=1,True)]);
  AListDetail.Add(AddHeaderInfo(2, 'Priority:',GetBitValue(aFlags,8)=1,nil,0));
end;

class function TWPcapProtocolL2TP.HeaderToString(const aPacketData: PByte; aPacketSize: Integer; AListDetail: TListHeaderString): Boolean; 
var LHeaderL2TP: PTL2TPHdrInternal;
    LPUDPHdr   : PUDPHdr;
    LUDPPayLoad: PByte;
begin

  Result := False;
  if not HeaderUDP(aPacketData, aPacketSize, LPUDPHdr) then Exit;
  LUDPPayLoad := GetUDPPayLoad(aPacketData, aPacketSize);
  LHeaderL2TP := Header(LUDPPayLoad);
  Try
    if not Assigned(LHeaderL2TP) then exit;
  
    AListDetail.Add(AddHeaderInfo(0, Format('%s (%s)', [ProtoName, AcronymName]), null, PByte(LHeaderL2TP), HeaderLength(LHeaderL2TP.Flags)));
    AListDetail.Add(AddHeaderInfo(1, 'Flags',ByteToBinaryString(LHeaderL2TP.Flags), @LHeaderL2TP.flags, SizeOf(LHeaderL2TP.flags)));
    GetL2TPFlag(LHeaderL2TP.Flags,AListDetail);
    AListDetail.Add(AddHeaderInfo(1, 'Version', LHeaderL2TP.Version, @LHeaderL2TP.Version, SizeOf(LHeaderL2TP.Version)));
    if LenghtIsPresent(LHeaderL2TP.Flags) then    
      AListDetail.Add(AddHeaderInfo(1, 'Length', wpcapntohs(LHeaderL2TP.Length), @LHeaderL2TP.Length, SizeOf(LHeaderL2TP.Length)));
    AListDetail.Add(AddHeaderInfo(1, 'Tunnel ID', wpcapntohs(LHeaderL2TP.tunnelID), @LHeaderL2TP.tunnelID, SizeOf(LHeaderL2TP.tunnelID)));
    AListDetail.Add(AddHeaderInfo(1, 'Session ID', wpcapntohs(LHeaderL2TP.SessionId), @LHeaderL2TP.sessionID, SizeOf(LHeaderL2TP.sessionID)));
    if SequencePresent(LHeaderL2TP.Flags) then    
    begin
      AListDetail.Add(AddHeaderInfo(1, 'Next sequence', wpcapntohs(LHeaderL2TP.Ns), @LHeaderL2TP.Ns, SizeOf(LHeaderL2TP.Ns)));
      AListDetail.Add(AddHeaderInfo(1, 'Next received', wpcapntohs(LHeaderL2TP.Nr), @LHeaderL2TP.Nr, SizeOf(LHeaderL2TP.Nr)));
    end;

    if OffSetIsPresent(LHeaderL2TP.Flags) then    
    begin    
      AListDetail.Add(AddHeaderInfo(1, 'Offset size',wpcapntohs(LHeaderL2TP.OffsetSize), @LHeaderL2TP.OffsetSize, SizeOf(LHeaderL2TP.OffsetSize))); 
      AListDetail.Add(AddHeaderInfo(1, 'Offset pad',wpcapntohs(LHeaderL2TP.OffsetPad), @LHeaderL2TP.OffsetSize, SizeOf(LHeaderL2TP.OffsetSize)));  
    end;
       
    if LHeaderL2TP.Length > HeaderEthSize then
    begin
      // Parse L2TP payload for control message AVP
      if LHeaderL2TP.Version = 2 then    
      begin
        ParseL2TPControlAVP(@LUDPPayLoad[HeaderEthSize],AListDetail,wpcapntohs(LHeaderL2TP.Length));
        {TODO MESSAGE CONTROL}
      end;
      {TODO version 3}
    end;
    Result := True;
  Finally
    Dispose(LHeaderL2TP);
  End;
end;


class function TWPcapProtocolL2TP.ParseL2TPControlAVP(PayloadData: PByte;AListDetail: TListHeaderString;aLengthPayload:word): string;
type
  TAVPHeader = packed record
    AvpType  : Word;
    AvtFlag  : Byte; //   Flags    : Byte;   // R (1 bit) + F (1 bit) + Vendor-ID (1 bit) + Padding (5 bits)    
    AvpLength: Array [1..3] of byte;
  end;
  PAVPHeader = ^TAVPHeader;

var LAvpHeader      : TAVPHeader;
    LAvpType        : Word;
    LAvpLength      : Word;
    LAvpValue       : Cardinal;
    LCurrentPos     : Integer;
    LResultStr      : string;
    LFlagsAndLength : word;
begin
  LResultStr := String.Empty;

  // Start from the beginning of the payload
  LCurrentPos := 0;

  // Loop through the payload data until the end is reached
  while LCurrentPos < aLengthPayload do
  begin
    // Extract AVP header information
    LAvpHeader := PAVPHeader(PayloadData + LCurrentPos)^;
    LAvpType   := wpcapntohs(LAvpHeader.AvpType);

    AListDetail.Add(AddHeaderInfo(1, Format('AVP %s [%d]', [L2TPAVPTypeToString(LAvpType),LAvpType]),null,@LAvpHeader,SizeOF(LAvpHeader))); 
    AListDetail.Add(AddHeaderInfo(2,'Type:',Format('%s [%d]', [L2TPAVPTypeToString(LAvpType),LAvpType]),@LAvpHeader.AvpType,sizeOf(LAvpHeader.AvpType)));       
    AListDetail.Add(AddHeaderInfo(2,'Flag:',LAvpHeader.AvtFlag,@LAvpHeader.AvtFlag,sizeOf(LAvpHeader.AvtFlag)));       
    {TODO BUGGED }
    LAvpLength := Pword(@(LAvpHeader.AvpLength))^;
    LAvpLength := wpcapntohs(LAvpLength);
    AListDetail.Add(AddHeaderInfo(2,'Mandatory:',(LAvpLength and $80) <> 0,PByte(LAvpLength and $80),1));
    AListDetail.Add(AddHeaderInfo(2,'Hidden:',(LAvpLength and $40) <> 0,PByte(LAvpLength and $40),1)); 
    AListDetail.Add(AddHeaderInfo(2,'Length:',(LAvpLength shr 8) and $FF,nil,0)); 
    // Add AVP type and length to the result string
    LResultStr := LResultStr + Format('AVP Type: %d, Length: %d'#13#10, [LAvpType, LAvpLength]);

    // Check if the AVP has a value
    if LAvpLength > SizeOf(TAVPHeader) then
    begin
      // Extract the AVP value from the payload data
      LResultStr := LResultStr + 'Value: ';
      Inc(LCurrentPos, SizeOf(TAVPHeader));
      case LAvpType of
        1, 2, 3, 6, 7, 8, 9, 10, 11, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30:
        begin
          // Integer AVP
          LAvpValue := ntohl(PDWORD(PayloadData + LCurrentPos)^);
          AListDetail.Add(AddHeaderInfo(2,'Message type:',LAvpValue,Pbyte(PayloadData + LCurrentPos),sizeOf(cardinal)));
          LResultStr := LResultStr + IntToStr(LAvpValue);
        end;
        4, 5, 12, 13:
        begin
          // String AVP
          AListDetail.Add(AddHeaderInfo(2,'Message type:',String(PAnsiChar(PayloadData + LCurrentPos)),Pbyte(PayloadData + LCurrentPos),sizeOf(cardinal)));              
          LResultStr := LResultStr + PAnsiChar(PayloadData + LCurrentPos);
        end
      else
        begin
          AListDetail.Add(AddHeaderInfo(2,'Message type:','Unknown AVP Type',nil,0));              
          // Unknown AVP type
          LResultStr := LResultStr + 'Unknown AVP Type';
        end;
      end;
      LResultStr := LResultStr + #13#10;

      {TODO message by AVP Type}
      // Move to the next AVP
      Inc(LCurrentPos, LAvpLength - SizeOf(TAVPHeader));
    end
    else
    begin
      // AVP has no value
      if LAvpType = 0 then
        AListDetail.Add(AddHeaderInfo(2,'Message type:','no value',nil,0));
      Inc(LCurrentPos, SizeOf(TAVPHeader));
    end;
  end;

  Result := LResultStr;
end;


end.
