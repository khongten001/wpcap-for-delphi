unit wpcap.Protocol.L2TP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, WinSock2, wpcap.Protocol.UDP, wpcap.Types,
  System.StrUtils, System.Rtti, System.SysUtils, System.Variants, WinApi.Windows,
  wpcap.BufferUtils, System.Win.ScktComp, DateUtils,wpcap.StrUtils,System.Generics.Collections;

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

  TListVendorId = TDictionary<Integer, string>;

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

  TAVPHeader = packed record
    AvtFlag   : Word;
    VendorID  : Word;
    AttrType  : Word;
  end;
  PAVPHeader = ^TAVPHeader;  

  
  /// <summary>
  /// Represents the Layer 2 Tunneling Protocol (L2TP) implementation for the WPcap library, which provides access to network traffic on Windows.
  /// </summary>
  TWPcapProtocolL2TP = Class(TWPcapProtocolBaseUDP)
  private
    class function GetL2TPFlag(aFlags: Word;AListDetail: TListHeaderString): string; static;
    class function ParseL2TPControlAVP(PayloadData: PByte;AListDetail: TListHeaderString;aLengthPayload:word;aVendorID: TListVendorId): string; static;
    class function L2TPAVPTypeToString(AVPType: Word): string; static;
    class function LenghtIsPresent(aFlags: Word): Boolean; static;
    class function SequencePresent(aFlags: Word): Boolean; static;
    class function OffSetIsPresent(aFlags: Word): Boolean; static;
    class function AvtType0ValueToString(const aAvtValue: Word): String; static;
    Class function InitVendorID: TListVendorID;Static;
    class function ReadAVPValueFromPacket(aPayloadData: PByte; aCurrentPos: Integer; aAvpLength, aAvpType: Integer;aVendorID: TListVendorId): TValue; static;
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
    ///  Converts the L2TP header to a string and adds it to the list of header details.
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
    inc(Result,SizeOf(word)*2);

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
   data message and 1 for a control message.}

  Result := Format('Message type [%d]',[GetBitValue(aFlags,1)]);
  AListDetail.Add(AddHeaderInfo(2, 'Message type:',ifthen(GetBitValue(aFlags,1)=1,'control message','data message'),nil,0));  
  
  {
   If the Length (L) bit is 1, the Length field is present. This bit
   MUST be set to 1 for control messages.
  }  
  Result :=  Format('%s LengthIncluded %s ',[Result,BoolToStr(LenghtIsPresent(aFlags),True)]);
  AListDetail.Add(AddHeaderInfo(2, 'Length is present:',LenghtIsPresent(aFlags),nil,0));

  {
    If the Sequence (S) bit is set to 1 the Ns and Nr fields are present.
    The S bit MUST be set to 1 for control messages.
  }
  Result :=  Format('%s SequenceIncluded %s ',[Result,BoolToStr(SequencePresent(aFlags),True)]);
  AListDetail.Add(AddHeaderInfo(2, 'Sequence is present:',SequencePresent(aFlags),nil,0));

  {
   If the Offset (O) bit is 1, the Offset Size field is present. The O
   bit MUST be set to 0 (zero) for control messages.
  }
  Result :=  Format('%s OffsetIncluded %s ',[Result,BoolToStr(OffSetIsPresent(aFlags),True)]);
  AListDetail.Add(AddHeaderInfo(2, 'Offset is present:',OffSetIsPresent(aFlags),nil,0));

  { If the Priority (P) bit is 1, this data message should receive
   preferential treatment in its local queuing and transmission.  LCP
   echo requests used as a keepalive for the link, for instance, should
   generally be sent with this bit set to 1. Without it, a temporary
   interval of local congestion could result in interference with
   keepalive messages and unnecessary loss of the link. This feature is
   only for use with data messages. The P bit MUST be set to 0 for all
   control messages.                                       }
  Result :=  Format('%s Priority %s ',[Result,BoolToStr(GetBitValue(aFlags,8)=1,True)]);
  AListDetail.Add(AddHeaderInfo(2, 'Priority:',GetBitValue(aFlags,8)=1,nil,0));
end;

class function TWPcapProtocolL2TP.HeaderToString(const aPacketData: PByte; aPacketSize: Integer; AListDetail: TListHeaderString): Boolean; 
var LHeaderL2TP: PTL2TPHdrInternal;
    LPUDPHdr   : PUDPHdr;
    LUDPPayLoad: PByte;
    Loffset    : Word;
    LVendorID  : TListVendorId;
begin

  Result := False;
  if not HeaderUDP(aPacketData, aPacketSize, LPUDPHdr) then Exit;
  LUDPPayLoad := GetUDPPayLoad(aPacketData, aPacketSize);
  LHeaderL2TP := Header(LUDPPayLoad);
  Try
    LVendorID := InitVendorID;  
    Try
      if not Assigned(LHeaderL2TP) then exit;
  
      AListDetail.Add(AddHeaderInfo(0, Format('%s (%s)', [ProtoName, AcronymName]), null, PByte(LHeaderL2TP), HeaderLength(LHeaderL2TP.Flags)));
      AListDetail.Add(AddHeaderInfo(1, 'Flags',ByteToBinaryString(LHeaderL2TP.Flags), @LHeaderL2TP.flags, SizeOf(LHeaderL2TP.flags)));
      GetL2TPFlag(LHeaderL2TP.Flags,AListDetail);
    
      {
       Ver MUST be 2, indicating the version of the L2TP data message header
       described in this document. The value 1 is reserved to permit
       detection of L2F [RFC2341] packets should they arrive intermixed with
       L2TP packets. Packets received with an unknown Ver field MUST be
       discarded.
      }    
      AListDetail.Add(AddHeaderInfo(1, 'Version', LHeaderL2TP.Version, @LHeaderL2TP.Version, SizeOf(LHeaderL2TP.Version)));
    
      {The Length field indicates the total length of the message in octets.}
      if LenghtIsPresent(LHeaderL2TP.Flags) then    
        AListDetail.Add(AddHeaderInfo(1, 'Length', wpcapntohs(LHeaderL2TP.Length), @LHeaderL2TP.Length, SizeOf(LHeaderL2TP.Length)));

      AListDetail.Add(AddHeaderInfo(1, 'Header length', HeaderLength(LHeaderL2TP.Flags),nil,0));
    
      {  Tunnel ID indicates the identifier for the control connection. L2TP
         tunnels are named by identifiers that have local significance only.
         That is, the same tunnel will be given different Tunnel IDs by each
         end of the tunnel. Tunnel ID in each message is that of the intended
         recipient, not the sender. Tunnel IDs are selected and exchanged as
         Assigned Tunnel ID AVPs during the creation of a tunnel.}
      AListDetail.Add(AddHeaderInfo(1, 'Tunnel ID', wpcapntohs(LHeaderL2TP.tunnelID), @LHeaderL2TP.tunnelID, SizeOf(LHeaderL2TP.tunnelID)));

       {
         Session ID indicates the identifier for a session within a tunnel.
         L2TP sessions are named by identifiers that have local significance
         only. That is, the same session will be given different Session IDs
         by each end of the session. Session ID in each message is that of the
         intended recipient, not the sender. Session IDs are selected and
         exchanged as Assigned Session ID AVPs during the creation of a
         session.
       }
      AListDetail.Add(AddHeaderInfo(1, 'Session ID', wpcapntohs(LHeaderL2TP.SessionId), @LHeaderL2TP.sessionID, SizeOf(LHeaderL2TP.sessionID)));
      if SequencePresent(LHeaderL2TP.Flags) then    
      begin
        {
         Ns indicates the sequence number for this data or control message,
         beginning at zero and incrementing by one (modulo 2**16) for each
         message sent. See Section 5.8 and 5.4 for more information on using
         this field.      
        }
        AListDetail.Add(AddHeaderInfo(1, 'Next sequence', wpcapntohs(LHeaderL2TP.Ns), @LHeaderL2TP.Ns, SizeOf(LHeaderL2TP.Ns)));
        {
         Nr indicates the sequence number expected in the next control message
         to be received.  Thus, Nr is set to the Ns of the last in-order
         message received plus one (modulo 2**16). In data messages, Nr is
         reserved and, if present (as indicated by the S-bit), MUST be ignored
         upon receipt. See section 5.8 for more information on using this
         field in control messages.
        }
        AListDetail.Add(AddHeaderInfo(1, 'Next received', wpcapntohs(LHeaderL2TP.Nr), @LHeaderL2TP.Nr, SizeOf(LHeaderL2TP.Nr)));
      end;
    
      Loffset :=0; 
      if OffSetIsPresent(LHeaderL2TP.Flags) then    
      begin    
      
        { The Offset Size field, if present, specifies the number of octets
         past the L2TP header at which the payload data is expected to start.
         Actual data within the offset padding is undefined. If the offset
         field is present, the L2TP header ends after the last octet of the
         offset padding.    }
        Loffset := wpcapntohs(LHeaderL2TP.OffsetSize);
        AListDetail.Add(AddHeaderInfo(1, 'Offset size',Loffset, @LHeaderL2TP.OffsetSize, SizeOf(LHeaderL2TP.OffsetSize))); 
      end;
       
      if UDPPayLoadLength(LPUDPHdr) > HeaderLength(LHeaderL2TP.Flags)+Loffset then
      begin
        // Parse L2TP payload for control message AVP
        if LHeaderL2TP.Version = 2 then    
        begin
          ParseL2TPControlAVP(@LUDPPayLoad[HeaderLength(LHeaderL2TP.Flags)+Loffset],AListDetail,wpcapntohs(LHeaderL2TP.Length),LVendorID);
          {TODO MESSAGE CONTROL}
        end;
        {TODO version 3}
      end;
      Result := True;
    Finally
      FreeAndNil(LVendorID);
    End;
  Finally
    Dispose(LHeaderL2TP);
  End;
end;

Class function TWPcapProtocolL2TP.AvtType0ValueToString(const aAvtValue:Word):String;
begin
  case aAvtValue of

    1 : Result := 'Authorization-Request';
    2 : Result := 'Authorization-Answer';
    3 : Result := 'Session-Termination-Request';
    4 : Result := 'Session-Termination-Answer';
    5 : Result := 'Abort-Session-Request';
    6 : Result := 'Abort-Session-Answer';
    7 : Result := 'Accounting-Request';
    8 : Result := 'Accounting-Answer';
    9 : Result := 'Device-Watchdog-Request';
    10: Result := 'Device-Watchdog-Answer';
    11: Result := 'Disconnect-Peer-Request';
    12: Result := 'Disconnect-Peer-Answer';
    13: Result := 'Device-Application-Auth-Request';
    14: Result := 'Call-Disconnect';
    15: Result := 'Re-Auth-Request';
    16: Result := 'Re-Auth-Answer';
    17: Result := 'Capability-Exchange-Request';
    18: Result := 'Capability-Exchange-Answer';
    19..31 : Result := 'Reserved';
  else
    Result := 'Unknown';
  end;

  Result := Format('%s [%d]',[result,aAvtValue])
end;

Class function TWPcapProtocolL2TP.InitVendorID: TListVendorID;
begin
  Result := TDictionary<Integer, string>.Create;
  Result.Add(0, 'IETF');
  Result.Add(9, 'Cisco Systems, Inc.');
  Result.Add(10, 'Ascend Communications, Inc.');
  Result.Add(11, 'DEC');
  Result.Add(14, 'Microsoft Corporation');
  Result.Add(18, '3Com Corporation');
  Result.Add(21, 'US Robotics Corporation');
  Result.Add(22, 'Ericsson/Redback Networks');
  Result.Add(23, 'Redback Networks');
  Result.Add(27, 'Lucent Technologies');
  Result.Add(31, 'US Robotics Corporation');
  Result.Add(41, 'Sun Microsystems, Inc.');
  Result.Add(42, 'IBM Corporation');
  Result.Add(44, 'Bay Networks, Inc.');
  Result.Add(45, 'Motorola');
  Result.Add(46, 'Northern Telecom Limited');
  Result.Add(47, 'Nortel Networks');
  Result.Add(49, 'Bay Networks, Inc.');
  Result.Add(50, 'Visual Networks, Inc.');
  Result.Add(51, 'Intel Corporation');
  Result.Add(54, '3Com Corporation');
  Result.Add(59, 'Wellfleet Communications, Inc.');
  Result.Add(60, 'Ascend Communications, Inc.');
  Result.Add(65, 'Cisco Systems, Inc.');
  Result.Add(66, 'Shiva Corporation');
  Result.Add(68, 'Digital Equipment Corporation');
  Result.Add(71, 'Livingston Enterprises, Inc.');
  Result.Add(72, 'Redback Networks');
  Result.Add(73, 'Juniper Networks');
  Result.Add(79, 'Kentrox');
  Result.Add(80, 'Westell, Inc.');
  Result.Add(85, 'Intel Corporation');
  Result.Add(90, 'Cisco Systems, Inc.');
  Result.Add(91, 'Cisco Systems, Inc.');
  Result.Add(94, 'Ascend Communications, Inc.');
  Result.Add(97, 'Nortel Networks');
  Result.Add(102, 'Intel Corporation');
  Result.Add(103, 'US Robotics Corporation');
  Result.Add(104, 'Nortel Networks');
  Result.Add(106, 'Shiva Corporation');
  Result.Add(111, 'Nortel Networks');
  Result.Add(116, 'IBM Corporation');
  Result.Add(117, '3Com Corporation');
  Result.Add(118, 'Intel Corporation');
  Result.Add(119, 'Lucent Technologies');
  Result.Add(121, 'Cisco Systems, Inc.');
  Result.Add(123, 'Nortel Networks');
  Result.Add(130, 'Cisco Systems, Inc.');
  Result.Add(135, 'Nortel Networks');
  Result.Add(138, 'Ericsson/Redback Networks');
  Result.Add(139, 'Nokia');
  Result.Add(156, 'IBM');
  Result.Add(158, 'Microsoft');
  Result.Add(163, 'Ascend');
  Result.Add(169, '3Com');
  Result.Add(170, 'Bellcore/Telcordia');
  Result.Add(171, 'Siemens');
  Result.Add(177, 'Cabletron');
  Result.Add(180, 'Bay Networks');
  Result.Add(181, 'Rapid City');
  Result.Add(186, 'Wellfleet');
  Result.Add(187, 'Xyplex');
  Result.Add(188, 'Synoptics');
  Result.Add(191, 'Cisco');
  Result.Add(196, 'Livingston');
  Result.Add(198, 'Microsoft');
  Result.Add(199, '3Com');
  Result.Add(208, 'US Robotics');
  Result.Add(211, 'Cisco Systems, Inc.');
  Result.Add(213, 'Microsoft');
  Result.Add(215, 'Bay Networks');
  Result.Add(218, 'Redback Networks');
  Result.Add(221, '3Com');
  Result.Add(223, '3Com');
  Result.Add(226, '3Com');
  Result.Add(229, 'Nortel Networks');
  Result.Add(235, 'Intel');
  Result.Add(236, 'Cisco Systems, Inc.');
  Result.Add(239, 'Cisco Systems, Inc.');
  Result.Add(245, 'Nortel Networks');
  Result.Add(251, 'Nortel Networks');
  Result.Add(254, '3Com');
  Result.Add(258, 'Cisco Systems, Inc.');
  Result.Add(259, 'Cisco Systems, Inc.');
  Result.Add(263, 'Cisco Systems, Inc.');
  Result.Add(267, 'Nortel Networks');
  Result.Add(273, 'Nortel Networks');
  Result.Add(276, 'Nortel Networks');
  Result.Add(279, 'Nortel Networks');
  Result.Add(282, 'Nortel Networks');
  Result.Add(285, 'Nortel Networks');
  Result.Add(291, 'Nortel Networks');
  Result.Add(293, 'Nortel Networks');
  Result.Add(298, 'Nortel Networks');
  Result.Add(303, 'Cisco Systems, Inc.');
  Result.Add(306, 'Cisco Systems, Inc.');
  Result.Add(311, 'Nortel Networks');
  Result.Add(315, 'Microsoft Corporation');
  Result.Add(317, 'Cisco Systems, Inc.');
  Result.Add(318, 'Cisco Systems, Inc.');
  Result.Add(320, 'Nortel Networks');
  Result.Add(322, 'Intel Corporation');
  Result.Add(324, 'Cisco Systems, Inc.');
  Result.Add(326, 'Nortel Networks');
  Result.Add(329, 'Nortel Networks');
  Result.Add(332, 'Cisco Systems, Inc.');
  Result.Add(335, 'Nortel Networks');
  Result.Add(337, 'Nortel Networks');
  Result.Add(338, 'Nortel Networks');
  Result.Add(339, 'Nortel Networks');
  Result.Add(342, 'Nortel Networks');
  Result.Add(344, 'Nortel Networks');
  Result.Add(345, 'Nortel Networks');
  Result.Add(346, 'Nortel Networks');
  Result.Add(348, 'Nortel Networks');
  Result.Add(351, 'Nortel Networks');
  Result.Add(352, 'Nortel Networks');
  Result.Add(354, 'Nortel Networks');
  Result.Add(356, 'Nortel Networks');
  Result.Add(360, 'Cisco Systems, Inc.');
  Result.Add(364, 'Nortel Networks');
  Result.Add(366, 'Nortel Networks');
  Result.Add(368, 'Nortel Networks');
  Result.Add(370, 'Nortel Networks');
  Result.Add(372, 'Nortel Networks');
  Result.Add(373, 'Nortel Networks');
  Result.Add(376, 'Nortel Networks');
  Result.Add(377, 'Nortel Networks');
  Result.Add(379, 'Nortel Networks');
  Result.Add(381, 'Nortel Networks');
  Result.Add(382, 'Nortel Networks');
  Result.Add(385, 'Nortel Networks');
  Result.Add(386, 'Nortel Networks');
  Result.Add(388, 'Nortel Networks');
  Result.Add(389, 'Nortel Networks');
  Result.Add(391, 'Nortel Networks');
  Result.Add(393, 'Nortel Networks');
  Result.Add(397, 'Nortel Networks');
  Result.Add(398, 'Nortel Networks');
  Result.Add(399, 'Nortel Networks');
  Result.Add(400, 'Nortel Networks');
  Result.Add(402, 'Nortel Networks');
  Result.Add(404, 'Nortel Networks');
  Result.Add(406, 'Nortel Networks');
  Result.Add(408, 'Nortel Networks');
  Result.Add(411, 'Nortel Networks');
  Result.Add(412, 'Nortel Networks');
  Result.Add(415, 'Nortel Networks');
  Result.Add(416, 'Nortel Networks');
  Result.Add(417, 'Nortel Networks');
  Result.Add(419, 'Nortel Networks');
  Result.Add(420, 'Nortel Networks');
  Result.Add(422, 'Nortel Networks');
  Result.Add(424, 'Nortel Networks');
  Result.Add(427, 'Nortel Networks');
  Result.Add(430, 'Nortel Networks');
  Result.Add(432, 'Nortel Networks');
  Result.Add(434, 'Nortel Networks');
  Result.Add(436, 'Nortel Networks');
end;

Class function TWPcapProtocolL2TP.ReadAVPValueFromPacket(aPayloadData: PByte; aCurrentPos: Integer; aAvpLength: Integer; aAvpType: Integer;aVendorID: TListVendorId): TValue;
var ByteValue         : Byte;
    IntValue          : Integer;
    Int64Value        : Int64;
    UIntValue         : Cardinal;
    LongValue         : LongWord;
    UInt64Value       : UInt64;
    RawValue          : TBytes;
    FloatValue        : Extended;
    I                 : Integer;
    OctetStringValue  : string;
    AddressValue      : string;
    TimeValue         : TDateTime;
    GroupedValue      : string;
    TimeStampValue    : TDateTime;
    UTF8StringValue   : string;
    AvpLen            : Cardinal;
    Value             : Tvalue;
    IP6Bytes          : array of byte;
begin
  case aAvpType of
    0: // Integer32 AVP
      begin
        IntValue    := wpcapntohs(PInteger(aPayloadData + aCurrentPos)^);      
        Result      := TValue.From<String>(AvtType0ValueToString(IntValue));
      end;
    14,12,20,31,63,67,124,88,89,90,94,95,98,99,100,114: // Enumer ,Integer32
      begin
        IntValue    := wpcapntohs(PInteger(aPayloadData + aCurrentPos)^);      
        Result      := TValue.From<Integer>(IntValue);
      end;    
    1,21,68,122,123,71,73: // Integer64 AVP
      begin
        Int64Value  := PInt64(aPayloadData + aCurrentPos)^;      
        Result      := TValue.From<Int64>(Int64Value);
      end;
    2,44,118,120,121, 72,74,75: // Unsigned32 AVP
      begin
        UIntValue   := PCardinal(aPayloadData + aCurrentPos)^;
        Result      := TValue.From<Cardinal>(UIntValue);
      end;
         
    3,45: // Unsigned64 AVP
      begin
        UInt64Value := PUInt64(aPayloadData + aCurrentPos)^;        
        Result      := TValue.From<UInt64>(UInt64Value);
      end;
    4, 5,22,23: // Float32, Float64 AVP
      begin
        FloatValue  := PExtended(aPayloadData + aCurrentPos)^;
        Result      := TValue.From<Extended>(FloatValue);
      end;
      
    6, 7, 8, 9, 10, 11,13,15,18,19,29,30,33,34,36,39,40,46,53,54,55,91,96,51,52,57,80,126,127,134,159,135, 163,
    164, 165, 166,138, 154, 155, 156, 157, 158,141,59,60,61,62,66,69,70,77,79,92,93: // OctetString, String, DiamIdent, Address, Time, Grouped AVP,UTF8String AVP
      begin
        OctetStringValue := String(PAnsiChar(aPayloadData + aCurrentPos));        
        case aAvpType of
          6,11,13,18,19,29,30,33,46,91,96,59,60,61,62,66,69,70,77,79,92,93: // OctetString AVP
            Result := TValue.From<string>(OctetStringValue);
            
          7,8,9,15,34,36,40,53,54,55,51,52,57,80,126,127,134,159,135, 163, 164, 
          165, 166,138, 154, 155, 156, 157, 158,141: // String, UTF8String AVP
            Result := TValue.From<string>(UTF8ToWideString(OctetStringValue));

          10,39: // Time AVP
            begin
              TimeValue := UnixToDateTime(StrToInt(OctetStringValue));
              Result    := TValue.From<TDateTime>(TimeValue);
            end;
        end;
      end;
      
    47,58: // TimeStamp AVP
      begin
        Int64Value     := PInt64(aPayloadData + aCurrentPos)^;        
        TimeStampValue := UnixToDateTime(Int64Value);
        Result         := TValue.From<TDateTime>(TimeStampValue);
      end;
    16: // Unsigned32 AVP (IPv4Address)
      begin
        UIntValue    := PCardinal(aPayloadData + aCurrentPos)^;        
        AddressValue := intToIPV4(UIntValue);
        Result       := TValue.From<string>(AddressValue);
      end;
    17: // Unsigned64 AVP (IPv6Address)
      begin
        Move(aPayloadData[aCurrentPos], IP6Bytes, SizeOf(IP6Bytes));      
        AddressValue := IPv6AddressToString(IP6Bytes);
        Result       := TValue.From<string>(AddressValue);
      end;
      
    24,119: // Time-Seconds AVP
      begin
        TimeValue   := UnixToDateTime(PInteger(aPayloadData + aCurrentPos)^);      
        Result      := TValue.From<TDateTime>(TimeValue);
      end;
      
    25: // Integer16 AVP
      begin
        IntValue    := PSmallInt(aPayloadData + aCurrentPos)^;        
        Result      := TValue.From<Integer>(IntValue);
      end;
       
    26,49,107,129, 161, 179, 245: // UnsignedShort AVP
      begin
        UIntValue   := wpcapntohs(PWord(aPayloadData + aCurrentPos)^);
        Result      := TValue.From<Cardinal>( UIntValue);
      end;
      
    27: // Integer8 AVP
      begin
        ByteValue   := PByte(aPayloadData + aCurrentPos)^;
        Result      := TValue.From<Integer>(ByteValue);
      end;

    28,50: // Unsigned8 AVP
      begin
        ByteValue   := PByte(aPayloadData + aCurrentPos)^;      
        Result      := TValue.From<Cardinal>(ByteValue);
      end;

    32: //TimeStamp AVP
      begin
        TimeStampValue := UnixToDateTime(PUInt32(aPayloadData + aCurrentPos)^);      
        Result         := TValue.From<TDateTime>(TimeStampValue);
      end;

    35: // IPAddress AVP
      begin
        AddressValue := Format('%d.%d.%d.%d', [aPayloadData[aCurrentPos], aPayloadData[aCurrentPos + 1], aPayloadData[aCurrentPos + 2], aPayloadData[aCurrentPos + 3]]);        
        Result       := TValue.From<string>(AddressValue);
      end;
      
    37: // IPv6Address AVP
      begin
        AddressValue := Format('%s:%s:%s:%s:%s:%s:%s:%s', [
                                IntToHex(aPayloadData[aCurrentPos], 2),
                                IntToHex(aPayloadData[aCurrentPos + 1], 2),
                                IntToHex(aPayloadData[aCurrentPos + 2], 2),
                                IntToHex(aPayloadData[aCurrentPos + 3], 2),
                                IntToHex(aPayloadData[aCurrentPos + 4], 2),
                                IntToHex(aPayloadData[aCurrentPos + 5], 2),
                                IntToHex(aPayloadData[aCurrentPos + 6], 2),
                                IntToHex(aPayloadData[aCurrentPos + 7], 2)]);        
        Result := TValue.From<string>(AddressValue);
      end;
      
    38: // IPv6Prefix AVP
      begin
        ByteValue := aPayloadData[aCurrentPos];
        aCurrentPos := aCurrentPos + 1;
        AddressValue := Format('%d:%s:%s:%s:%s:%s:%s:%s/%d', [
                                  ByteValue,
                                  IntToHex(aPayloadData[aCurrentPos], 2),
                                  IntToHex(aPayloadData[aCurrentPos + 1], 2),
                                  IntToHex(aPayloadData[aCurrentPos + 2], 2),
                                  IntToHex(aPayloadData[aCurrentPos + 3], 2),
                                  IntToHex(aPayloadData[aCurrentPos + 4], 2),
                                  IntToHex(aPayloadData[aCurrentPos + 5], 2),
                                  IntToHex(aPayloadData[aCurrentPos + 6], 2),
                                  aPayloadData[aCurrentPos + 7]]);
        Result := TValue.From<string>(AddressValue);
      end;
      
    41: // EUI64 AVP
      begin
        SetLength(RawValue, 8);
        Move((aPayloadData+aCurrentPos+8)^, RawValue[0], 8);        
        Result := TValue.From<TBytes>(RawValue);
      end;
    42: // IPFilterRule AVP
      begin
        OctetStringValue := String(PAnsiChar(aPayloadData + aCurrentPos));        
       // IPFilterRuleValue := ParseIPFilterRule(OctetStringValue);{Todo}
        Result            := TValue.From<string>(OctetStringValue);
      end;

    43,48,128, 145, 167, 178, 183, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195,
    196, 197, 198, 199, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214,
    215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233,
    234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255:
      begin
        ByteValue   := PByte(aPayloadData + aCurrentPos)^;        
        Result      := TValue.From<Byte>(ByteValue);
      end;  
             
    56: // MACAddress AVP
      begin
     //   AddressValue := MACAddrToStr(PayloadData + LCurrentPos);  
        Result       := TValue.From<string>(AddressValue);
      end;    


    64: //Float32 AVP
      begin
        FloatValue  := PSingle(aPayloadData + aCurrentPos)^;        
        Result      := TValue.From<Extended>(FloatValue);
      end;
    65: //Float64 AVP
      begin
        FloatValue  := PDouble(aPayloadData + aCurrentPos)^;        
        Result      := TValue.From<Extended>(FloatValue);
      end;    

    78: //Grouped AVP
      begin
        //GroupedValue := TValueDictionary.Create;
       { LCurrentPos  := LCurrentPos + 8; //Skip the Grouped AVP Header
        while LCurrentPos < StartPos + AvpLength do
        begin
          //Parse the AVP inside the Grouped AVP
          ParsedAVP := ParseAVP(PayloadData, LCurrentPos, StartPos + AvpLength);

          //Add the parsed AVP to the GroupedValue dictionary
          //GroupedValue.Add(ParsedAVP.AvpCode, ParsedAVP.Value);
        end;    }
        Result := TValue.From<String>('78: //Grouped AVP TODO');
      end;

    81,142,143,131,162, 200, 201: // Time AVP
      begin
        Int64Value   := Int64(PInt64(aPayloadData + aCurrentPos)^);        
        Result       := TValue.From<Int64>(SwapInt64(Int64Value));
      end;      
 
    82,83,84,85,86,87,104,108,109,116,111,112,113: //UTF8String AVP
      begin
        UTF8StringValue  := String(PAnsiChar(aPayloadData + aCurrentPos- aAvpLength - 8));        
        Result           := TValue.From<string>(UTF8StringValue);
      end;


    97: //Subscription-Id AVP
      begin
        aCurrentPos     := aCurrentPos + 4;
        UTF8StringValue := String(PAnsiChar(aPayloadData + aCurrentPos));        
        Result          := TValue.From<String>(UTF8StringValue); 
      end;

    105: //IP6Address AVP
      begin
        SetLength(RawValue, 16);
        Move((aPayloadData+aCurrentPos)^, RawValue[0], 16);
        Result      := TValue.From<TBytes>(RawValue);
      end;
      
    106,117: //IPFilterRule AVP
      begin
        SetLength(RawValue, aAvpLength - 8);
        Move((aPayloadData+aCurrentPos)^, RawValue[0], aAvpLength - 8);        
        Result      := TValue.From<TBytes>(RawValue);
      end;   

    125,137: // FailedAVP AVP
      begin
        GroupedValue := '';
        while aCurrentPos < aAvpLength do
        begin
          // Get the AVP Code
          UIntValue   := PCardinal(aPayloadData + aCurrentPos)^;
          aCurrentPos := aCurrentPos + SizeOf(UIntValue);

          // Get the AVP Length
          AvpLen      := PCardinal(aPayloadData + aCurrentPos)^;
          aCurrentPos := aCurrentPos + SizeOf(AvpLen);

          // Skip Vendor ID
          aCurrentPos := aCurrentPos + SizeOf(Cardinal);

          // Read the AVP Value
          Value := ReadAVPValueFromPacket(aPayloadData, aCurrentPos, AvpLen, UIntValue,aVendorID);

          // Append the AVP to the result string
          GroupedValue := GroupedValue + Format('%d=%s;', [UIntValue, Value.ToString]);
        end;
        Result := TValue.From<string>(GroupedValue);
      end; 
      
    110: //Time AVP
      begin
        //Get the Time value as a 64-bit unsigned integer and convert it to a TDateTime value.
       // Int64Value   := PUInt64(PayloadData + LCurrentPos)^;
       // Int64Value   := SwapInt64(Int64Value);
      //  DateTimeVal := MakeGmtDateTime(TimeValue - UnixToDateTimeDelta);
      //  LCurrentPos := LCurrentPos + AvpLength - 8;
        Result      := TValue.From<TDateTime>(now);
      end;
  
  
    115,132: //Float32 AVP
      begin
        FloatValue  := PSingle(aPayloadData + aCurrentPos)^;
      //  FloatValue  := Swap(FloatValue);
        Result      := TValue.From<Single>(FloatValue);
      end;
	

    130, 146, 175, 176, 177, 180, 181, 182 :
      begin
        LongValue   := PLongWord(aPayloadData + aCurrentPos)^;        
        Result      := TValue.From<LongWord>(Swap(LongValue));
      end;
      
    133:
      begin
        FloatValue  := PDouble(aPayloadData + aCurrentPos)^;
        Result      := TValue.From<Double>((FloatValue));
      end;

    136:
      begin
      //Extension AVP
        Result :=  TValue.From<String>('Extension AVP not implemented');
      end;

    139:
      begin
      //IP Filter Rule
        Result := TValue.From<String>('IP Filter Rule not implemented');
      end;
    140:
      begin
        //IP Address
        AddressValue := Format('%d.%d.%d.%d', [PByte(aPayloadData + aCurrentPos + 1)^,
                          PByte(aPayloadData + aCurrentPos + 2)^,
                          PByte(aPayloadData + aCurrentPos + 3)^,
                          PByte(aPayloadData + aCurrentPos + 4)^]);
        Result := TValue.From<string>(AddressValue);
      end;
    144:
      begin
        //IPv6 Address
        SetLength(RawValue, 16);
        Move((aPayloadData+aCurrentPos + 1)^, RawValue[0], 16);
        AddressValue := String.Empty;
        for I := 0 to 7 do
          AddressValue := AddressValue + IntToHex((RawValue[I * 2] shl 8) or RawValue[I * 2 + 1], 4) + ':';
          
        AddressValue := Copy(AddressValue, 1, Length(AddressValue) - 1);      
        Result       := TValue.From<string>(AddressValue);
      end;
    256..511:
    begin
      // Vendor-specific AVP
      if aAvpLength < 12 then
      begin
        Result  := TValue.From<string>(Format('Invalid vendor-specific AVP length: %d for AVP type ', [aAvpLength,aAvpType]));
        Exit;
      end;

      LongValue   := PLongWord(aPayloadData + aCurrentPos)^;
      LongValue   := Swap(LongValue);

      if not aVendorID.TryGetValue(LongValue, UTF8StringValue) then
      begin
        Result  := TValue.From<string>(Format('Unknown vendor ID: %d', [LongValue]));
        Exit;
      end;

      Result := Format('Vendor id %s [%d]',[UTF8StringValue,LongValue]);
      {
      SubAvpCode := PWord(PayloadData + LCurrentPos)^;
      SwapWord(@SubAvpCode);
      inc(LCurrentPos,sizeOf(Word));


      SubAvpLength := PWord(PayloadData + LCurrentPos)^;
      SubAvpLength := Swap(SubAvpLength));
      inc(LCurrentPos,sizeOf(Word));
      
      SubPayloadData := PayloadData + LCurrentPos;
      Result         := ProcessAVP(UTF8StringValue.AvpDictionary, SubAvpCode, SubPayloadDat - 8,);
      LCurrentPos    := LCurrentPos + SubAvpLength - 8;   }
    end;
  else
    Result  := TValue.From<string>(Format('Unknown AVP type: %d', [aAvpType]));
  end;
end;	     

class function TWPcapProtocolL2TP.ParseL2TPControlAVP(PayloadData: PByte;AListDetail: TListHeaderString;aLengthPayload:word;aVendorID: TListVendorId): string;
CONST AVP_LENGHT_WITHOUT_VALUE = 6;
var LAvpHeader      : TAVPHeader;
    LAvpType        : Word;
    LAvpFlag        : Word;
    LAvpLength      : Word;
    LAvpValue       : TValue;
    LCurrentPos     : Integer;
    LResultStr      : string;    
begin


  {
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |M|H| rsvd  |      Length       |           Vendor ID           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Attribute Type        |        Attribute Value...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                       [until Length is reached]...                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  }
  Try
  LResultStr := String.Empty;
  // Start from the beginning of the payload
  LCurrentPos := 0;
  // Loop through the payload data until the end is reached
  while LCurrentPos < aLengthPayload do
  begin
    // Extract AVP header information
    LAvpHeader := PAVPHeader(PayloadData + LCurrentPos)^;
    LAvpFlag   := wpcapntohs(LAvpHeader.AvtFlag);
    LAvpType   := wpcapntohs(LAvpHeader.AttrType);
    LAvpLength := GetLastNBit(LAvpFlag,10);    
    AListDetail.Add(AddHeaderInfo(1, Format('AVP %s [%d]', [L2TPAVPTypeToString(LAvpType),LAvpType]),null,@LAvpHeader,SizeOF(LAvpHeader))); 

    {
       The first six bits are a bit mask, describing the general attributes
       of the AVP.

       Two bits are defined in this document, the remaining are reserved for
       future extensions.  Reserved bits MUST be set to 0. An AVP received
       with a reserved bit set to 1 MUST be treated as an unrecognized AVP.

       Mandatory (M) bit: Controls the behavior required of an
       implementation which receives an AVP which it does not recognize. If
       the M bit is set on an unrecognized AVP within a message associated
       with a particular session, the session associated with this message
       MUST be terminated. If the M bit is set on an unrecognized AVP within
       a message associated with the overall tunnel, the entire tunnel (and
       all sessions within) MUST be terminated. If the M bit is not set, an
       unrecognized AVP MUST be ignored. The control message must then
       continue to be processed as if the AVP had not been present.

       Hidden (H) bit: Identifies the hiding of data in the Attribute Value
       field of an AVP.  This capability can be used to avoid the passing of
       sensitive data, such as user passwords, as cleartext in an AVP.
       Section 4.3 describes the procedure for performing AVP hiding.

       Length: Encodes the number of octets (including the Overall Length
       and bitmask fields) contained in this AVP. The Length may be
       calculated as 6 + the length of the Attribute Value field in octets.
       The field itself is 10 bits, permitting a maximum of 1023 octets of
       data in a single AVP. The minimum Length of an AVP is 6. If the
       length is 6, then the Attribute Value field is absent.
    }
    
    AListDetail.Add(AddHeaderInfo(2,'Flag:',Format('%s %s',[ByteToBinaryString(GetByteFromWord(LAvpFlag,1)),
                                                            ByteToBinaryString(GetByteFromWord(LAvpFlag,2))]),@LAvpFlag,sizeOf(LAvpFlag)));       
    AListDetail.Add(AddHeaderInfo(3,'Mandatory:',GetBitValue(GetByteFromWord(LAvpFlag,1),1)=1,nil,0));
    AListDetail.Add(AddHeaderInfo(3,'Hidden:',GetBitValue(GetByteFromWord(LAvpFlag,1),2)=1,nil,0)); 
    AListDetail.Add(AddHeaderInfo(3,'Length:',LAvpLength,@LAvpLength,10)); 
    
    {
      Vendor ID: The IANA assigned "SMI Network Management Private
      Enterprise Codes" [RFC1700] value.  The value 0, corresponding to
      IETF adopted attribute values, is used for all AVPs defined within
      this document. Any vendor wishing to implement their own L2TP
      extensions can use their own Vendor ID along with private Attribute

      values, guaranteeing that they will not collide with any other
      vendor's extensions, nor with future IETF extensions. Note that there
      are 16 bits allocated for the Vendor ID, thus limiting this feature
      to the first 65,535 enterprises.
    }    
    AListDetail.Add(AddHeaderInfo(2,'Vendor:',wpcapntohs(LAvpHeader.VendorID),@LAvpHeader.VendorID,sizeOf(LAvpHeader.VendorID)));       

    {Attribute Type: A 2 octet value with a unique interpretation across
     all AVPs defined under a given Vendor ID.}    
    AListDetail.Add(AddHeaderInfo(2,'Type:',Format('%s [%d]', [L2TPAVPTypeToString(LAvpType),LAvpType]),@LAvpHeader.AttrType,sizeOf(LAvpHeader.AttrType)));       


    // Add AVP type and length to the result string
    LResultStr := LResultStr + Format('AVP Type: %d, Length: %d'#13#10, [LAvpType, LAvpLength]);
    
    // Check if the AVP has a value

    if LAvpLength > AVP_LENGHT_WITHOUT_VALUE then
    begin
      {Attribute Value: This is the actual value as indicated by the Vendor
       ID and Attribute Type. It follows immediately after the Attribute
       Type field, and runs for the remaining octets indicated in the Length
       (i.e., Length minus 6 octets of header). This field is absent if the
       Length is 6.}
      LResultStr := LResultStr + 'Value: ';
      Inc(LCurrentPos, SizeOf(TAVPHeader));       
      
      LAvpValue := wpcapntohs(Pcardinal(PayloadData + LCurrentPos)^);
      LAvpValue := ReadAVPValueFromPacket(PayloadData,LCurrentPos,LAvpLength,LAvpType,aVendorID);
      AListDetail.Add(AddHeaderInfo(2,'Type value:',LAvpValue.ToString,nil,0));
      LResultStr :=Format('%s %s',[LResultStr,LAvpValue.ToString])  + #13#10;

      {TODO message by AVP Type}
      // Move to the next AVP
      Inc(LCurrentPos, LAvpLength - SizeOf(TAVPHeader));
    end
    else
    begin
      // AVP has no value
      if LAvpType = 0 then
        AListDetail.Add(AddHeaderInfo(2,'Type value:','not present',nil,0));
      Inc(LCurrentPos, SizeOf(TAVPHeader));
    end;
  end;
  except

  End;

end;


end.
