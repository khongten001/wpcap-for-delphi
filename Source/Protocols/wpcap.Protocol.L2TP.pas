//*************************************************************
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

unit wpcap.Protocol.L2TP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, WinSock2, wpcap.Protocol.UDP, wpcap.Types,idGlobal,wpcap.packet,
  System.StrUtils, System.Rtti, System.SysUtils, System.Variants, WinApi.Windows,
  wpcap.BufferUtils, System.Win.ScktComp, DateUtils,wpcap.IpUtils,System.Generics.Collections;

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
    Flags     : Uint8;      // Flags for the L2TP header.
    Version   : Uint8;
  end;

  TListVendorId = TDictionary<Integer, string>;

  PTL2TPHdrInternal = ^TL2TPHdrInternal;
  TL2TPHdrInternal = packed record
    Flags     : Uint8;      // Flags for the L2TP header.
    Version   : Uint8;
    Length    : Uint16;      // Length of the L2TP header and payload.
    TunnelId  : Uint16;      // Identifier for the L2TP tunnel.
    SessionId : Uint16;      // Identifier for the L2TP session.
    Ns        : Uint16;      // Next sequence number for this session.
    Nr        : Uint16;      // Next received sequence number for this session.
    OffsetSize: Uint16;      // Size of the optional offset field in the header.
    OffsetPad : Uint16;      // Size of the optional offset field in the header.    
  end;

  TAVPHeader = packed record
    AvtFlag   : Uint16;
    VendorID  : Uint16;
    AttrType  : Uint16;
  end;
  PAVPHeader = ^TAVPHeader;  

  
  /// <summary>
  /// Represents the Layer 2 Tunneling Protocol (L2TP) implementation for the WPcap library, which provides access to network traffic on Windows.
  /// </summary>
  TWPcapProtocolL2TP = Class(TWPcapProtocolBaseUDP)
  private
    CONST
      AVTYPE_CONTROL_MESSAGE              = 0;
      AVTYPE_RESULT_ERROR_CODE            = 1;
      AVTYPE_PROTOCOL_VERSION             = 2;
      AVTYPE_FRAMING_CAPABILITIES         = 3;
      AVTYPE_BEARER_CAPABILITIES          = 4;
      AVTYPE_TIE_BREAKER                  = 5;
      AVTYPE_FIRMWARE_REVISION            = 6;
      AVTYPE_HOST_NAME                    = 7;
      AVTYPE_VENDOR_NAME                  = 8;
      AVTYPE_ASSIGNED_TUNNEL_ID           = 9;
      AVTYPE_RECEIVE_WINDOW_SIZE          =10;
      AVTYPE_CHALLENGE                    =11;
      AVTYPE_CAUSE_CODE                   =12;
      AVTYPE_CHALLENGE_RESPONSE           =13;
      AVTYPE_ASSIGNED_SESSION             =14;
      AVTYPE_CALL_SERIAL_NUMBER           =15;
      AVTYPE_MINIMUM_BPS                  =16;
      AVTYPE_MAXIMUM_BPS                  =17;
      AVTYPE_BEARER_TYPE                  =18;
      AVTYPE_FRAMING_TYPE                 =19;
      AVTYPE_CALLED_NUMBER                =21;
      AVTYPE_CALLING_NUMBER               =22;
      AVTYPE_SUB_ADDRESS                  =23;
      AVTYPE_TX_CONNECT_SPEED             =24;
      AVTYPE_PHYSICAL_CHANNEL             =25;
      AVTYPE_INITIAL_RECEIVED_LCP_CONFREQ =26;
      AVTYPE_LAST_SENT_LCP_CONFREQ        =27;
      AVTYPE_LAST_RECEIVED_LCP_CONFREQ    =28;
      AVTYPE_PROXY_AUTHEN_TYPE            =29;
      AVTYPE_PROXY_AUTHEN_NAME            =30;
      AVTYPE_PROXY_AUTHEN_CHALLENGE       =31;
      AVTYPE_PROXY_AUTHEN_ID              =32;
      AVTYPE_PROXY_AUTHEN_RESPONSE        =33;
      AVTYPE_CALL_STATUS_AVPS             =34;
      AVTYPE_ACCM                         =35;
      AVTYPE_RANDOM_VECTOR                =36;
      AVTYPE_PRIVATE_GROUP_ID             =37;
      AVTYPE_RX_CONNECT_SPEED             =38;
      AVTYPE_SEQUENCING_REQUIRED          =39;
      AVTYPE_PPP_DISCONNECT_CAUSE_CODE    =46;
      AVTYPE_EXTENDED_VENDOR_ID           =58;
      AVTYPE_MESSAGE_DIGEST               =59;
      AVTYPE_ROUTER_ID                    =60;
      AVTYPE_ASSIGNED_CONTROL_CONN_ID     =61;
      AVTYPE_PW_CAPABILITY_LIST           =62;
      AVTYPE_LOCAL_SESSION_ID             =63;
      AVTYPE_REMOTE_SESSION_ID            =64;
      AVTYPE_ASSIGNED_COOKIE              =65;
      AVTYPE_REMOTE_END_ID                =66;
      AVTYPE_PW_TYPE                      =68;
      AVTYPE_L2_SPECIFIC_SUBLAYER         =69;
      AVTYPE_DATA_SEQUENCING              =70;
      AVTYPE_CIRCUIT_STATUS               =71;
      AVTYPE_PREFERRED_LANGUAGE           =72;
      AVTYPE_CTL_MSG_AUTH_NONCE           =73;
      AVTYPE_TX_CONNECT_SPEED_V3          =74;
      AVTYPE_RX_CONNECT_SPEED_V3          =75;
      AVTYPE_CONNECT_SPEED_UPDATE         =97;
      
      MESSAGE_TYPE_SCCRQ                  = 1;
      MESSAGE_TYPE_SCCRP                  = 2;
      MESSAGE_TYPE_SCCCN                  = 3;
      MESSAGE_TYPE_StopCCN                = 4;
      MESSAGE_TYPE_Reserved_5             = 5;
      MESSAGE_TYPE_HELLO                  = 6;
      MESSAGE_TYPE_OCRQ                   = 7;
      MESSAGE_TYPE_OCRP                   = 8;
      MESSAGE_TYPE_OCCN                   = 9;
      MESSAGE_TYPE_ICRQ                   =10;
      MESSAGE_TYPE_ICRP                   =11;
      MESSAGE_TYPE_ICCN                   =12;
      MESSAGE_TYPE_Reserved_13            =13;
      MESSAGE_TYPE_CDN                    =14;
      MESSAGE_TYPE_WEN                    =15;
      MESSAGE_TYPE_SLI                    =16;
      MESSAGE_TYPE_MDMST                  =17;
      MESSAGE_TYPE_SRRQ                   =18;
      MESSAGE_TYPE_SRRP                   =19;
      MESSAGE_TYPE_ACK                    =20;
      MESSAGE_TYPE_FSQ                    =21;
      MESSAGE_TYPE_FSR                    =22;
      MESSAGE_TYPE_MSRQ                   =23;
      MESSAGE_TYPE_MSRP                   =24;
      MESSAGE_TYPE_MSE                    =25;
      MESSAGE_TYPE_MSI                    =26;
      MESSAGE_TYPE_MSEN                   =27;
      MESSAGE_TYPE_CSUN                   =28;
      MESSAGE_TYPE_CSURQ                  =29;     

      ERR_NO_GENERAL                      = 0;
      ERR_NO_CONTROL                      = 1;
      ERR_LENGTH                          = 2;
      ERR_FIELD_VALUE                     = 3;
      ERR_INSUFFICIENT_RESOURCES          = 4;
      ERR_INVALID_SESSION                 = 5;
      ERR_GENERIC_VENDOR                  = 6;
      ERR_TRY_ANOTHER                     = 7;
      ERR_UNKNOWN_AVP                     = 8;
      ERR_TRY_ANOTHER_DIRECTED            = 9;
      ERR_NEXT_HOP_UNREACHABLE            = 10;
      ERR_NEXT_HOP_BUSY                   = 11;
      ERR_TSA_BUSY                        = 12;    
         
    class function GetL2TPFlag(aFlags: Uint16;aStartLevel:Integer;AListDetail: TListHeaderString): string; static;
    class function ParseL2TPControlAVP(const aPayloadData: PByte;AListDetail: TListHeaderString;aLengthPayload:Uint16;aStartLevel:Integer;aVendorID: TListVendorId;aAdditionalParameters: PTAdditionalParameters): string; static;
    class function LenghtIsPresent(aFlags: Uint16): Boolean; static;
    class function SequencePresent(aFlags: Uint16): Boolean; static;
    class function OffSetIsPresent(aFlags: Uint16): Boolean; static;
    class function AvtType0ValueToString(const aAvtValue: Uint16): String;
    Class function InitVendorID: TListVendorID;Static;
    class procedure ReadAVPValueFromPacket(const aLabel:String;const aPayloadData: PByte;aPayloadSize:Integer;var aCurrentPos:Integer;var aIsStopCcn: Boolean;const aAvpLength,aAvpType,aStartLevel: Integer; aVendorID: TListVendorId;AListDetail: TListHeaderString;aAdditionalParameters: PTAdditionalParameters); static;
    class function L2TPAVPTypeToString(AVPType: Uint16): string; static;
    class function HiddenFlagIsSetted(aAvpLen: Integer): Boolean; static;
    class function GetErrorMessage(const aErrorCode: Uint16): string;
    Class function ResultCodeStopccnToString(const aCode:Uint16):String;    
    Class function ResultCodeToString(const aCode:Uint16):String;     
    class function CauseCodeDirectionToString(const aErrorCode: Uint8): string;
    class function PWTypesToString(const aPwType: Uint16): String;
    class function AuthenTypeToString(const aType: Uint16): String;
    class function L2SublayerToString(const aSubLayer: Uint16): String;
    class function DataSequenceToString(const aSubLayer: Uint16): String;
  public
    /// <summary>
    /// Returns the default port number used by the L2TP protocol (1701).
    /// </summary>
    class Function DefaultPort: word;override;

    /// <summary>
    /// Return Intenal protocol ID
    /// </summary>
    class function IDDetectProto: Byte; override;
    
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
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean; override; 
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

class function TWPcapProtocolL2TP.HeaderLength(aFlag:byte): word;
begin
  Result := SizeOf(TL2TPHdr)+ (SizeOf(Uint16)*2); // lenght structure fixed

  if LenghtIsPresent(aFlag) then
    inc(Result,SizeOf(Uint16));
  
  if SequencePresent(aFlag) then
    inc(Result,SizeOf(Uint16)*2);

  if OffSetIsPresent(aFlag) then
    inc(Result,SizeOf(Uint16));  
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
    aCurrentPos    : Uint16;
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
    Result.Length := Puint16(aUDPPayLoad +aCurrentPos)^; 
    inc(aCurrentPos,SizeOf(Result.TunnelId));
  end;

  Result.TunnelId := Puint16(aUDPPayLoad +aCurrentPos)^; 
  inc(aCurrentPos,SizeOf(Result.SessionId));

  Result.SessionId :=Puint16(aUDPPayLoad +aCurrentPos)^; 
  inc(aCurrentPos,SizeOf(Result.Ns));
  
  if SequencePresent(aBaseStructure.Flags) then
  begin    
    Result.Ns := Puint16(aUDPPayLoad +aCurrentPos)^; 
    inc(aCurrentPos,SizeOf(Result.Nr));
    Result.Nr := Puint16(aUDPPayLoad +aCurrentPos)^; 
    inc(aCurrentPos,SizeOf(Result.Nr));
  end;

  if OffSetIsPresent(aBaseStructure.Flags) then
  begin    
    Result.OffsetSize := Puint16(aUDPPayLoad +aCurrentPos)^; 
    inc(aCurrentPos,SizeOf(Result.OffsetPad));
    Result.OffsetPad := Puint16(aUDPPayLoad +aCurrentPos)^;     
  end;
end;

class function TWPcapProtocolL2TP.L2TPAVPTypeToString(AVPType: Uint16): string;
begin      
  case AVPType of
    AVTYPE_CONTROL_MESSAGE              : Result := 'Control Message';
    AVTYPE_RESULT_ERROR_CODE            : Result := 'Result-Error Code';
    AVTYPE_PROTOCOL_VERSION             : Result := 'Protocol Version';
    AVTYPE_FRAMING_CAPABILITIES         : Result := 'Framing Capabilities';
    AVTYPE_BEARER_CAPABILITIES          : Result := 'Bearer Capabilities';
    AVTYPE_TIE_BREAKER                  : Result := 'Tie Breaker';
    AVTYPE_FIRMWARE_REVISION            : Result := 'Firmware Revision';
    AVTYPE_HOST_NAME                    : Result := 'Host Name';
    AVTYPE_VENDOR_NAME                  : Result := 'Vendor Name';
    AVTYPE_ASSIGNED_TUNNEL_ID           : Result := 'Assigned Tunnel ID';
    AVTYPE_RECEIVE_WINDOW_SIZE          : Result := 'Receive Window Size';
    AVTYPE_CHALLENGE                    : Result := 'Challenge';
    AVTYPE_CAUSE_CODE                   : Result := 'Cause Code';
    AVTYPE_CHALLENGE_RESPONSE           : Result := 'Challenge Response';
    AVTYPE_ASSIGNED_SESSION             : Result := 'Assigned Session';
    AVTYPE_CALL_SERIAL_NUMBER           : Result := 'Call Serial Number';
    AVTYPE_MINIMUM_BPS                  : Result := 'Minimum BPS';
    AVTYPE_MAXIMUM_BPS                  : Result := 'Maximum BPS';
    AVTYPE_BEARER_TYPE                  : Result := 'Bearer Type';
    AVTYPE_FRAMING_TYPE                 : Result := 'Framing Type';
    20                                  : Result := 'Reserved';
    AVTYPE_CALLED_NUMBER                : Result := 'Called Number';
    AVTYPE_CALLING_NUMBER               : Result := 'Calling Number';
    AVTYPE_SUB_ADDRESS                  : Result := 'Sub-Address';
    AVTYPE_TX_CONNECT_SPEED             : Result := 'Connect Speed';
    AVTYPE_PHYSICAL_CHANNEL             : Result := 'Physical Channel';
    AVTYPE_INITIAL_RECEIVED_LCP_CONFREQ : Result := 'Initial Received LCP CONFREQ';
    AVTYPE_LAST_SENT_LCP_CONFREQ        : Result := 'Last Sent LCP CONFREQ';
    AVTYPE_LAST_RECEIVED_LCP_CONFREQ    : Result := 'Last Received LCP CONFREQ';
    AVTYPE_PROXY_AUTHEN_TYPE            : Result := 'Proxy Authen Type';
    AVTYPE_PROXY_AUTHEN_NAME            : Result := 'Proxy Authen Name';
    AVTYPE_PROXY_AUTHEN_CHALLENGE       : Result := 'Proxy Authen Challenge';
    AVTYPE_PROXY_AUTHEN_ID              : Result := 'Proxy Authen ID';
    AVTYPE_PROXY_AUTHEN_RESPONSE        : Result := 'Proxy Authen Response';
    AVTYPE_CALL_STATUS_AVPS             : Result := 'Call status AVPs';
    AVTYPE_ACCM                         : Result := 'ACCM';
    AVTYPE_RANDOM_VECTOR                : Result := 'Random Vector';
    AVTYPE_PRIVATE_GROUP_ID             : Result := 'Private group ID';
    AVTYPE_RX_CONNECT_SPEED             : Result := 'RxConnect Speed';
    AVTYPE_SEQUENCING_REQUIRED          : Result := 'Sequencing Required';
    40                                  : Result := 'Circuit Status';
    41                                  : Result := 'Class';
    42                                  : Result := 'Vendor Specific';
    43                                  : Result := 'Session ID';
    44                                  : Result := 'Bearer Information';
    45                                  : Result := 'Framing Information';
    AVTYPE_PPP_DISCONNECT_CAUSE_CODE    : Result := 'PPP Disconnect Cause Code';
    47                                  : Result := 'Calling Sub Address';
    48                                  : Result := 'Called Sub Address';
    49                                  : Result := 'Tx Connect Time';
    50                                  : Result := 'Proxy Authen Window';
    51                                  : Result := 'Status Info';
    52                                  : Result := 'Acct Session ID';
    53                                  : Result := 'Acct Multi Session ID';
    54                                  : Result := 'Acct Link Count';
    55                                  : Result := 'Acct Input Octets';
    56                                  : Result := 'Acct Output Octets';
    57                                  : Result := 'Acct Input Packets';
    AVTYPE_EXTENDED_VENDOR_ID           : Result := 'Extended Vendor ID';
    AVTYPE_MESSAGE_DIGEST               : Result := 'Message Digest';
    AVTYPE_ROUTER_ID                    : Result := 'Router ID';
    AVTYPE_ASSIGNED_CONTROL_CONN_ID     : Result := 'Assigned Control Connection ID';
    AVTYPE_PW_CAPABILITY_LIST           : Result := 'Pseudowire Capability List';
    AVTYPE_LOCAL_SESSION_ID             : Result := 'Local Session ID';
    AVTYPE_REMOTE_SESSION_ID            : Result := 'Remote Session ID';
    AVTYPE_ASSIGNED_COOKIE              : Result := 'Assigned Cookie';
    AVTYPE_REMOTE_END_ID                : Result := 'Remote End ID';
    67                                  : Result := 'Acct Interim Interval';    
    AVTYPE_PW_TYPE                      : Result := 'Pseudowire Type';
    AVTYPE_L2_SPECIFIC_SUBLAYER         : Result := 'Layer2 Specific Sublayer';
    AVTYPE_DATA_SEQUENCING              : Result := 'Data Sequencing';
    AVTYPE_CIRCUIT_STATUS               : Result := 'Circuit Status';
    AVTYPE_PREFERRED_LANGUAGE           : Result := 'Preferred Language';
    AVTYPE_CTL_MSG_AUTH_NONCE           : Result := 'Control Message Authentication Nonce';
    AVTYPE_TX_CONNECT_SPEED_V3          : Result := 'Tx Connect Speed Version 3';
    AVTYPE_RX_CONNECT_SPEED_V3          : Result := 'Rx Connect Speed Version 3';
    76                           	      : Result := 'Failover Capability';                            
    77                           	      : Result := 'Tunnel Recovery';                                
    78                           	      : Result := 'Suggested Control Sequence';                     
    79                           	      : Result := 'Failover Session State';                         
    80                           	      : Result := 'Multicast Capability';                           
    81                           	      : Result := 'New Outgoing Sessions';                          
    82                           	      : Result := 'New Outgoing Sessions Acknowledgement';          
    83                           	      : Result := 'Withdraw Outgoing Sessions';                     
    84                           	      : Result := 'Multicast Packets Priority';                     
    85                           	      : Result := 'Frame-Relay Header Length';                      
    86                           	      : Result := 'ATM Maximum Concatenated Cells';                 
    87                           	      : Result := 'OAM Emulation Required';                         
    88                           	      : Result := 'ATM Alarm Status';                               
    89                           	      : Result := 'Attachment Group Identifier';                    
    90                           	      : Result := 'Local End Identifier';                           
    91                           	      : Result := 'Interface Maximum Transmission Unit';            
    92                           	      : Result := 'FCS Retention';                                  
    93                           	      : Result := 'Tunnel Switching Aggregator ID';                 
    94                           	      : Result := 'Maximum Receive Unit (MRU)';                     
    95                           	      : Result := 'Maximum Reassembled Receive Unit (MRRU)';        
    96                           	      : Result := 'VCCV Capability';                                
    AVTYPE_CONNECT_SPEED_UPDATE         : Result := 'Connect Speed Update';                           
    98                           	      : Result := 'Connect Speed Update Enable';                    
    99                           	      : Result := 'TDM Pseudowire';                                 
    100                          	      : Result := 'RTP AVP';                                        
    101                          	  	  : Result := 'PW Switching Point';  
    102                                 : Result := 'IPv6 Tokens';
    103                                 : Result := 'NAT Information';
    104                                 : Result := 'Remote Endpoint IP Information';
    105                                 : Result := 'Local Endpoint IP Information';
    106                                 : Result := 'Service ID';
    107                                 : Result := 'QoS Parameters';
    108                                 : Result := 'Transit VLAN ID';
    109                                 : Result := 'Transit Service Name';
    110                                 : Result := 'IPv6 Prefix Pool';
    111                                 : Result := 'Subscriber Information';
    112                                 : Result := 'Subscription ID';
    113                                 : Result := 'Remote MAC Address';
    114                                 : Result := 'Session Priority';
    115                                 : Result := 'Home Gateway IP Address';
    116                                 : Result := 'Home Gateway IPv6 Address';
    117                                 : Result := 'IPv4 MTU';
    118                                 : Result := 'IPv6 MTU';
    119                                 : Result := 'Outer VLAN ID';
    120                                 : Result := 'Inner VLAN ID';
    121                                 : Result := 'Originating Line Info';
    122                                 : Result := 'NAS Port Type';
    123                                 : Result := 'Source Port';
    124                                 : Result := 'Destination Port';
    125                                 : Result := 'Message Authenticator';
    126                                 : Result := 'Proxy State';
    127                                 : Result := 'Proxy Information';
    128                                 : Result := 'NAS Identifier';
    129                                 : Result := 'Proxy Action';
    130                                 : Result := 'Location ID';
    131                                 : Result := 'Location Name';
    132                                 : Result := 'Location Type';
    133                                 : Result := 'Location Data';
    134                                 : Result := 'ATM VC';
    135                                 : Result := 'ATM VC Type';
    136                                 : Result := 'ATM CLP';
    137                                 : Result := 'ATM NNI';
    138                                 : Result := 'ATM OAM VPI';
    139                                 : Result := 'ATM OAM VCI';
    140                                 : Result := 'IP Technology Type';
    141                                 : Result := 'IPv6 ND Cache Parameters';
    142                                 : Result := 'Framed Pool ID';
    143                                 : Result := 'Class of Service';
    144                                 : Result := 'Tunnel Type';
    145                                 : Result := 'Tunnel Medium Type';
    146                                 : Result := 'Tunnel Client Endpoint';
    147                                 : Result := 'Tunnel Server Endpoint';
    148                                 : Result := 'Acct Tunnel Connection';
    149                                 : Result := 'Tunnel Password';
    150                                 : Result := 'Tunnel Private Group ID';
    151                                 : Result := 'Tunnel Assignment ID';
    152                                 : Result := 'Tunnel Preference';
    153                                 : Result := 'ARAP Password';
    154                                 : Result := 'ARAP Features';
    155                                 : Result := 'ARAP Zone Access';
    156                                 : Result := 'ARAP Security';
    157                                 : Result := 'ARAP Security Data';
    158                                 : Result := 'Password Retry';
    159                                 : Result := 'Prompt';
    160                                 : Result := 'Connect Info';
    161                                 : Result := 'Configuration Token';
    162                                 : Result := 'EAP Message';
    163                                 : Result := 'Signature';
    164                                 : Result := 'ARAP Challenge Response';
    165                                 : Result := 'Acct Interim Interval Valid';
    166                                 : Result := 'ARAP Password Change Reason';
    167                                 : Result := 'ARAP Password Change Date';
    168                                 : Result := 'Protocol Support';
    169                                 : Result := 'Framed Management Protocol';
    170                                 : Result := 'Management Transport Protection';
    171                                 : Result := 'Management Policy ID';
    172                                 : Result := 'Management Privilege Level';
    173                                 : Result := 'PKINIT Anchor';
    174                                 : Result := 'CoA Information';
    175                                 : Result := 'Effective Policy ID';
    176                                 : Result := 'Effective Policy Name';
    177                                 : Result := 'User Profile';
    178                                 : Result := 'Acct Input Octets64';
    179                                 : Result := 'Acct Output Octets64';
    180                                 : Result := 'Access Point Name';
    181                                 : Result := 'Event Sub Type';
    182                                 : Result := 'Circuit ID';
    183                                 : Result := 'Vendor Specific';
    184                                 : Result := 'Dialout Allowed';
    185                                 : Result := 'Filter ID';
    186                                 : Result := 'Prompt Time';
    187                                 : Result := 'Idle Timeout';
    188                                 : Result := 'Connect Progress';
    189                                 : Result := 'Disconnect Cause';
    190                                 : Result := 'Calling Station ID';
    191                                 : Result := 'Called Station ID';
    192                                 : Result := 'NAS Port Id';
    193                                 : Result := 'Framed IP Address';
    194                                 : Result := 'Framed IP Netmask';
    195                                 : Result := 'Framed IP Route';
    196                                 : Result := 'Filter Id';
    197                                 : Result := 'Framed AppleTalk Link';
    198                                 : Result := 'Framed AppleTalk Network';
    199                                 : Result := 'Framed AppleTalk Zone';
    200                                 : Result := 'Acct Input Packets';
    201                                 : Result := 'Acct Output Packets';
    202                                 : Result := 'Acct Session Id';
    203                                 : Result := 'Acct Authentic';
    204                                 : Result := 'Acct Session Time';
    205                                 : Result := 'Acct Input Gigawords';
    206                                 : Result := 'Acct Output Gigawords';
    207                                 : Result := 'Unassigned';
    208                                 : Result := 'Event Timestamp';
    209                                 : Result := 'Egress VLANID';
    210                                 : Result := 'Ingress Filters';
    211                                 : Result := 'Egress VLAN Name';
    212                                 : Result := 'UserName';
    213                                 : Result := 'VLAN Name';
    214                                 : Result := 'Filter Name';
    215                                 : Result := 'IPv6 Interface ID';
    216                                 : Result := 'IPv6 Client IP Address';
    217                                 : Result := 'IPv6 Server IP Address';
    218                                 : Result := 'RADIUS IPv6 Prefix';
    219                                 : Result := 'Framed IPv6 Prefix';
    220                                 : Result := 'Login IPv6 Host';
    221                                 : Result := 'Framed IPv6 Route';
    222                                 : Result := 'Framed IPv6 Pool';
    223                                 : Result := 'Error Cause';
    224                                 : Result := 'EAP Key Name';
    225                                 : Result := 'Digest Response';
    226                                 : Result := 'Digest Realm';
    227                                 : Result := 'Digest Nonce';
    228                                 : Result := 'Digest Response Auth';
    229                                 : Result := 'Digest Nextnonce';
    230                                 : Result := 'Digest Method';
    231                                 : Result := 'Digest URI';
    232                                 : Result := 'Digest Qop';
    233                                 : Result := 'Digest Algorithm';
    234                                 : Result := 'Digest Entity Body Hash';
    235                                 : Result := 'Digest CNonce';
    236                                 : Result := 'Digest Nonce Count';
    237                                 : Result := 'Digest Username';
    238                                 : Result := 'Digest Opaque';
    239                                 : Result := 'Digest Auth Param';
    240                                 : Result := 'Digest AKA Auts';
    241                                 : Result := 'Digest Domain';
    242                                 : Result := 'Digest Stale';
    243                                 : Result := 'Digest HA1';
    244                                 : Result := 'SIP AOR';
    245                                 : Result := 'Delegated IPv6 Prefix';
    246                                 : Result := 'MIP6 Feature Vector';
    247                                 : Result := 'MIP6 Home Link Prefix';
    248                                 : Result := 'Operator Name';
    249                                 : Result := 'Location Information';
    250                                 : Result := 'Location';
    251                                 : Result := 'Location Data';
    252                                 : Result := 'Basic Location Policy Rules';
    253                                 : Result := 'Extended Location Policy Rules';
    254                                 : Result := 'Location Capable';
    255                                 : Result := 'Requested Location Info';    
  end;
end;

class function TWPcapProtocolL2TP.LenghtIsPresent(aFlags:Uint16):Boolean;
begin
  Result := GetBitValue(aFlags,2) =1;
end;

class function TWPcapProtocolL2TP.SequencePresent(aFlags:Uint16):Boolean;
begin
  Result := GetBitValue(aFlags,5) =1;
end;

class function TWPcapProtocolL2TP.OffSetIsPresent(aFlags:Uint16):Boolean;
begin
  Result := GetBitValue(aFlags,7) =1;
end;

class function TWPcapProtocolL2TP.GetErrorMessage(const aErrorCode: Uint16): string;
begin
  case aErrorCode of
    ERR_NO_GENERAL              : Result := 'No General Error';
    ERR_NO_CONTROL              : Result := 'No control connection exists yet for this pair of LCCEs';
    ERR_LENGTH                  : Result := 'Length is wrong';
    ERR_FIELD_VALUE             : Result := 'One of the field values was out of range';
    ERR_INSUFFICIENT_RESOURCES  : Result := 'Insufficient resources to handle this operation now';
    ERR_INVALID_SESSION         : Result := 'Invalid Session ID';
    ERR_GENERIC_VENDOR          : Result := 'A generic vendor-specific error occurred';
    ERR_TRY_ANOTHER             : Result := 'Try another';
    ERR_UNKNOWN_AVP             : Result := 'Receipt of an unknown AVP with the M bit set';
    ERR_TRY_ANOTHER_DIRECTED    : Result := 'Try another directed';
    ERR_NEXT_HOP_UNREACHABLE    : Result := 'Next hop unreachable';
    ERR_NEXT_HOP_BUSY           : Result := 'Next hop busy';
    ERR_TSA_BUSY                : Result := 'TSA busy';
  else
    Result := 'Unknown error';
  end;
end;

class function TWPcapProtocolL2TP.CauseCodeDirectionToString(const aErrorCode: Uint8): string;
begin
  case aErrorCode of
     0: Result := 'global error';
     1: Result := 'at peer';
     2: Result := 'at local';
  else
    Result := 'Unknown';
  end;
end;   

class function TWPcapProtocolL2TP.GetL2TPFlag(aFlags: Uint16;aStartLevel:Integer;AListDetail:TListHeaderString): string;
begin
{
   |T|L|x|x|S|x|O|P|x|x|x|x|  Ver  |          Length (opt)         |

   The Type (T) bit indicates the type of message. It is set to 0 for a
   data message and 1 for a control message.}

  Result := Format('Message type [%d]',[GetBitValue(aFlags,1)]);
  AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.MsgType',[AcronymName]), 'Message type:',ifthen(GetBitValue(aFlags,1)=1,'control message','data message'), @aFlags,SizeOf(aFlags), GetBitValue(aFlags,1) ));  
  
  {
   If the Length (L) bit is 1, the Length field is present. This bit
   MUST be set to 1 for control messages.
  }  
  Result :=  Format('%s LengthIncluded %s ',[Result,BoolToStr(LenghtIsPresent(aFlags),True)]);
  AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.LenIsPresent',[AcronymName]), 'Length is present:',LenghtIsPresent(aFlags),@aFlags,SizeOf(aFlags), GetBitValue(aFlags,2) ));  

  {
    If the Sequence (S) bit is set to 1 the Ns and Nr fields are present.
    The S bit MUST be set to 1 for control messages.
  }
  Result :=  Format('%s SequenceIncluded %s ',[Result,BoolToStr(SequencePresent(aFlags),True)]);
  AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.SeqIsPresent',[AcronymName]), 'Sequence is present:',SequencePresent(aFlags),@aFlags,SizeOf(aFlags), GetBitValue(aFlags,5) ));  

  {
   If the Offset (O) bit is 1, the Offset Size field is present. The O
   bit MUST be set to 0 (zero) for control messages.
  }
  Result :=  Format('%s OffsetIncluded %s ',[Result,BoolToStr(OffSetIsPresent(aFlags),True)]);
  AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.OffSetIsPresent',[AcronymName]), 'Offset is present:',OffSetIsPresent(aFlags),@aFlags,SizeOf(aFlags), GetBitValue(aFlags,7) ));  

  { If the Priority (P) bit is 1, this data message should receive
   preferential treatment in its local queuing and transmission.  LCP
   echo requests used as a keepalive for the link, for instance, should
   generally be sent with this bit set to 1. Without it, a temporary
   interval of local congestion could result in interference with
   keepalive messages and unnecessary loss of the link. This feature is
   only for use with data messages. The P bit MUST be set to 0 for all
   control messages.                                       }
  Result :=  Format('%s Priority %s ',[Result,BoolToStr(GetBitValue(aFlags,8)=1,True)]);
  AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.Priority',[AcronymName]), 'Priority:',GetBitValue(aFlags,8)=1, @aFlags,SizeOf(aFlags), GetBitValue(aFlags,8) ));  
end;

class function TWPcapProtocolL2TP.HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean; 
var LHeaderL2TP   : PTL2TPHdrInternal;
    LPUDPHdr      : PUDPHdr;
    LUDPPayLoad   : PByte;
    Loffset       : Uint16;
    UDPPayLoadLen : Integer;
    LVendorID     : TListVendorId;
begin

  Result := False;
  if not HeaderUDP(aPacketData, aPacketSize, LPUDPHdr) then Exit;
  LUDPPayLoad   := GetUDPPayLoad(aPacketData, aPacketSize);
  UDPPayLoadLen := UDPPayLoadLength(LPUDPHdr)-8;
  FIsFilterMode := aIsFilterMode;
  LHeaderL2TP   := Header(LUDPPayLoad);
  Try
    LVendorID := InitVendorID;  
    Try
      if not Assigned(LHeaderL2TP) then exit;
  
      AListDetail.Add(AddHeaderInfo(aStartLevel, AcronymName, Format('%s (%s)', [ProtoName, AcronymName]), null, LUDPPayLoad, UDPPayLoadLen ));
      
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.HeaderLen',[AcronymName]), 'Header length', HeaderLength(LHeaderL2TP.Flags),nil,0));      
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Flags',[AcronymName]), 'Flags',ByteToBinaryString(LHeaderL2TP.Flags), @LHeaderL2TP.flags, SizeOf(LHeaderL2TP.flags), LHeaderL2TP.flags ));

      GetL2TPFlag(LHeaderL2TP.Flags,aStartLevel,AListDetail);
    
      {
       Ver MUST be 2, indicating the version of the L2TP data message header
       described in this document. The value 1 is reserved to permit
       detection of L2F [RFC2341] packets should they arrive intermixed with
       L2TP packets. Packets received with an unknown Ver field MUST be
       discarded.
      }    
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Version',[AcronymName]), 'Version', LHeaderL2TP.Version, @LHeaderL2TP.Version, SizeOf(LHeaderL2TP.Version)));
    
      {The Length field indicates the total length of the message in octets.}
      if LenghtIsPresent(LHeaderL2TP.Flags) then    
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Len',[AcronymName]), 'Length', wpcapntohs(LHeaderL2TP.Length), @LHeaderL2TP.Length, SizeOf(LHeaderL2TP.Length)));

    
      {  Tunnel ID indicates the identifier for the control connection. L2TP
         tunnels are named by identifiers that have local significance only.
         That is, the same tunnel will be given different Tunnel IDs by each
         end of the tunnel. Tunnel ID in each message is that of the intended
         recipient, not the sender. Tunnel IDs are selected and exchanged as
         Assigned Tunnel ID AVPs during the creation of a tunnel.}
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.TunnelId',[AcronymName]), 'Tunnel ID', wpcapntohs(LHeaderL2TP.tunnelID), @LHeaderL2TP.tunnelID, SizeOf(LHeaderL2TP.tunnelID)));

       {
         Session ID indicates the identifier for a session within a tunnel.
         L2TP sessions are named by identifiers that have local significance
         only. That is, the same session will be given different Session IDs
         by each end of the session. Session ID in each message is that of the
         intended recipient, not the sender. Session IDs are selected and
         exchanged as Assigned Session ID AVPs during the creation of a
         session.
       }
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SessionId',[AcronymName]), 'Session ID',wpcapntohs(LHeaderL2TP.SessionId) , @LHeaderL2TP.sessionID, SizeOf(LHeaderL2TP.sessionID)));

      aAdditionalParameters.Info := Format('Tunnel ID %d Session ID %d %s',[wpcapntohs(LHeaderL2TP.tunnelID),wpcapntohs(LHeaderL2TP.SessionId),aAdditionalParameters.Info]);

      if SequencePresent(LHeaderL2TP.Flags) then    
      begin
        {
         Ns indicates the sequence number for this data or control message,
         beginning at zero and incrementing by one (modulo 2**16) for each
         message sent. See Section 5.8 and 5.4 for more information on using
         this field.      
        }
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.NextSequence',[AcronymName]), 'Next sequence', wpcapntohs(LHeaderL2TP.Ns), @LHeaderL2TP.Ns, SizeOf(LHeaderL2TP.Ns)));
        {
         Nr indicates the sequence number expected in the next control message
         to be received.  Thus, Nr is set to the Ns of the last in-order
         message received plus one (modulo 2**16). In data messages, Nr is
         reserved and, if present (as indicated by the S-bit), MUST be ignored
         upon receipt. See section 5.8 for more information on using this
         field in control messages.
        }
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.NextReceived',[AcronymName]), 'Next received', wpcapntohs(LHeaderL2TP.Nr), @LHeaderL2TP.Nr, SizeOf(LHeaderL2TP.Nr)));
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
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.OffsetSize',[AcronymName]), 'Offset size',Loffset, @LHeaderL2TP.OffsetSize, SizeOf(LHeaderL2TP.OffsetSize))); 
      end;
       
      if UDPPayLoadLen > HeaderLength(LHeaderL2TP.Flags)+Loffset then
      begin
        // Parse L2TP payload for control message AVP
        if LHeaderL2TP.Version = 2 then    
          ParseL2TPControlAVP(@LUDPPayLoad[HeaderLength(LHeaderL2TP.Flags)+Loffset],AListDetail,wpcapntohs(LHeaderL2TP.Length),aStartLevel,LVendorID,aAdditionalParameters)              
        else if LHeaderL2TP.Version = 3 then   {TODO version 3}
          DoLog('TWPcapProtocolL2TP.HeaderToString','L2TP Version 3 not implemented',TWLLWarning);                

      end;
      Result := True;
    Finally
      FreeAndNil(LVendorID);
    End;
  Finally
    Dispose(LHeaderL2TP);
  End;
end;


Class function TWPcapProtocolL2TP.AvtType0ValueToString(const aAvtValue:Uint16):String;
begin
  case aAvtValue of
    MESSAGE_TYPE_SCCRQ      : Result := 'Authorization-Request';
    MESSAGE_TYPE_SCCRP      : Result := 'Authorization-Answer';
    MESSAGE_TYPE_SCCCN      : Result := 'Session-Termination-Request';
    MESSAGE_TYPE_StopCCN    : Result := 'Session-Termination-Answer';
    MESSAGE_TYPE_Reserved_5 : Result := 'Abort-Session-Request';
    MESSAGE_TYPE_HELLO      : Result := 'Abort-Session-Answer';
    MESSAGE_TYPE_OCRQ       : Result := 'Accounting-Request';
    MESSAGE_TYPE_OCRP       : Result := 'Accounting-Answer';
    MESSAGE_TYPE_OCCN       : Result := 'Device-Watchdog-Request';
    MESSAGE_TYPE_ICRQ       : Result := 'Device-Watchdog-Answer';
    MESSAGE_TYPE_ICRP       : Result := 'Disconnect-Peer-Request';
    MESSAGE_TYPE_ICCN       : Result := 'Disconnect-Peer-Answer';
    MESSAGE_TYPE_Reserved_13: Result := 'Device-Application-Auth-Request';
    MESSAGE_TYPE_CDN        : Result := 'Call-Disconnect';
    MESSAGE_TYPE_WEN        : Result := 'Re-Auth-Request';
    MESSAGE_TYPE_SLI        : Result := 'Re-Auth-Answer';
    MESSAGE_TYPE_MDMST      : Result := 'Capability-Exchange-Request';
    MESSAGE_TYPE_SRRQ       : Result := 'Capability-Exchange-Answer';
    19..31 : Result := 'Reserved';
  else
    Result := 'Unknown';
  end;
end;

Class function TWPcapProtocolL2TP.InitVendorID: TListVendorID;
begin


  Result := TDictionary<Integer, string>.Create;
  Result.Add(VENDOR_IETF, 'Reserved');
  Result.Add(VENDOR_ACC, 'ACC');
  Result.Add(VENDOR_CISCO, 'Cisco');
  Result.Add(VENDOR_HEWLETT_PACKARD, 'Hewlett-Packard');
  Result.Add(VENDOR_SUN_MICROSYSTEMS, 'Sun Microsystems');
  Result.Add(VENDOR_MERIT, 'Merit');
  Result.Add(VENDOR_AT_AND_T, 'AT&T');
  Result.Add(VENDOR_MOTOROLA, 'Motorola');
  Result.Add(VENDOR_SHIVA, 'Shiva');
  Result.Add(VENDOR_ERICSSON, 'Ericsson');
  Result.Add(VENDOR_CISCO_VPN5000, 'Cisco VPN 5000');
  Result.Add(VENDOR_LIVINGSTON, 'Livingston');
  Result.Add(VENDOR_MICROSOFT, 'Microsoft');
  Result.Add(VENDOR_3COM, '3Com');
  Result.Add(VENDOR_ASCEND, 'Ascend');
  Result.Add(VENDOR_BAY, 'Bay');
  Result.Add(VENDOR_FOUNDRY, 'Foundry');
  Result.Add(VENDOR_VERSANET, 'Versanet');
  Result.Add(VENDOR_REDBACK, 'Redback');
  Result.Add(VENDOR_JUNIPER, 'Juniper');
  Result.Add(VENDOR_APTIS, 'Aptis');
  Result.Add(VENDOR_DT_AG, 'DT_AG');
  Result.Add(VENDOR_IXIA, 'Ixia');
  Result.Add(VENDOR_CISCO_VPN3000, 'Cisco VPN 3000');
  Result.Add(VENDOR_COSINE, 'Cosine');
  Result.Add(VENDOR_SHASTA, 'Shasta');
  Result.Add(VENDOR_NETSCREEN, 'Netscreen');
  Result.Add(VENDOR_NOMADIX, 'Nomadix');
  Result.Add(VENDOR_T_MOBILE, 'T-Mobile');
  Result.Add(VENDOR_BROADBAND_FORUM, 'Broadband Forum');
  Result.Add(VENDOR_NOKIA, 'Nokia');
  Result.Add(VENDOR_ZTE, 'ZTE');
  Result.Add(VENDOR_SIEMENS, 'Siemens');
  Result.Add(VENDOR_CABLELABS, 'CableLabs');
  Result.Add(VENDOR_UNISPHERE, 'Unisphere');
  Result.Add(VENDOR_CISCO_BBSM, 'Cisco BBSM');
  Result.Add(VENDOR_THE3GPP2, '3GPP2');
  Result.Add(VENDOR_SKT_TELECOM, 'SKT Telecom');
  Result.Add(VENDOR_IP_UNPLUGGED, 'IP Unplugged');
  Result.Add(VENDOR_ISSANNI, 'Issanni');
  Result.Add(VENDOR_NETSCALER, 'Netscaler');
  Result.Add(VENDOR_DE_TE_MOBIL, 'DeTeMobil');
  Result.Add(VENDOR_QUINTUM, 'Quintum');
  Result.Add(VENDOR_INTERLINK, 'Interlink');
  Result.Add(VENDOR_CNCTC, 'CNCTC');
  Result.Add(VENDOR_STARENT_NETWORKS, 'Starent Networks');
  Result.Add(VENDOR_COLUBRIS, 'Colubris');
  Result.Add(VENDOR_THE3GPP, '3GPP');
  Result.Add(VENDOR_GEMTEK_SYSTEMS, 'Gemtek Systems');
  Result.Add(VENDOR_BARRACUDA, 'Barracuda');
  Result.Add(VENDOR_ERICSSON_PKT_CORE, 'Ericsson PKT Core');
  Result.Add(VENDOR_DACOM, 'Dacom');
  Result.Add(VENDOR_COLUMBIA_UNIVERSITY, 'Columbia University');
  Result.Add(VENDOR_FORTINET, 'Fortinet');
  Result.Add(VENDOR_VERIZON, 'Verizon');
  Result.Add(VENDOR_PLIXER, 'Plixer');
  Result.Add(VENDOR_WIFI_ALLIANCE,'WiFi Alliance');
  Result.Add(VENDOR_T_SYSTEMS_NOVA,'T-Systems NOVA');
  Result.Add(VENDOR_TRAVELPING,'Travelport');
  Result.Add(VENDOR_CHINATELECOM_GUANZHOU,'China Telecom Guangzhou');
  Result.Add(VENDOR_GIGAMON,'Gigamon');
  Result.Add(VENDOR_CACE,'CACE Technologies');
  Result.Add(VENDOR_FASTIP,'FastIP');
  Result.Add(VENDOR_NTOP,'ntop');
  Result.Add(VENDOR_ERICSSON_CANADA_INC,'Ericsson Canada Inc.');
  Result.Add(VENDOR_NIAGARA_NETWORKS,'Niagara Networks');
  Result.Add(VENDOR_CISCO_WIFI,'Cisco WiFi');

  Result.Add(10, 'Ascend Communications, Inc.');

  Result.Add(14, 'Microsoft Corporation');
  Result.Add(18, '3Com Corporation');
  Result.Add(21, 'US Robotics Corporation');
  Result.Add(22, 'Ericsson/Redback Networks');
  Result.Add(23, 'Redback Networks');
  Result.Add(27, 'Lucent Technologies');
  Result.Add(31, 'US Robotics Corporation');
  Result.Add(41, 'Sun Microsystems, Inc.');

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

Class function TWPcapProtocolL2TP.ResultCodeStopccnToString(const aCode:Uint16):String;
begin
  case aCode of
    0: Result := 'Reserved';
    1: Result := 'General request to clear control connection';
    2: Result := 'General error, Error Code indicates the problem';
    3: Result := 'Control connection already exists';
    4: Result := 'Requester is not authorized to establish a control connection';
    5: Result := 'The protocol version of the requester is not supported';
    6: Result := 'Requester is being shut down';
    7: Result := 'Finite state machine error or timeout';
    8: Result := 'Control connection due to mismatching CCDS value';
  else
    Result := 'Unknown';
  end;    
end;

Class function TWPcapProtocolL2TP.ResultCodeToString(const aCode:Uint16):String;
begin
  case aCode of
     0: Result := 'Reserved';
     1: Result := 'Session disconnected due to loss of carrier or circuit disconnect';
     2: Result := 'Session disconnected for the reason indicated in Error Code';
     3: Result := 'Session disconnected for administrative reasons';
     4: Result := 'Appropriate facilities unavailable (temporary condition)';
     5: Result := 'Appropriate facilities unavailable (permanent condition)';
     6: Result := 'Invalid destination';
     7: Result := 'Call failed due to no carrier detected';
     8: Result := 'Call failed due to detection of a busy signal';
     9: Result := 'Call failed due to lack of a dial tone';
    10: Result := 'Call was not established within time allotted by LAC';
    11: Result := 'Call was connected but no appropriate framing was detected';
    12: Result := 'Disconnecting call due to mismatching SDS value';
    13: Result := 'Session not established due to losing tie breaker';
    14: Result := 'Session not established due to unsupported PW type';
    15: Result := 'Session not established, sequencing required without valid L2-Specific Sublayer';
    16: Result := 'Finite state machine error or timeout';
    17: Result := 'FR PVC was deleted permanently (no longer provisioned) ';       
    18: Result := 'FR PVC has been INACTIVE for an extended period of time';       
    19: Result := 'Mismatched FR Header Length';                                   
    20: Result := 'HDLC Link was deleted permanently (no longer provisioned)';     
    21: Result := 'HDLC Link has been INACTIVE for an extended period of time';    
    22: Result := 'Session not established due to other LCCE can not support the OAM Cell Emulation';  
    23: Result := 'Mismatching interface MTU';                                      
    24: Result := 'Attempt to connect to non-existent forwarder';                   
    25: Result := 'Attempt to connect to unauthorized forwarder';                   
    26: Result := 'Loop Detected';                                                  
    27: Result := 'Attachment Circuit bound to different PE';                       
    28: Result := 'Attachment Circuit bound to different remote Attachment Circuit';
    29: Result := 'Unassigned';
    30: Result := 'Return code to indicate connection was refused because of TDM PW parameters. The error code indicates the problem.'; 
    31: Result := 'Sequencing not supported'; 
  else
    Result := 'Unknown';
  end;    
end;

Class function TWPcapProtocolL2TP.AuthenTypeToString(const aType:Uint16):String;
begin
  case aType of
    0 : Result := 'Reserved';
    1 : Result := 'Textual username/password exchange';
    2 : Result := 'PPP CHAP';
    3 : Result := 'PPP PAP';
    4 : Result := 'No Authentication';
    5 : Result := 'Microsoft CHAP Version 1';
    6 : Result := 'Reserved';
    7 : Result := 'EAP';
  else
    Result := 'Unknown';
  end;    
end;

Class function TWPcapProtocolL2TP.L2SublayerToString(const aSubLayer:Uint16):String;
begin
  case aSubLayer of
    0: Result := 'No L2-Specific Sublayer';
    1: Result := 'Default L2-Specific Sublayer present';
    2: Result := 'ATM-Specific Sublayer present';
    3: Result := 'MPT-Specific Sublayer';
    4: Result := 'PSP-Specific Sublayer';
  else
    Result := 'Unknown';
  end;    
end;    

Class function TWPcapProtocolL2TP.PWTypesToString(const aPwType:Uint16):String;
CONST
  L2TPv3_PW_DEFAULT     = $0000;
  L2TPv3_PW_FR          = $0001;
  L2TPv3_PW_AAL5        = $0002;
  L2TPv3_PW_ATM_PORT    = $0003;
  L2TPv3_PW_ETH_VLAN    = $0004;
  L2TPv3_PW_ETH         = $0005;
  L2TPv3_PW_CHDLC       = $0006;
  L2TPv3_PW_PPP         = $0007; // Scaduto, non assegnato
  L2TPv3_PW_ATM_VCC     = $0009;
  L2TPv3_PW_ATM_VPC     = $000A;
  L2TPv3_PW_IP          = $000B; // Scaduto, non assegnato
  L2TPv3_PW_DOCSIS_DMPT = $000C; // MPEG2-TS
  L2TPv3_PW_DOCSIS_PSP  = $000D;
  L2TPv3_PW_E1          = $0011;
  L2TPv3_PW_T1          = $0012;
  L2TPv3_PW_E3          = $0013;
  L2TPv3_PW_T3          = $0014;
  L2TPv3_PW_CESOPSN     = $0015;
  L2TPv3_PW_CESOPSN_CAS = $0017;
begin
  case aPwType of
    L2TPv3_PW_FR          : Result := 'Frame Relay DLCI';
    L2TPv3_PW_AAL5        : Result := 'ATM AAL5 SDU VCC transport';
    L2TPv3_PW_ATM_PORT    : Result := 'ATM Cell transparent Port Mode';
    L2TPv3_PW_ETH_VLAN    : Result := 'Ethernet VLAN';
    L2TPv3_PW_ETH         : Result := 'Ethernet';
    L2TPv3_PW_CHDLC       : Result := 'HDLC';
    L2TPv3_PW_PPP         : Result := 'PPP'; 
    L2TPv3_PW_ATM_VCC     : Result := 'ATM Cell transport VCC Mode';
    L2TPv3_PW_ATM_VPC     : Result := 'ATM Cell transport VPC Mode';
    L2TPv3_PW_IP          : Result := 'IP Transport';
    L2TPv3_PW_DOCSIS_DMPT : Result := 'MPEG-TS Payload Type (MPTPW)';
    L2TPv3_PW_DOCSIS_PSP  : Result := 'Packet Streaming Protocol (PSPPW)';   
    L2TPv3_PW_E1          : Result := 'Structure-agnostic E1 circuit';       
    L2TPv3_PW_T1          : Result := 'Structure-agnostic T1 (DS1) circuit'; 
    L2TPv3_PW_E3          : Result := 'Structure-agnostic E3 circuit';       
    L2TPv3_PW_T3          : Result := 'Structure-agnostic T3 (DS3) circuit'; 
    L2TPv3_PW_CESOPSN     : Result := 'CESoPSN basic mode';                  
    $0016                 : Result := 'Unassigned';
    L2TPv3_PW_CESOPSN_CAS : Result := 'CESoPSN TDM with CAS';                
  else
    Result := 'Unknown';
  end;    
end;

Class function TWPcapProtocolL2TP.DataSequenceToString(const aSubLayer:Uint16):String;
begin
  case aSubLayer of
     0: Result := 'No incoming data packets require sequencing';
     1: Result := 'Only non-IP data packets require sequencing';
     2: Result := 'All incoming data packets require sequencing';
  else
    Result := 'Unknown';
  end;    
end;

Class procedure TWPcapProtocolL2TP.ReadAVPValueFromPacket(const aLabel:String;const aPayloadData: PByte;aPayloadSize:Integer;var aCurrentPos:integer;var aIsStopCcn: Boolean;
                          const aAvpLength,aAvpType,aStartLevel: Integer; aVendorID: TListVendorId;AListDetail: TListHeaderString;aAdditionalParameters: PTAdditionalParameters);
var LUint16        : UInt16;   
    LAvpTypeCaption: STring; 
    LLabel         : STring;
    LMessageType   : Uint16;  //L2TPv3
    LDigit         : String;  //L2TPv3
    LDigitInxex    : Integer; //L2TPv3
    LBckAvpLen     : Integer;
begin
  LAvpTypeCaption := Format('%s:',[L2TPAVPTypeToString(aAvpType)]);
  LLabel          := Format('%s.Value',[aLabel]);
  case aAvpType of
    AVTYPE_CONTROL_MESSAGE: 
      begin
        LUint16 := ParserUint16Value(aPayloadData,aStartLevel,aPayloadSize,LLabel,LAvpTypeCaption,AListDetail,AvtType0ValueToString,true,aCurrentPos);
        aAdditionalParameters.Info := Format('%s %s %s',[LAvpTypeCaption,AvtType0ValueToString(LUint16),aAdditionalParameters.Info]);
        if (LUint16 = MESSAGE_TYPE_StopCCN) then
          aIsStopCcn := true;
      end;

    AVTYPE_RESULT_ERROR_CODE:
      begin  
        if (aAvpLength < 2)then Exit;

        if aIsStopCcn then
          ParserUint16Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.StopResulCode',[aLabel]),'Stop result code:',AListDetail,ResultCodeStopccnToString,true,aCurrentPos)
        else 
          ParserUint16Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.ResultCode',[aLabel]),'Result code:',AListDetail,ResultCodeToString,true,aCurrentPos);

        if (aAvpLength -2 < 2) then Exit;
          ParserUint16Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.Code',[aLabel]),'Error code:',AListDetail,GetErrorMessage,true,aCurrentPos);
      
        if (aAvpLength -4 < 2) then Exit;
          ParserGenericBytesValue(aPayloadData,aStartLevel,aCurrentPos+aAvpLength -4,aAvpLength -4,Format('%s.Message',[aLabel]),'Error message:',AListDetail,BytesToStringRawInternal,true,aCurrentPos);
      end;      

    AVTYPE_PROTOCOL_VERSION :
      begin      
        if (aAvpLength < 1)then Exit;      
        ParserUint8Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.ProtocolVersion',[aLabel]),'Protocol version:',AListDetail,nil,true,aCurrentPos);
        ParserUint8Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.ProtocolRevision',[aLabel]),'Protocol revision:',AListDetail,nil,true,aCurrentPos);
      end;

    AVTYPE_FRAMING_CAPABILITIES:
      begin
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.AsyncFramingSupported',[aLabel]),'Async framing supported:',AListDetail,nil,true,aCurrentPos);
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.SyncFramingSupported',[aLabel]),'Sync framing supported:',AListDetail,nil,true,aCurrentPos);      
      end;

    AVTYPE_BEARER_CAPABILITIES:
      begin
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.AnalogAccessSupported',[aLabel]),'Analog access supported:',AListDetail,nil,true,aCurrentPos);
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.DigitalAccessSupported',[aLabel]),'Digital access supported:',AListDetail,nil,true,aCurrentPos);      
      end;

    AVTYPE_TIE_BREAKER         : ParserGenericBytesValue(aPayloadData,aStartLevel,aCurrentPos+aAvpLength,8,LLabel,LAvpTypeCaption,AListDetail,nil,true,aCurrentPos);

    AVTYPE_CAUSE_CODE          :
      begin
        if (aAvpLength < 2)then Exit;

        ParserUint16Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.Coee',[aLabel]),'Cause code:',AListDetail,nil,true,aCurrentPos);

        if (aAvpLength -2 < 1) then Exit;
          ParserUint8Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.Message',[aLabel]),'Cause message:',AListDetail,nil,true,aCurrentPos);
      
        if (aAvpLength -3 <= 0) then Exit;
          ParserGenericBytesValue(aPayloadData,aStartLevel,aCurrentPos+aAvpLength -3,aAvpLength -3,Format('%s.AdvisorMessage',[aLabel]),'Advisor message:',AListDetail,BytesToStringRawInternal,true,aCurrentPos)
      end;

    AVTYPE_CHALLENGE_RESPONSE : ParserGenericBytesValue(aPayloadData,aStartLevel,aCurrentPos+aAvpLength,16,Format('%s.ChanllengeResponse',[aLabel]),'ChanllengeResponse:',AListDetail,BytesToStringRawInternal,true,aCurrentPos);

    AVTYPE_BEARER_TYPE        : 
      begin
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.AnalogBearType',[aLabel]),'Analog bear type:',AListDetail,nil,true,aCurrentPos);
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.DigitalBearType',[aLabel]),'Digital bear type:',AListDetail,nil,true,aCurrentPos);
      end;

    AVTYPE_FRAMING_TYPE       : 
      begin
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.AsyncFramingType',[aLabel]),'Async framing type:',AListDetail,nil,true,aCurrentPos);
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.SyncFramingType',[aLabel]),'Sync framing type:',AListDetail,nil,true,aCurrentPos);    
      end;  
         
    AVTYPE_LAST_SENT_LCP_CONFREQ,   
    AVTYPE_LAST_RECEIVED_LCP_CONFREQ,  
    AVTYPE_INITIAL_RECEIVED_LCP_CONFREQ:
      begin
        ParserGenericBytesValue(aPayloadData,aStartLevel,aCurrentPos+aAvpLength,aAvpLength,LLabel,LAvpTypeCaption,AListDetail,BytesToHex,true,aCurrentPos);
        {Dissector ??}
        DoLog('TWPcapProtocolL2TP.ReadAVPValueFromPacket',Format('AVPType [%d] with len [%d] Dissector not implemented',[aAvpType,aAvpLength]),TWLLWarning);         
      end;

    AVTYPE_PROXY_AUTHEN_TYPE   :
      begin
        LMessageType := ParserUint16Value(aPayloadData,aStartLevel,aPayloadSize,LLabel,LAvpTypeCaption,AListDetail,AuthenTypeToString,true,aCurrentPos);      
        //TODO use for next AVP   
      end;

    AVTYPE_CALL_STATUS_AVPS    :
      begin
        if (aAvpLength < 6)then Exit;

        Inc(aCurrentPos,2);

        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.CRCError',[aLabel]),'CRC Error:',AListDetail,nil,True,aCurrentPos);

        if (aAvpLength -10 < 4) then Exit;
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.FremingError',[aLabel]),'Error framing:',AListDetail,nil,True,aCurrentPos);
      
        if (aAvpLength -14 < 4) then Exit;
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.HardwareOverruns',[aLabel]),'Hardware overruns:',AListDetail,nil,true,aCurrentPos);

        if (aAvpLength -18 < 4) then Exit;
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.BufferOverruns',[aLabel]),'Buffer overruns:',AListDetail,nil,true,aCurrentPos);

        if (aAvpLength -22 < 4) then Exit;
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.TimeOutErrors',[aLabel]),'Time out errors:',AListDetail,nil,true,aCurrentPos);

        if (aAvpLength -26 < 4) then Exit;        
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.AlignmentErrors',[aLabel]),'Alignment errors:',AListDetail,nil,true,aCurrentPos);
      end;      

    AVTYPE_ACCM: 
      begin
       if (aAvpLength < 6)then Exit;

        Inc(aCurrentPos,2);

        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.SendACCM',[aLabel]),'Send ACCM:',AListDetail,nil,True,aCurrentPos);

        if (aAvpLength -10 < 4) then Exit;
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.ReceiveACCM',[aLabel]),'Receive ACCM:',AListDetail,nil,true,aCurrentPos);
       
      end;
      
    AVTYPE_PPP_DISCONNECT_CAUSE_CODE  :
      begin
        if (aAvpLength < 2)then Exit;

        ParserUint16Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.DisconnectCode',[aLabel]),'Disconnet code:',AListDetail,nil,True,aCurrentPos);

        if (aAvpLength -2 < 2) then Exit;
        ParserUint16Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.ProtocolNumber',[aLabel]),'Protocol number:',AListDetail,nil,True,aCurrentPos);
      
        if (aAvpLength -4 < 1) then Exit;
        ParserUint8Value(aPayloadData,aStartLevel,aPayloadSize,Format('%s.CauseCodeDirection',[aLabel]),'Cause code direction:',AListDetail,CauseCodeDirectionToString,True,aCurrentPos);

        if (aAvpLength -5 <= 0) then Exit;
        ParserGenericBytesValue(aPayloadData,aStartLevel,aCurrentPos+aAvpLength,aAvpLength,Format('%s.CauseCodeMessage',[aLabel]),'Cause code Message:',AListDetail,BytesToStringRawInternal,true,aCurrentPos);              
      end;

    AVTYPE_MESSAGE_DIGEST      :
      begin  
         LDigitInxex := aCurrentPos;
         LDigit      := ParserGenericBytesValue(aPayloadData,aStartLevel,aCurrentPos+aAvpLength,aAvpLength,LLabel,LAvpTypeCaption,AListDetail,BytesToHex,true,aCurrentPos);
         DoLog('TWPcapProtocolL2TP.ReadAVPValueFromPacket',Format('AVPType [%d] with len [%d] check_control_digest not implemented',[aAvpType,aAvpLength]),TWLLWarning);         
      end;

    AVTYPE_ASSIGNED_CONTROL_CONN_ID   :
      begin
         ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,LLabel,LAvpTypeCaption,AListDetail,nil,true,aCurrentPos);
         DoLog('TWPcapProtocolL2TP.ReadAVPValueFromPacket',Format('AVPType [%d] with len [%d] L2TPv3 (calculate lcce1_id and lcce2_id by LMessageType) not implemented',[aAvpType,aAvpLength]),TWLLWarning);
      end;
      
    AVTYPE_PW_CAPABILITY_LIST  :
      begin
        AListDetail.Add(AddHeaderInfo(aStartLevel, LLabel ,'Pseudowire Capabilities List',null,PByte(aPayloadData[aCurrentPos]),aAvpLength )); 
        LBckAvpLen :=  aAvpLength;
        while (LBckAvpLen >= 2) do
        begin
          ParserUint16Value(aPayloadData,aStartLevel+1,aPayloadSize,LLabel,LAvpTypeCaption,AListDetail,PWTypesToString,true,aCurrentPos);
          Dec(LBckAvpLen)
        end;
      end;

    AVTYPE_LOCAL_SESSION_ID    :
      begin
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,LLabel,LAvpTypeCaption,AListDetail,nil,true,aCurrentPos);
        DoLog('TWPcapProtocolL2TP.ReadAVPValueFromPacket',Format('AVPType [%d] with len [%d] L2TPv3 (calculate lsession_id) not implemented',[aAvpType,aAvpLength]),TWLLWarning);
      end;

    AVTYPE_REMOTE_SESSION_ID :
      begin
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,LLabel,LAvpTypeCaption,AListDetail,nil,true,aCurrentPos);
        DoLog('TWPcapProtocolL2TP.ReadAVPValueFromPacket',Format('AVPType [%d] with len [%d] L2TPv3 (calculate lsession_id) not implemented',[aAvpType,aAvpLength]),TWLLWarning);        
      end;      
    AVTYPE_ASSIGNED_COOKIE     :
      begin
        ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,LLabel,LAvpTypeCaption,AListDetail,nil,true,aCurrentPos);
        DoLog('TWPcapProtocolL2TP.ReadAVPValueFromPacket',Format('AVPType [%d] with len [%d] L2TPv3 (calculate Cookie) not implemented',[aAvpType,aAvpLength]),TWLLWarning);
      end;

    AVTYPE_PW_TYPE             :
      begin
        ParserUint16Value(aPayloadData,aStartLevel,aPayloadSize,LLabel,LAvpTypeCaption,AListDetail,PWTypesToString,true,aCurrentPos);
        DoLog('TWPcapProtocolL2TP.ReadAVPValueFromPacket',Format('AVPType [%d] with len [%d] L2TPv3 (calculate pw_type) not implemented',[aAvpType,aAvpLength]),TWLLWarning);        
      end;

    AVTYPE_L2_SPECIFIC_SUBLAYER : 
       begin
        ParserUint16Value(aPayloadData,aStartLevel,aPayloadSize,LLabel,LAvpTypeCaption,AListDetail,L2SublayerToString,true,aCurrentPos);
        DoLog('TWPcapProtocolL2TP.ReadAVPValueFromPacket',Format('AVPType [%d] with len [%d] L2TPv3 (calculate L2S ublayer) not implemented',[aAvpType,aAvpLength]),TWLLWarning);        
      end;
      
    AVTYPE_CIRCUIT_STATUS:
      begin
        ParserUint16Value(aPayloadData,aStartLevel,aPayloadSize,LLabel,LAvpTypeCaption,AListDetail,nil,true,aCurrentPos);
        ParserUint16Value(aPayloadData,aStartLevel,aPayloadSize,LLabel+'.Type',LAvpTypeCaption+ ' type',AListDetail,nil,true,aCurrentPos);
      end;
      
    AVTYPE_CTL_MSG_AUTH_NONCE:
      begin
        ParserGenericBytesValue(aPayloadData,aStartLevel,aCurrentPos+aAvpLength,aAvpLength,LLabel,LAvpTypeCaption,AListDetail,BytesToHex,true,aCurrentPos);
        DoLog('TWPcapProtocolL2TP.ReadAVPValueFromPacket',Format('AVPType [%d] with len [%d] L2TPv3 (calculate cma_nonce) not implemented',[aAvpType,aAvpLength]),TWLLWarning);        
      end;


    AVTYPE_TX_CONNECT_SPEED_V3,
    AVTYPE_RX_CONNECT_SPEED_V3 :
      begin 
        if (aAvpLength < 8)then Exit;
        ParserUint64Value(aPayloadData,aStartLevel,aPayloadSize,LLabel,LAvpTypeCaption,AListDetail,nil,true,aCurrentPos);
      end;

    AVTYPE_CONNECT_SPEED_UPDATE:
      begin
        ParserGenericBytesValue(aPayloadData,aStartLevel,aCurrentPos+aAvpLength,aAvpLength,LLabel,LAvpTypeCaption,AListDetail,BytesToHex,true,aCurrentPos);
        if (aAvpLength = 12) then   // L2TPv2 
        begin
          
          DoLog('TWPcapProtocolL2TP.ReadAVPValueFromPacket',Format('AVTYPE_CONNECT_SPEED_UPDATE subtree L2TPv2 not implemented',[aAvpType,aAvpLength]),TWLLWarning);        
        end
        else if (aAvpLength = 20) then  // L2TPv3 
        begin
          DoLog('TWPcapProtocolL2TP.ReadAVPValueFromPacket',Format('AVTYPE_CONNECT_SPEED_UPDATE subtree L2TPv3 not implemented',[aAvpType,aAvpLength]),TWLLWarning);         
        end;      
      end;
      
    AVTYPE_DATA_SEQUENCING     : ParserUint16Value(aPayloadData,aStartLevel,aPayloadSize,LLabel,LAvpTypeCaption,AListDetail,DataSequenceToString,true,aCurrentPos); 
    AVTYPE_PROXY_AUTHEN_ID     : ParserUint8Value(aPayloadData,aStartLevel,aPayloadSize,LLabel,LAvpTypeCaption,AListDetail,nil,true,aCurrentPos);

    AVTYPE_ASSIGNED_SESSION,
    AVTYPE_ASSIGNED_TUNNEL_ID,
    AVTYPE_RECEIVE_WINDOW_SIZE,
    AVTYPE_FIRMWARE_REVISION     : ParserUint16Value(aPayloadData,aStartLevel,aPayloadSize,LLabel,LAvpTypeCaption,AListDetail,nil,true,aCurrentPos);
              
    AVTYPE_CALL_SERIAL_NUMBER,
    AVTYPE_TX_CONNECT_SPEED,
    AVTYPE_RX_CONNECT_SPEED,
    AVTYPE_ROUTER_ID,
    AVTYPE_MINIMUM_BPS,        
    AVTYPE_MAXIMUM_BPS           : ParserUint32Value(aPayloadData,aStartLevel,aPayloadSize,LLabel,LAvpTypeCaption,AListDetail,nil,true,aCurrentPos);
    
    AVTYPE_CALLED_NUMBER,
    AVTYPE_CALLING_NUMBER,
    AVTYPE_PREFERRED_LANGUAGE,
    AVTYPE_REMOTE_END_ID,
    AVTYPE_SUB_ADDRESS,
    AVTYPE_VENDOR_NAME,
    AVTYPE_CHALLENGE,
    AVTYPE_PROXY_AUTHEN_NAME,
    AVTYPE_HOST_NAME              : ParserGenericBytesValue(aPayloadData,aStartLevel,aCurrentPos+aAvpLength,aAvpLength,LLabel,LAvpTypeCaption,AListDetail,BytesToStringRawInternal,true,aCurrentPos);

    AVTYPE_PROXY_AUTHEN_RESPONSE,
    AVTYPE_RANDOM_VECTOR,    
    AVTYPE_PRIVATE_GROUP_ID,
    AVTYPE_PROXY_AUTHEN_CHALLENGE : ParserGenericBytesValue(aPayloadData,aStartLevel,aCurrentPos+aAvpLength,aAvpLength,LLabel,LAvpTypeCaption,AListDetail,BytesToHex,true,aCurrentPos);
    
    {TODO CONSTANT!!}
    20,77,79,91,96,92,93      : ParserUint16Value(aPayloadData,aStartLevel,aPayloadSize,LLabel,'Value:',AListDetail,nil,true,aCurrentPos);

    40,53,54,55,51,52,57,80,  
    126,127,134,159,135, 163, 
    164, 165, 166,138, 
    154, 155, 156, 157, 
    158,141                   : ParserGenericBytesValue(aPayloadData,aStartLevel,aCurrentPos+aAvpLength,aAvpLength,LLabel,'Value:',AListDetail,BytesToHex,true,aCurrentPos); 

  else
    DoLog('TWPcapProtocolL2TP.ReadAVPValueFromPacket',Format('AVPType [%d] with len [%d] not implemented',[aAvpType,aAvpLength]),TWLLWarning); 
  end;
end;	   

class function TWPcapProtocolL2TP.HiddenFlagIsSetted(aAvpLen: Integer): Boolean;
begin
  Result := (aAvpLen and $4000) = $4000;
end;  

class function TWPcapProtocolL2TP.ParseL2TPControlAVP(const aPayloadData: PByte;AListDetail: TListHeaderString;aLengthPayload:Uint16;aStartLevel:Integer;aVendorID: TListVendorId;aAdditionalParameters: PTAdditionalParameters): string;
CONST AVP_LENGHT_WITHOUT_VALUE = 6;
var LAvpHeader      : TAVPHeader;
    LAvpType        : Uint16;
    LAvpFlag        : Uint16;
    LAvpLength      : Uint16;
    LCurrentPos     : Integer;
    LByte0          : Uint8;
    LByte1          : Uint8;
    LTypeStr        : string; 
    LLabel          : String;
    LisStopMsg      : boolean;
    LBckPos         : Integer;
    LVendorID       : Uint16;
    LVendorStr      : String;
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
  // Start from the beginning of the payload
  LCurrentPos := 0;
  LisStopMsg  := False;
  // Loop through the payload data until the end is reached
  while LCurrentPos < aLengthPayload do
  begin
    // Extract AVP header information
    LAvpHeader := PAVPHeader(aPayloadData + LCurrentPos)^;
    LAvpFlag   := wpcapntohs(LAvpHeader.AvtFlag);
    LAvpType   := wpcapntohs(LAvpHeader.AttrType);
    LAvpLength := GetLastNBit(LAvpFlag,10);  

    if LAvpLength < AVP_LENGHT_WITHOUT_VALUE then break;
    if LCurrentPos+LAvpLength > aLengthPayload then break;
    
    
    LTypeStr   := L2TPAVPTypeToString(LAvpType);
    LLabel     := Format('%s.AVP.%s',[AcronymName,LTypeStr]);  
    
    AListDetail.Add(AddHeaderInfo(aStartLevel+1, LLabel , Format('AVP %s ', [LTypeStr]),null,@LAvpHeader,SizeOF(LAvpHeader), LAvpType )); 

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
    LByte0 := GetByteFromWord(LAvpFlag,0);
    LByte1 := GetByteFromWord(LAvpFlag,1);
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags',[LLabel]), 'Flags:',Format('%s %s',[ByteToBinaryString(LByte0),
                                                                                                       ByteToBinaryString(LByte1)]),
                                 @LAvpFlag,sizeOf(LAvpFlag),GetByteFromWord(LAvpFlag,0)));       
                                                            
    AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Flags.Mandatory',[LLabel]), 'Mandatory:',GetBitValue(LByte1,1)=1, @LByte1,SizeOf(LByte1), GetBitValue(LByte1,1) ));
    AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Flags.Hidden',[LLabel]), 'Hidden:',GetBitValue(LByte1,2)=1, @LByte1,SizeOf(LByte1), GetBitValue(LByte1,2) ));
    AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Flags.Length',[LLabel]), 'Length:',LAvpLength,@LAvpLength,10)); 

    if HiddenFlagIsSetted(wpcapntohs( PUint16(aPayloadData + LCurrentPos)^)) then 
    begin
      Inc(LCurrentPos, LAvpLength);
      Continue;
    end;
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
    LVendorID := wpcapntohs(LAvpHeader.VendorID);
    if aVendorID.TryGetValue(LVendorID,LVendorStr) then    
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Vendor',[LLabel]), 'Vendor:',LVendorStr,@LAvpHeader.VendorID,sizeOf(LAvpHeader.VendorID),LVendorID))
    else                                       
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Vendor',[LLabel]), 'Vendor:',LVendorID,@LAvpHeader.VendorID,sizeOf(LAvpHeader.VendorID)));

    {Attribute Type: A 2 octet value with a unique interpretation across
     all AVPs defined under a given Vendor ID.}    
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Type',[LLabel]), 'Type:',L2TPAVPTypeToString(LAvpType),@LAvpHeader.AttrType,sizeOf(LAvpHeader.AttrType), LAvpType ));       
    
    // Check if the AVP has a value

    {Attribute Value: This is the actual value as indicated by the Vendor
     ID and Attribute Type. It follows immediately after the Attribute
     Type field, and runs for the remaining octets indicated in the Length
     (i.e., Length minus 6 octets of header). This field is absent if the
     Length is 6.}

    Inc(LCurrentPos, SizeOf(TAVPHeader));  
    LBckPos := LCurrentPos;     

    {TODO AVP For Vendor}
    case LVendorID of
      VENDOR_CISCO          : DoLog('TWPcapProtocolL2TP.HeaderToString','AVPValue custom VENDOR_CISCO not implemented',TWLLWarning);                
      VENDOR_BROADBAND_FORUM: DoLog('TWPcapProtocolL2TP.HeaderToString','AVPValue custom VENDOR_BROADBAND_FORUM not implemented',TWLLWarning);                
      VENDOR_ERICSSON       : DoLog('TWPcapProtocolL2TP.HeaderToString','AVPValue custom VENDOR_ERICSSON not implemented',TWLLWarning);                
    end;
    ReadAVPValueFromPacket(LLabel,aPayloadData,aLengthPayload,LCurrentPos,LisStopMsg,LAvpLength,LAvpType,aStartLevel+2,aVendorID,AListDetail,aAdditionalParameters);
    
    if ( LAvpLength -SizeOf(TAVPHeader) )- (LCurrentPos - LBckPos) > 0 then
      Inc(LCurrentPos,( LAvpLength -SizeOf(TAVPHeader) )- (LCurrentPos - LBckPos) );    

  end;
end;


end.
