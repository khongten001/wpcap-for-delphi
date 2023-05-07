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

unit wpcap.Protocol.DHCP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils, wpcap.StrUtils,wpcap.packet,
  idGlobal, Wpcap.protocol.UDP, WinApi.Windows, wpcap.BufferUtils, Variants,winSock2,
  wpcap.IPUtils, System.StrUtils;

type
 {https://www.rfc-editor.org/rfc/rfc2131,

 [Options]
 https://www.iana.org/assignments/bootp-dhcp-parameters/bootp-dhcp-parameters.xhtml
 }

{

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
   +---------------+---------------+---------------+---------------+
   |                            xid (4)                            |
   +-------------------------------+-------------------------------+
   |           secs (2)            |           flags (2)           |
   +-------------------------------+-------------------------------+
   |                          ciaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          yiaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          siaddr  (4)                          |
   +---------------------------------------------------------------+
   |                          giaddr  (4)                          |
   +---------------------------------------------------------------+
   |                                                               |
   |                          chaddr  (16)                         |
   |                                                               |
   |                                                               |
   +---------------------------------------------------------------+
   |                                                               |
   |                          sname   (64)                         |
   +---------------------------------------------------------------+
   |                                                               |
   |                          file    (128)                        |
   +---------------------------------------------------------------+
   |                                                               |
   |                          options (variable)                   |
   +---------------------------------------------------------------+
}
 
 TDHCPHeader = packed record
    OpCode        : UInt8;                 // Type
    HType         : UInt8;                 // hardware type
    HLen          : UInt8;                 // Len address hardware
    Hops          : UInt8;                 // Number of hops
    TransactionID : DWORD;                // ID transaction
    SecondsElapsed: Uint16;                 // Second elapsed
    Flags         : Uint16;                 // Flag
    ClientIP      : Uint32;             // IP client
    YourIP        : Uint32;             // IP assigned to client
    ServerIP      : Uint32;             // IP server DHCP
    RelayAgentIP  : Uint32;             // IP relay agent
    ClientMAC     : array[0..15] of UInt8; // MAC of client with padding
    ServerName    : array[0..63] of UInt8;
    BootFileName  : array[0..127] of UInt8;
    MagicCookie   : Uint32;  
  end;  
  PTDHCPHeader = ^TDHCPHeader; 

  {
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     Code      |    Length     |  Protocol     |   Algorithm   |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |     RDM       | Replay Detection (64 bits)                    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Replay cont.                                                 |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Replay cont. |                                               |
     +-+-+-+-+-+-+-+-+                                               |
     |                                                               |
     |           Authentication Information                          |
     |                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  }
  
  TDHCPAuthentication  = packed record
    Protocol          : UInt8;       
    Algorithm         : UInt8;        
    RDM               : UInt8;      
    ReplayDetection   : UInt64;   
    SecretID          : UInt32;
    AuthenticationInfo: array[0..15]of UInt8; // 64 byte        
  end;
  PTDHCPAuthentication = ^TDHCPAuthentication; 
  
  /// <summary>
  /// The SIP protocol implementation class.
  /// </summary>
  TWPcapProtocolDHCP = Class(TWPcapProtocolBaseUDP)
  private     
    CONST
    OPTION_PAD                                      = 0;
    OPTION_SUB_NETMASK                              = 1;
    OPTION_TIME_OFFSET                              = 2;    
    OPTION_SUB_ROUTER                               = 3;
    OPTION_NAME_ADDR                                = 5;
    OPTION_DOMAIN_ADDR                              = 6;
    OPTION_LOG_ADDR                                 = 7;
    OPTION_QUOTE_ADDR                               = 8;
    OPTION_LPR_ADDR                                 = 9;
    OPTION_IMPRESS_ADDR                             = 10;
    OPTION_RPL_ADDR                                 = 11;
    OPTION_HOSTNAME                                 = 12;
    OPTION_BOOT_FILE_SIZE                           = 13;
    OPTION_MERIT_DUMP_FILE                          = 14;
    OPTION_DOMAIN_NAME                              = 15;
    OPTION_SWAP_SERVER                              = 16;
    OPTION_ROOT_PATH                                = 17;
    OPTION_EXT_FILE                                 = 18;
    OPTION_FORWARD_ON_OFF                           =	19;    
    OPTION_SRCRTE_ON_OFF                            =	20;    
    OPTION_ROOT_FILER                               = 21;
    OPTION_MAX_DG_ASSEMBLY                          = 22;
    OPTION_DEFAULT_IP_TTL                           =	23;    
    OPTION_MTU_TIMEOUT                              = 24;    
    OPTION_MTU_PLATEAU                              = 25;
    OPTION_MTU_INTERFACE	                          = 26;	    
    OPTION_MTU_SUBNET                               =	27;    
    OPTION_BROADCAST_ADDR                           = 28;
    OPTION_MASK_DISCOVERY                           =	29;
    OPTION_MASK_SUPPLIER                            =	30;
    OPTION_ROUTER_DISCOVERY                         =	31;    
    OPTION_ROUTER_REQUEST                           = 32;
    OPTION_STATIC_ROUTE                             = 33;
    OPTION_TRAILERS                                 =	34;   
    OPTION_ARP_TIMEOUT                              = 35;    
    OPTION_ETHERNET                                 =	36;
    OPTION_DEFAULT_TCP_TTL                          =	37;
    OPTION_KEEPALIVE_TIME                           = 38;
    OPTION_KEEPALIVE_DATA                           =	39;     
    OPTION_NIS_DOMAIN                               = 40;
    OPTION_NIS_SERVERS                              = 41;
    OPTION_NTP_SERVERS                              = 42;
    OPTION_VENDOR_SPECIFIC                          = 43;
    OPTION_NETBIOS_NAME_SRV                         = 44;
    OPTION_NETBIOS_DIST_SRV                         = 45;
    OPTION_NETBIOS_NODE_TYPE                        =	46;    
    OPTION_NETBIOS_SCOPE                            = 47;
    OPTION_X_WINDOW_FONT                            = 48;
    OPTION_X_WINDOW_MANAGER                         = 49;    
    OPTION_ADDR_REQUEST                             = 50;
    OPTION_ADDRESS_TIME                             = 51;    
    OPTION_OVERLOAD                                 =	52;
    OPTION_DHCP_MSG_TYPE                            =	53; 
    OPTION_DHCP_SERVER_ID                           = 54;   
    OPTION_PARAMETER_LIST                           = 55;
    OPTION_DHCP_MESSAGE                             = 56;
    OPTION_DHCP_MAX_MSG_SIZE                        = 57;	
    OPTION_RENEWAL_TIME                             = 58;
    OPTION_REBINDING_TIME                           = 59;        
    OPTION_CLASS_ID                                 = 60;
    OPTION_CLIENT_ID                                = 61;
    OPTION_NETWARE_IP_DOMAIN                        = 62;
    OPTION_NETWARE_IP_OPTION                        = 63;
    OPTION_NISDOMAINNAME                            = 64;
    OPTION_NISSERVERADDR                            = 65;
    OPTION_SERVERNAME                               = 66;
    OPTION_BOOTFILENAME                             = 67;
    OPTION_HOMEAGENTADDRS                           = 68;
    OPTION_SMTPSERVER                               = 69;
    OPTION_POP3SERVER                               = 70;
    OPTION_NNTPSERVER                               = 71;
    OPTION_WWWSERVER                                = 72;
    OPTION_FINGERSERVER                             = 73;
    OPTION_IRCSERVER                                = 74;
    OPTION_STREETTALKSERVER                         = 75;
    OPTION_STDASERVER                               = 76;
    OPTION_USERCLASS                                = 77;
    OPTION_DIRECTORY_AGENT                          = 78;
    OPTION_SERVICE_SCOPE                            = 79;
    OPTION_CLIENT_FQDN                              = 81;
    OPTION_RELAY_AGENT_INFORMATION                  = 82;
    OPTION_ISNS                                     = 83;
    OPTION_NDS_SERVERS                              = 85;
    OPTION_NDS_TREE_NAME                            = 86;
    OPTION_NDS_CONTEXT                              = 87;
    OPTION_AUTHENTICATION                           = 90;
    OPTION_CLIENT_SYSTEM                            = 93;
    OPTION_CLIENT_NDI                               = 94;
    OPTION_LDAP                                     = 95;
    OPTION_UUID_GUID                                = 97;
    OPTION_USERAUTH                                 = 98;
    OPTION_PCODE                                    = 100;
    OPTION_TCODE                                    = 101;
    OPTION_IPV6_ONLY_PREFERRED                      = 108;    
    OPTION_DHCP4O6_S46_SADDR                      	= 109;    
    OPTION_NETINFO_ADDRESS                          = 112;
    OPTION_NETINFO_TAG                              = 113;
    OPTION_DHCP_CAPTIVEPORTAL                       = 114;
    OPTION_AUTOCONFIG                               = 116;
    OPTION_NAME_SERVICE_SEARCH                      = 117;
    OPTION_SUBNET_SELECTION_OPTION                  = 118;    
    OPTION_DOMAIN_SEARCH                            = 119;
    OPTION_SIP_SERVERS_DHCP_OPTION                  = 120;
    OPTION_CLASSLESS_STATIC_ROUTE_OPTION            = 121;
    OPTION_CCC                                      = 122;
    OPTION_GEOCONF                                  = 123;     
    OPTION_OPTION_CAPWAP_AC_V4                      = 138;    
    OPTION_OPTIONIPV4_ADDRESSMOS                    = 139;
    OPTION_OPTIONIPV4_FQDNMOS                       = 140;
    OPTION_SIP_UA_CONFIGURATION_SERVICE_DOMAINS     = 141;
    OPTION_OPTIONIPV4_ADDRESSANDSF                  = 142;
    OPTION_OPTION_V4_SZTP_REDIRECT                  = 143;
    OPTION_GEOLOC                                   = 144;    
    OPTION_FORCERENEW_NONCE_CAPABLE                 =	145;    
    OPTION_RDNSS_SELECTION                          = 146;
    OPTION_OPTION_V4_DOTS_RI                        = 147;
    OPTION_OPTION_V4_DOTS_ADDR                      = 148;    
    OPTION_STATUS_CODE                              = 151;
    OPTION_BASE_TIME                                = 152;
    OPTION_START_TIME_OF_STATE                      = 153;
    OPTION_QUERY_START_TIME                         = 154;
    OPTION_QUERY_END_TIME                           = 155;    
    OPTION_DHCPSTATE                                =	156;
    OPTION_DATASOURCE                               =	157;      
    OPTION_V4_PCP_SERVER                            = 158; 
    OPTION_V4_PORTPARAMS                            = 159;    
    OPTION_MUD_URL_V4                               = 161;
    OPTION_OPTION_V4_DNR                            = 162;
    OPTION_PXELINUX_MAGIC                           = 208;
    OPTION_CONFIGURATION_FILE                       = 209;
    OPTION_PATH_PREFIX                              = 210;
    OPTION_REBOOT_TIME                              = 211;    
    OPTION_6RD                                      = 212; 
    OPTION_OPTION_V4_ACCESS_DOMAIN                  = 213;
    OPTION_SUBNET_ALLOCATION_OPTION                 =	220;
    OPTION_END                                      = 255;

    class function OptionToString(const aOption: UInt8;AddOptionNumber:Boolean=True): String;
    class function OptionToStringInternal(const aOption: UInt8): String;
    class function OptionValueToCaption(const aOption: UInt8): String; 
    class function GetNetBIOSNodeTypeString(const aNodeType: UInt8): string; 
    class function GetOptionOverloadTypeString(const aOverloadType: UInt8): string; 
    class function GetDHCPMessageTypeString(const aMessageType: UInt8): string; 
    class function GetNetWareSubOptionString(const asubOption: UInt8): string; 
    class function GetDHCPSubOptionDescription(const asubOptionCode: UInt8): string; 
    class function DHCPStatusCodeToStr(const aCode: UInt8): string; 
    class function DecimalToDHCPState(const aValue: UInt8): string; 
    class function DecimalToAuthenticationSuboption(avalue: Integer): string; 
    class function DecToDhcpOptionStr(Const avalue: UInt8): string; 
    class function GetLabelOptions(const aOptions:UInt8): String;
    class function DhcpOptionToString(const aValue: UInt8): String;
  protected
  public
    /// <summary>
    /// Returns the default DHCP port (110).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the DHCP protocol.
    /// </summary>
    class function IDDetectProto: UInt8; override;
    /// <summary>
    /// Returns the name of the DHCP protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the POP3 protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function HeaderLength(aFlag:byte): word; override;
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalInfo: PTAdditionalInfo): Boolean; override;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: UInt8): Boolean; override;        
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolDHCP }



class function TWPcapProtocolDHCP.DefaultPort: Word;
begin
  Result := PROTO_DHCP_PORT_S;
end;

class function TWPcapProtocolDHCP.IDDetectProto: UInt8;
begin
  Result := DETECT_PROTO_DHCP;
end;

class function TWPcapProtocolDHCP.ProtoName: String;
begin
  Result := 'Dynamic Host Configuration Protocol';
end;

class function TWPcapProtocolDHCP.IsValid(const aPacket: PByte;
  aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: UInt8): Boolean;
var LUDPPPtr: PUDPHdr;
begin
  Result := False;
  if not HeaderUDP(aPacket,aPacketSize,LUDPPPtr) then exit;   
  if not PayLoadLengthIsValid(LUDPPPtr) then  Exit;
  Result  := inherited IsValid(aPacket,aPacketSize,aAcronymName,aIdProtoDetected);  

  if not Result then
    Result := IsValidByPort(PROTO_DHCP_PORT_C,DstPort(LUDPPPtr),SrcPort(LUDPPPtr),aAcronymName,aIdProtoDetected)     
end;

class function TWPcapProtocolDHCP.AcronymName: String;
begin
  Result := 'DHCP';
end;


class function TWPcapProtocolDHCP.GetLabelOptions(const aOptions:UInt8):String;
begin
  Result := Format('%s.Options.%s',[AcronymName,OptionToString(aOptions).Replace(' ','')]);
end;


class function TWPcapProtocolDHCP.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalInfo: PTAdditionalInfo): Boolean;
var LUDPPayLoad         : PByte;
    LDummy              : Integer;
    LHeaderDHCP         : PTDHCPHeader;
    LBytesTmp           : TidBytes;
    LCurrentPos         : Integer;
    LPayLoadLen         : Integer;
    LOption             : UInt8;
    LLen                : UInt8;
    LByteValue          : UInt8;
    I                   : Integer;
    LPosDummy           : Integer;
    LDHCPAuthentication : PTDHCPAuthentication;
    LTmpIP              : String;
    LEnrichment         : TWcapEnrichmentType;    
begin
  Result        := False;
  FIsFilterMode := aisFilterMode;
  LUDPPayLoad   := inherited GetPayLoad(aPacketData,aPacketSize,LPayLoadLen,LDummy);  

  if not Assigned(LUDPPayLoad) then
  begin
    FisMalformed := true;
    Exit;
  end;
  
  AListDetail.Add(AddHeaderInfo(aStartLevel,AcronymName, Format('%s (%s)', [ProtoName, AcronymName]), null, LUDPPayLoad,LPayLoadLen));

  LHeaderDHCP := PTDHCPHeader(LUDPPayLoad);

 {  op 1  Message op code / message type.
       1 = BOOTREQUEST, 2 = BOOTREPLY}  
  AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.MessageType',[AcronymName]), 'Message type:', ifthen(LHeaderDHCP.OpCode=1,'Boot request','Boot reply'), @LHeaderDHCP.OpCode,SizeOf(LHeaderDHCP.OpCode),LHeaderDHCP.OpCode));

 {  htype  1  Hardware address type, see ARP section in "Assigned
              Numbers" RFC; e.g., '1' = 10mb ethernet.  }   
  AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.HWType',[AcronymName]), 'Hardware type:', LHeaderDHCP.HType, @LHeaderDHCP.HType,SizeOf(LHeaderDHCP.HType)));
  
 {  hlen   1  Hardware address length (e.g.  '6' for 10mb
              ethernet).}
  AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.HWAddressLen',[AcronymName]), 'Hardware address length:', LHeaderDHCP.HLen, @LHeaderDHCP.HLen,SizeOf(LHeaderDHCP.HLen)));  

 {  hops   1  Client sets to zero, optionally used by relay agents
              when booting via a relay agent.}
  AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.Hops',[AcronymName]), 'Hops:', LHeaderDHCP.Hops, @LHeaderDHCP.Hops,SizeOf(LHeaderDHCP.Hops)));    

 {  xid    4  Transaction ID, a random number chosen by the
              client, used by the client and server to associate
              messages and responses between a client and a
              server.}
  AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.TransactionID',[AcronymName]), 'Transaction ID:', LongWordToString(LHeaderDHCP.TransactionID), @LHeaderDHCP.TransactionID,SizeOf(LHeaderDHCP.TransactionID),LHeaderDHCP.TransactionID));    

  { secs   2  Filled in by client, seconds elapsed since client
              began address acquisition or renewal process. }
  AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.sElapsed',[AcronymName]), 'Seconds Elapsed:', wpcapntohs(LHeaderDHCP.SecondsElapsed), @LHeaderDHCP.SecondsElapsed,SizeOf(LHeaderDHCP.SecondsElapsed)));      

  { flags   2  Flags (see figure 2).}
  AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.Bootpflags',[AcronymName]), 'Bootp flags:', ByteToBinaryString( LHeaderDHCP.Flags), @LHeaderDHCP.Flags,SizeOf(LHeaderDHCP.Flags),LHeaderDHCP.Flags));        

  {
                                    1 1 1 1 1 1
                0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |B|             MBZ             |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                B:  BROADCAST flag

                MBZ:  MUST BE ZERO (reserved for future use)
  }
  AListDetail.Add(AddHeaderInfo(aStartLevel+2,Format('%s.Bootpflags.Broadcast',[AcronymName]), 'Broadcast:', GetBitValue( LHeaderDHCP.Flags,1), @LHeaderDHCP.Flags,SizeOf(LHeaderDHCP.Flags)));    

  { ciaddr  4  Client IP address; only filled in if client is in
               BOUND, RENEW or REBINDING state and can respond
               to ARP requests.}  
  AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.ClientIP',[AcronymName]), 'Client IP address:', MakeUint32IntoIPv4AddressInternal(wpcapntohl( LHeaderDHCP.ClientIP)), @LHeaderDHCP.ClientIP,SizeOf(LHeaderDHCP.ClientIP)));          

  { yiaddr  4  'your' (client) IP address.}
  AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.YourUP',[AcronymName]), 'Your (client) IP address:', MakeUint32IntoIPv4AddressInternal(wpcapntohl(LHeaderDHCP.YourIP)), @LHeaderDHCP.YourIP,SizeOf(LHeaderDHCP.YourIP)));          

  { siaddr  4  IP address of next server to use in bootstrap;
               returned in DHCPOFFER, DHCPACK by server.      }
  AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.ServerIP',[AcronymName]), 'Next server IP address:', MakeUint32IntoIPv4AddressInternal(wpcapntohl(LHeaderDHCP.ServerIP)), @LHeaderDHCP.ServerIP,SizeOf(LHeaderDHCP.ServerIP)));            

 { giaddr   4  Relay agent IP address, used in booting via a
               relay agent.}
  AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.RelayAgentIP',[AcronymName]), 'Relay Agent IP address:', MakeUint32IntoIPv4AddressInternal(wpcapntohl(LHeaderDHCP.RelayAgentIP)), @LHeaderDHCP.RelayAgentIP,SizeOf(LHeaderDHCP.RelayAgentIP)));          

  {chaddr   16  Client hardware address.  }
  SetLength(LBytesTmp,LHeaderDHCP.HLen);
  Move(LHeaderDHCP.ClientMAC[0], LBytesTmp[0], LHeaderDHCP.HLen);   

  AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.ClientMAC',[AcronymName]), 'Client MAC address:', MACAddressToString(LBytesTmp), @LBytesTmp,SizeOf(LBytesTmp)));          
  
  SetLength(LBytesTmp,SizeOf(LHeaderDHCP.ClientMAC)- LHeaderDHCP.HLen);
  Move(LHeaderDHCP.ClientMAC[LHeaderDHCP.HLen], LBytesTmp[0], SizeOf(LHeaderDHCP.ClientMAC)- LHeaderDHCP.HLen);   
  AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.ClientMAC.Padding',[AcronymName]), 'Client MAC address paddings:', MACAddressToString(LBytesTmp), @LBytesTmp,SizeOf(LBytesTmp)));   

  { sname   64  Optional server host name, null terminated string.  }
  SetLength(LBytesTmp, SizeOf(LHeaderDHCP.ServerName));
  Move(LHeaderDHCP.ServerName[0], LBytesTmp[0], SizeOf(LHeaderDHCP.ServerName));  
  AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.ServerName',[AcronymName]), 'Server name:', BytesToStringRaw(LBytesTmp), @LBytesTmp,SizeOf(LBytesTmp)));

 {  file    128  Boot file name, null terminated string; "generic"
                 name or null in DHCPDISCOVER, fully qualified
                 directory-path name in DHCPOFFER.  }
  SetLength(LBytesTmp, SizeOf(LHeaderDHCP.BootFileName));
  Move(LHeaderDHCP.BootFileName[0], LBytesTmp[0], SizeOf(LHeaderDHCP.BootFileName));  
  AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.BootFileName',[AcronymName]), 'Boot FileName:', BytesToStringRaw(LBytesTmp), @LBytesTmp,SizeOf(LBytesTmp)));      
    
  
  AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.MagicCookie',[AcronymName]), 'Magic Cookie:', wpcapntohl(LHeaderDHCP.MagicCookie), @LHeaderDHCP.MagicCookie,SizeOf(LHeaderDHCP.MagicCookie)));
  LCurrentPos := HeaderLength(0);

  while LCurrentPos < LPayLoadLen do
  begin

    LOption := ParserUint8Value(LUDPPayLoad, aStartLevel+1,LPayLoadLen,Format('%s.Options',[AcronymName]), 'Options',AListDetail, OptionToStringInternal, True, LCurrentPos);

    if LOption = OPTION_PAD then Continue;      
    
    if ( LOption <> OPTION_END) then
    begin
  
      LLen := ParserUint8Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen, Format('%s.Len',[GetLabelOptions(LOption)]), 'Length',AListDetail, nil, False, LCurrentPos);
                      {90,82 KO}
      case LOption of
        {IPv4}

        OPTION_SUB_ROUTER,
        OPTION_NAME_ADDR,
        OPTION_DOMAIN_ADDR,
        OPTION_LOG_ADDR,
        OPTION_QUOTE_ADDR,
        OPTION_LPR_ADDR,
        OPTION_IMPRESS_ADDR,
        OPTION_DHCP_SERVER_ID,
        OPTION_RPL_ADDR,
        OPTION_ADDR_REQUEST,
        OPTION_ROUTER_REQUEST,
        OPTION_OPTION_V4_DOTS_ADDR,
        OPTION_BROADCAST_ADDR,
        OPTION_6RD,
        OPTION_SUB_NETMASK :
          begin
            for I := 0 to (LLen div 4 ) -1 do
              ParserUint32Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen, Format('%s.%s',[GetLabelOptions(LOption),OptionValueToCaption(LOption).Replace(' ','')]), Format('%s:',[OptionValueToCaption(LOption)]),
                              AListDetail, MakeUint32IntoIPv4AddressInternal, True, LCurrentPos);
          end;

        {String}  
        OPTION_MERIT_DUMP_FILE,
        OPTION_DOMAIN_NAME,
        OPTION_ROOT_PATH,
        OPTION_EXT_FILE,
        OPTION_ROOT_FILER,
        OPTION_SWAP_SERVER,
        OPTION_MTU_PLATEAU,
        OPTION_STATIC_ROUTE,
        OPTION_NIS_SERVERS,
        OPTION_NIS_DOMAIN,
        OPTION_NTP_SERVERS,
        OPTION_VENDOR_SPECIFIC,
        OPTION_NETBIOS_NAME_SRV,
        OPTION_NETBIOS_DIST_SRV,
        OPTION_NETBIOS_SCOPE,
        OPTION_X_WINDOW_FONT,
        OPTION_X_WINDOW_MANAGER,
        OPTION_DHCP_MESSAGE,
        OPTION_CLASS_ID,
        OPTION_NETWARE_IP_DOMAIN,
        OPTION_NISDOMAINNAME,
        OPTION_NISSERVERADDR,
        OPTION_SERVERNAME,
        OPTION_BOOTFILENAME,
        OPTION_HOMEAGENTADDRS,
        OPTION_SMTPSERVER,
        OPTION_POP3SERVER,
        OPTION_NNTPSERVER,
        OPTION_WWWSERVER,
        OPTION_FINGERSERVER,
        OPTION_IRCSERVER,
        OPTION_STREETTALKSERVER,
        OPTION_STDASERVER,
        OPTION_USERCLASS,
        OPTION_DIRECTORY_AGENT,
        OPTION_SERVICE_SCOPE,
        OPTION_CLIENT_FQDN,
        OPTION_ISNS,
        OPTION_NDS_SERVERS,
        OPTION_NDS_TREE_NAME,
        OPTION_NDS_CONTEXT,
        OPTION_CLIENT_SYSTEM,
        OPTION_CLIENT_NDI,
        OPTION_LDAP,
        OPTION_UUID_GUID,
        OPTION_USERAUTH,
        OPTION_PCODE,
        OPTION_TCODE,
        OPTION_NETINFO_ADDRESS,
        OPTION_NETINFO_TAG,
        OPTION_DHCP_CAPTIVEPORTAL,
        OPTION_AUTOCONFIG,
        OPTION_NAME_SERVICE_SEARCH,
        OPTION_DOMAIN_SEARCH,
        OPTION_CLASSLESS_STATIC_ROUTE_OPTION,
        OPTION_OPTION_CAPWAP_AC_V4,
        OPTION_OPTIONIPV4_ADDRESSMOS,
        OPTION_OPTIONIPV4_FQDNMOS,
        OPTION_SIP_UA_CONFIGURATION_SERVICE_DOMAINS,
        OPTION_OPTIONIPV4_ADDRESSANDSF,
        OPTION_OPTION_V4_SZTP_REDIRECT,
        OPTION_RDNSS_SELECTION,
        OPTION_OPTION_V4_DOTS_RI,
        OPTION_OPTION_V4_DNR,
        OPTION_MUD_URL_V4,
        OPTION_CONFIGURATION_FILE,
        OPTION_PATH_PREFIX,
        OPTION_OPTION_V4_ACCESS_DOMAIN,
        OPTION_SUBNET_ALLOCATION_OPTION,        
        OPTION_HOSTNAME:
            ParserGenericBytesValue(LUDPPayLoad,aStartLevel+2,LPayLoadLen,LLen,Format('%s.%s',[GetLabelOptions(LOption),OptionValueToCaption(LOption).Replace(' ','')]), Format('%s:',[OptionValueToCaption(LOption)]),AListDetail,BytesToStringRawInternal,True,LCurrentPos);   

        OPTION_CLIENT_ID:
          begin 
            LByteValue :=  ParserUint8Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen,  Format('%s.HwType',[GetLabelOptions(LOption)]), 'Hardaware type:',AListDetail, nil, True, LCurrentPos);
            
            if isValidLen(LCurrentPos,LPayLoadLen,LLen-1) then
            begin
              SetLength(LBytesTmp, LLen-1);
              Move((LUDPPayLoad + LCurrentPos)^, LBytesTmp[0],LLen-1);
              if LByteValue = 1 then
                AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.ClientID',[GetLabelOptions(LOption)]), 'ClientID:' , MACAddressToString(LBytesTmp), @LBytesTmp,SizeOf(LBytesTmp) ))
              else
                AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.ClientID',[GetLabelOptions(LOption)]), 'ClientID:' , BytesToStringRaw(LBytesTmp), @LBytesTmp,SizeOf(LBytesTmp) ));                              
              inc(LCurrentPos,LLen-1);
            end;
          end;

        OPTION_SIP_SERVERS_DHCP_OPTION:
          begin 
            LByteValue :=  ParserUint8Value(LUDPPayLoad, aStartLevel+2,LLen, Format('%s.Encoding',[GetLabelOptions(LOption)]) ,'Encoding:',AListDetail, DhcpOptionToString, True, LCurrentPos);
            if isValidLen(LCurrentPos,LPayLoadLen,LLen-1) then
            begin
              SetLength(LBytesTmp, LLen-1);
              Move((LUDPPayLoad + LCurrentPos)^, LBytesTmp[0],LLen-1);
              LEnrichment := wetNone;
              if LByteValue = 1 then            
              begin
                LTmpIP := BytesToIPv4Str(LBytesTmp);
                if IsValidPublicIP(LTmpIP) then
                  LEnrichment := WetIP;
                 AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.IP',[GetLabelOptions(LOption)]), Format('%s:',[OptionValueToCaption(LOption)]),LTmpIP, @LBytesTmp,SizeOf(LBytesTmp),-1,LEnrichment ))
              end
              else
              begin
                LTmpIP := IPv6AddressToString(LBytesTmp);
                if IsValidPublicIP(LTmpIP) then
                  LEnrichment := WetIP;
                 AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.IP',[GetLabelOptions(LOption)]), Format('%s:',[OptionValueToCaption(LOption)]), LtmpIP, @LBytesTmp,SizeOf(LBytesTmp),-1,LEnrichment ));                              
              end;
              inc(LCurrentPos,LLen-1);            
            end;
          end;
            
        {Booolean}
        OPTION_FORWARD_ON_OFF,
        OPTION_DEFAULT_IP_TTL,
        OPTION_MTU_SUBNET,
        OPTION_MASK_DISCOVERY,
        OPTION_MASK_SUPPLIER,
        OPTION_ROUTER_DISCOVERY,
        OPTION_TRAILERS,
        OPTION_ETHERNET,
        OPTION_DEFAULT_TCP_TTL,
        OPTION_KEEPALIVE_DATA,        
        OPTION_SRCRTE_ON_OFF:
            ParserUint8Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen,Format('%s.%s',[GetLabelOptions(LOption),OptionValueToCaption(LOption).Replace(' ','')]), Format('%s:',[OptionValueToCaption(LOption)]),AListDetail, ByteToBooleanStr, True, LCurrentPos);

        {Enumerate} 
        OPTION_NETBIOS_NODE_TYPE         :
            ParserUint8Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen,Format('%s.%s',[GetLabelOptions(LOption),OptionValueToCaption(LOption).Replace(' ','')]), Format('%s:',[OptionValueToCaption(LOption)]),AListDetail, GetNetBIOSNodeTypeString, True, LCurrentPos);
          
        OPTION_OVERLOAD                  :
            ParserUint8Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen,Format('%s.%s',[GetLabelOptions(LOption),OptionValueToCaption(LOption).Replace(' ','')]), Format('%s:',[OptionValueToCaption(LOption)]),AListDetail, GetOptionOverloadTypeString, True, LCurrentPos);
          
        OPTION_DHCP_MSG_TYPE             :
            ParserUint8Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen,Format('%s.%s',[GetLabelOptions(LOption),OptionValueToCaption(LOption).Replace(' ','')]), Format('%s:',[OptionValueToCaption(LOption)]),AListDetail, GetDHCPMessageTypeString, True, LCurrentPos);
          
        OPTION_DATASOURCE, 
        OPTION_FORCERENEW_NONCE_CAPABLE  :
            ParserUint8Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen,Format('%s.%s',[GetLabelOptions(LOption),OptionValueToCaption(LOption).Replace(' ','')]), Format('%s:',[OptionValueToCaption(LOption)]),AListDetail, nil, True, LCurrentPos);
          
        OPTION_DHCPSTATE                 :
            ParserUint8Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen,Format('%s.%s',[GetLabelOptions(LOption),OptionValueToCaption(LOption).Replace(' ','')]), Format('%s:',[OptionValueToCaption(LOption)]),AListDetail, DecimalToDHCPState, True, LCurrentPos);

        OPTION_NETWARE_IP_OPTION:
          begin
            for I := 0 to (LLen ) -1 do
              ParserUint8Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen,Format('%s.%s',[GetLabelOptions(LOption),OptionValueToCaption(LOption).Replace(' ','')]), Format('%s:',[OptionValueToCaption(LOption)]),AListDetail, GetNetWareSubOptionString, True, LCurrentPos);
          end;

        OPTION_PARAMETER_LIST:
          begin
            for I := 0 to (LLen ) -1 do
              ParserUint8Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen,Format('%s.%s',[GetLabelOptions(LOption),OptionValueToCaption(LOption).Replace(' ','')]), Format('%s:',[OptionValueToCaption(LOption)]),AListDetail, OptionToStringInternal, True, LCurrentPos);
          end;
          
        OPTION_CCC:
          begin            
            for I := 0 to (LLen ) -1 do
              ParserUint8Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen,Format('%s.%s',[GetLabelOptions(LOption),OptionValueToCaption(LOption).Replace(' ','')]), Format('%s:',[OptionValueToCaption(LOption)]),AListDetail, GetDHCPSubOptionDescription, True, LCurrentPos);
          end;

        OPTION_STATUS_CODE:
          begin
            for I := 0 to (LLen ) -1 do
              ParserUint8Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen,Format('%s.%s',[GetLabelOptions(LOption),OptionValueToCaption(LOption).Replace(' ','')]), Format('%s:',[OptionValueToCaption(LOption)]),AListDetail, DHCPStatusCodeToStr, True, LCurrentPos);
          end;

        OPTION_AUTHENTICATION:
          begin
            LDHCPAuthentication := PTDHCPAuthentication(LUDPPayLoad + LCurrentPos);
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Protocol',[GetLabelOptions(LOption)]), 'Protocol:', DecimalToAuthenticationSuboption(LDHCPAuthentication.Protocol), @LDHCPAuthentication.Protocol,sizeOf(LDHCPAuthentication.Protocol),LDHCPAuthentication.Protocol));
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Algorithm',[GetLabelOptions(LOption)]), 'Algorithm:',ifthen(LDHCPAuthentication.Algorithm=1,'HMAC-SHA1 keyed hash','Reserved'), @LDHCPAuthentication.Algorithm,sizeOf(LDHCPAuthentication.Algorithm),LDHCPAuthentication.Algorithm));
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.RDM',[GetLabelOptions(LOption)]), 'Replay Detection Method:',ifthen(LDHCPAuthentication.RDM=0,'use of a monotonically increasing counter value','Reserved'), @LDHCPAuthentication.RDM,sizeOf(LDHCPAuthentication.RDM),LDHCPAuthentication.RDM));
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.ReplayDetection',[GetLabelOptions(LOption)]), 'Replay Detection value:', ntohl(LDHCPAuthentication.ReplayDetection), @LDHCPAuthentication.ReplayDetection,sizeOf(LDHCPAuthentication.ReplayDetection)));                                                                 
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.SecretID',[GetLabelOptions(LOption)]), 'Secret ID:', wpcapntohl(LDHCPAuthentication.SecretID), @LDHCPAuthentication.SecretID,sizeOf(LDHCPAuthentication.SecretID)));                 
            LPosDummy := 0;
            ParserGenericBytesValue(@(LDHCPAuthentication.AuthenticationInfo[0]),aStartLevel+2,SizeOf(LDHCPAuthentication.AuthenticationInfo),SizeOf(LDHCPAuthentication.AuthenticationInfo),Format('%s.HMACMD5Hash',[AcronymName]), 'HMAC MD5 Hash:',AListDetail,BytesToHex,True,LPosDummy); 
            inc(LCurrentPos,LLen);
          end;
          
        {Date}
        OPTION_TIME_OFFSET,
        OPTION_MTU_TIMEOUT,
        OPTION_ARP_TIMEOUT,
        OPTION_KEEPALIVE_TIME,
        OPTION_ADDRESS_TIME,
        OPTION_RENEWAL_TIME,
        OPTION_REBINDING_TIME,
        OPTION_IPV6_ONLY_PREFERRED,
        OPTION_SUBNET_SELECTION_OPTION,
        OPTION_BASE_TIME,
        OPTION_START_TIME_OF_STATE,
        OPTION_QUERY_START_TIME,
        OPTION_QUERY_END_TIME,
        OPTION_V4_PORTPARAMS,
        OPTION_REBOOT_TIME:
            ParserUint32Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen,Format('%s.%s',[GetLabelOptions(LOption),OptionValueToCaption(LOption).Replace(' ','')]), Format('%s:',[OptionValueToCaption(LOption)]),AListDetail, nil, True, LCurrentPos);
          
        OPTION_PXELINUX_MAGIC:            {magic string = F1:00:74:7E}
           ParserUint32Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen,Format('%s.%s',[GetLabelOptions(LOption),OptionValueToCaption(LOption).Replace(' ','')]), Format('%s:',[OptionValueToCaption(LOption)]),AListDetail, nil, True, LCurrentPos);

        {Numeric}
        OPTION_BOOT_FILE_SIZE,
        OPTION_MAX_DG_ASSEMBLY,
        OPTION_MTU_INTERFACE,
        OPTION_DHCP_MAX_MSG_SIZE :
            ParserUint16Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen,Format('%s.%s',[GetLabelOptions(LOption),OptionValueToCaption(LOption).Replace(' ','')]), Format('%s:',[OptionValueToCaption(LOption)]),AListDetail, SizeWordToStr, True, LCurrentPos);                      

        OPTION_V4_PCP_SERVER :
          begin
            {Includes one or multiple lists of PCP server IP addresses; each list is treated as a separate PCP server.  } 
            inc(LCurrentPos,LLen);
          end;

        OPTION_GEOLOC :
          begin 
            DoLog('TWPcapProtocolDHCP.HeaderToString','OPTION_GEOLOC not implemented',TWLLWarning); 
            {  V4

               0                   1                   2                   3
               0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              |   Code 123    |    Length     |   LaRes   |     Latitude      +
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              |                Latitude (cont'd)              |   LoRes   |   +
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              |                             Longitude                         |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              | AType |   AltRes  |                Altitude                   +
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              | Alt.(cont'd)  |    Res  |Datum|
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            }

            { V6
               0                   1                   2                   3
               0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              |       Option Code (63)        |            OptLen             |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              |  LatUnc   |                  Latitude                         +
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              | Lat (cont'd)  |  LongUnc  |               Longitude           +
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              |    Longitude (cont'd)         | AType |   AltUnc  |  Altitude +
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              |               Altitude (cont'd)               |Ver| Res |Datum|
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            }
                      

                      
          
            inc(LCurrentPos,LLen);
          end;

        OPTION_GEOCONF   :
          begin
            DoLog('TWPcapProtocolDHCP.HeaderToString','OPTION_GEOCONF not implemented',TWLLWarning); 
            {   V4
               0                   1                   2                   3
               0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              |   Code 144    |    Length     |   LatUnc  |     Latitude      +
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              |                Latitude (cont'd)              |  LongUnc  |   +
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              |                             Longitude                         |
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              | AType |   AltUnc  |                Altitude                   +
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
              | Alt.(cont'd)  |Ver| Res |Datum|
              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            }
          
            inc(LCurrentPos,LLen);
          end;

        OPTION_RELAY_AGENT_INFORMATION  :
          begin
            ParserUint8Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen, Format('%s.SubOption',[GetLabelOptions(LOption)]), 'SubOption',AListDetail, DecToDhcpOptionStr, True, LCurrentPos);  
            LByteValue := ParserUint8Value(LUDPPayLoad, aStartLevel+2,LPayLoadLen, Format('%s.Len',[GetLabelOptions(LOption)]), 'Length',AListDetail, nil, True, LCurrentPos);
            ParserGenericBytesValue(LUDPPayLoad,aStartLevel+2,LPayLoadLen,LByteValue,Format('%s.Value',[GetLabelOptions(LOption)]), 'Value:',AListDetail,BytesToHex,True,LCurrentPos);                             
          end
                      
      else
        inc(LCurrentPos,LLen);
      end;
      

    end
    else break;
  end;
  Result := True;
end;

Class function TWPcapProtocolDHCP.OptionValueToCaption(const aOption:UInt8):String;
begin
  case aOption of
    OPTION_PAD            : Result := 'Padding';
    OPTION_ROUTER_REQUEST : Result := 'Router Solicitation Address';
    OPTION_SUB_ROUTER     : Result := 'Router Address';
    OPTION_NAME_ADDR      : Result := 'IEN-116 Server Address';
    OPTION_DHCP_MESSAGE   : Result := 'Message';
  else
    Result := OptionToString(aOption,False)
  end;
end;

Class function TWPcapProtocolDHCP.OptionToString(const aOption:UInt8;AddOptionNumber:Boolean=True):String;
begin
  case aOption of
    OPTION_PAD                                     	: Result := 'Pad';
    OPTION_SUB_NETMASK                             	: Result := 'Subnet Mask';
    OPTION_TIME_OFFSET                              : Result := 'Time Offset'; //Time Offset in Seconds from deprecade 100-101
    OPTION_SUB_ROUTER                              	: Result := 'Router';
    4                                              	: Result := 'Time Server';
    OPTION_NAME_ADDR                               	: Result := 'Name Server';
    OPTION_DOMAIN_ADDR                             	: Result := 'Domain Server';
    OPTION_LOG_ADDR                                	: Result := 'Log Server';
    OPTION_QUOTE_ADDR                              	: Result := 'Quotes Server';
    OPTION_LPR_ADDR                                	: Result := 'LPR Server';
    OPTION_IMPRESS_ADDR                            	: Result := 'Impress Server';
    OPTION_RPL_ADDR                                	: Result := 'RLP Server';
    OPTION_HOSTNAME                                	: Result := 'Hostname';
    OPTION_BOOT_FILE_SIZE                          	: Result := 'Boot File Size';
    OPTION_MERIT_DUMP_FILE                         	: Result := 'Merit Dump File';
    OPTION_DOMAIN_NAME                             	: Result := 'Domain Name';
    OPTION_SWAP_SERVER                             	: Result := 'Swap Server';
    OPTION_ROOT_PATH                               	: Result := 'Root Path';
    OPTION_EXT_FILE                                	: Result := 'Extension File';
    OPTION_FORWARD_ON_OFF                           : Result := 'Forward';
    OPTION_SRCRTE_ON_OFF                            : Result := 'SrcRte';
    OPTION_ROOT_FILER                              	: Result := 'Policy Filter';
    OPTION_MAX_DG_ASSEMBLY                         	: Result := 'Max DG Assembly';
    OPTION_DEFAULT_IP_TTL                           : Result := 'Default IP TTL';
    OPTION_MTU_TIMEOUT                             	: Result := 'MTU Timeout';
    OPTION_MTU_PLATEAU                             	: Result := 'MTU Plateau';
    OPTION_MTU_INTERFACE                           	: Result := 'MTU Interface';
    OPTION_MTU_SUBNET                              	: Result := 'MTU Subnet';
    OPTION_BROADCAST_ADDR                          	: Result := 'Broadcast Address';
    OPTION_MASK_DISCOVERY                           : Result := 'Mask Discovery';
    OPTION_MASK_SUPPLIER                            : Result := 'Mask Supplier';
    OPTION_ROUTER_DISCOVERY                         : Result := 'Router Discovery';
    OPTION_ROUTER_REQUEST                          	: Result := 'Router Request';
    OPTION_STATIC_ROUTE                            	: Result := 'Static Route';
    OPTION_TRAILERS                                	: Result := 'Trailers';
    OPTION_ARP_TIMEOUT                              : Result := 'ARP Timeout';
    OPTION_ETHERNET                                 : Result := 'Ethernet';
    OPTION_DEFAULT_TCP_TTL                          : Result := 'Default TCP TTL';
    OPTION_KEEPALIVE_TIME                          	: Result := 'Keepalive Time';
    OPTION_KEEPALIVE_DATA                           : Result := 'Keepalive Data';
    OPTION_NIS_DOMAIN                              	: Result := 'NIS Domain';
    OPTION_NIS_SERVERS                             	: Result := 'NIS Servers';
    OPTION_NTP_SERVERS                             	: Result := 'NTP Servers';
    OPTION_VENDOR_SPECIFIC                         	: Result := 'Vendor Specific';
    OPTION_NETBIOS_NAME_SRV                        	: Result := 'NETBIOS Name Srv';
    OPTION_NETBIOS_DIST_SRV                         : Result := 'NETBIOS Dist Srv';
    OPTION_NETBIOS_NODE_TYPE                       	: Result := 'NETBIOS Node Type';
    OPTION_NETBIOS_SCOPE                           	: Result := 'NETBIOS Scope';
    OPTION_X_WINDOW_FONT                           	: Result := 'X Window Font';
    OPTION_X_WINDOW_MANAGER                        	: Result := 'X Window Manager';
    OPTION_ADDR_REQUEST                            	: Result := 'Address Request';
    OPTION_ADDRESS_TIME                           	: Result := 'Address Time';
    OPTION_OVERLOAD                                 : Result := 'Overload';
    OPTION_DHCP_MSG_TYPE                            : Result := 'DHCP Msg Type';
    OPTION_DHCP_SERVER_ID                          	: Result := 'DHCP Server Id';
    OPTION_PARAMETER_LIST                          	: Result := 'Parameter List';
    OPTION_DHCP_MESSAGE                            	: Result := 'DHCP Message';
    OPTION_DHCP_MAX_MSG_SIZE                       	: Result := 'DHCP Max Msg Size';
    OPTION_RENEWAL_TIME                             : Result := 'Renewal Time';
    OPTION_REBINDING_TIME                          	: Result := 'Rebinding Time';
    OPTION_CLASS_ID                                	: Result := 'Class Id';
    OPTION_CLIENT_ID                               	: Result := 'Client Id';
    OPTION_NETWARE_IP_DOMAIN                        : Result := 'NetWare/IP Domain';
    OPTION_NETWARE_IP_OPTION                       	: Result := 'NetWare/IP Option';
    OPTION_NISDOMAINNAME                            : Result := 'NIS-Domain-Name';
    OPTION_NISSERVERADDR                            : Result := 'NIS-Server-Addr';
    OPTION_SERVERNAME                               : Result := 'Server-Name';
    OPTION_BOOTFILENAME                             : Result := 'Bootfile-Name';
    OPTION_HOMEAGENTADDRS                           : Result := 'Home-Agent-Addrs';
    OPTION_SMTPSERVER                               : Result := 'SMTP-Server';
    OPTION_POP3SERVER                               : Result := 'POP3-Server';
    OPTION_NNTPSERVER                               : Result := 'NNTP-Server';
    OPTION_WWWSERVER                                : Result := 'WWW-Server';
    OPTION_FINGERSERVER                             : Result := 'Finger-Server';
    OPTION_IRCSERVER                                : Result := 'IRC-Server';
    OPTION_STREETTALKSERVER                         : Result := 'StreetTalk-Server';
    OPTION_STDASERVER                               : Result := 'STDA-Server';
    OPTION_USERCLASS                                : Result := 'User-Class';
    OPTION_DIRECTORY_AGENT                          : Result := 'Directory Agent';
    OPTION_SERVICE_SCOPE                            : Result := 'Service Scope';
    80                                              : Result := 'Rapid Commit';
    OPTION_CLIENT_FQDN                              : Result := 'Client FQDN';
    OPTION_RELAY_AGENT_INFORMATION                  : Result := 'Relay Agent Information';
    OPTION_ISNS                                     : Result := 'iSNS';
    84                                             	: Result := 'REMOVED/Unassigned';
    OPTION_NDS_SERVERS                              : Result := 'NDS Servers';
    OPTION_NDS_TREE_NAME                            : Result := 'NDS Tree Name';
    OPTION_NDS_CONTEXT                              : Result := 'NDS Context';
    88                                             	: Result := 'BCMCS Controller Domain Name list';
    89                                             	: Result := 'BCMCS Controller IPv4 address option';
    OPTION_AUTHENTICATION                           : Result := 'Authentication';
    91                                             	: Result := 'client-last-transaction-time option';
    92                                             	: Result := 'associated-ip option';
    OPTION_CLIENT_SYSTEM                           	: Result := 'Client System';
    OPTION_CLIENT_NDI                               : Result := 'Client NDI';
    OPTION_LDAP                                     : Result := 'LDAP';
    96                                             	: Result := 'REMOVED/Unassigned';
    OPTION_UUID_GUID                                : Result := 'UUID/GUID';
    OPTION_USERAUTH                                 : Result := 'User-Auth';
    99                                             	: Result := 'GEOCONF_CIVIC';
    OPTION_PCODE                                    : Result := 'PCode';
    OPTION_TCODE                                    : Result := 'TCode';
    102..107                                       	: Result := 'REMOVED/Unassigned';
    OPTION_IPV6_ONLY_PREFERRED                     	: Result := 'IPv6-Only Preferred';
    OPTION_DHCP4O6_S46_SADDR                      	: Result := 'OPTION_DHCP4O6_S46_SADDR';
    110                                            	: Result := 'REMOVED/Unassigned';
    111                                            	: Result := 'Unassigned';
    OPTION_NETINFO_ADDRESS                          : Result := 'Netinfo Address';
    OPTION_NETINFO_TAG                              : Result := 'Netinfo Tag';
    OPTION_DHCP_CAPTIVEPORTAL                       : Result := 'DHCP Captive-Portal';
    115                                            	: Result := 'REMOVED/Unassigned';
    OPTION_AUTOCONFIG                               : Result := 'Auto-Config';
    OPTION_NAME_SERVICE_SEARCH                      : Result := 'Name Service Search';
    OPTION_SUBNET_SELECTION_OPTION                 	: Result := 'Subnet Selection Option';
    OPTION_DOMAIN_SEARCH                            : Result := 'Domain Search';
    OPTION_SIP_SERVERS_DHCP_OPTION                  : Result := 'SIP Servers DHCP Option';
    OPTION_CLASSLESS_STATIC_ROUTE_OPTION            : Result := 'Classless Static Route Option';
    OPTION_CCC                                      : Result := 'CCC';
    OPTION_GEOCONF                                	: Result := 'Geo conf';
    124                                            	: Result := 'V-I Vendor Class';
    125                                            	: Result := 'V-I Vendor-Specific Information';
    126                                            	: Result := 'Removed/Unassigned';
    127                                            	: Result := 'Removed/Unassigned';
    128                                            	: Result := '"DOCSIS ""full security"" server IP address"';
    129                                            	: Result := 'Call Server IP address';
    130                                            	: Result := '"Discrimination string (toidentify vendor)"';
    131                                            	: Result := 'PXE - undefined (vendor specific)';
    132                                            	: Result := 'PXE - undefined (vendor specific)';
    133                                            	: Result := 'PXE - undefined (vendor specific)';
    134                                            	: Result := 'PXE - undefined (vendor specific)';
    135                                            	: Result := 'PXE - undefined (vendor specific)';
    136                                            	: Result := 'OPTION_PANA_AGENT';
    137                                            	: Result := 'OPTION_V4_LOST';
    OPTION_OPTION_CAPWAP_AC_V4                      : Result := 'OPTION_CAPWAP_AC_V4';
    OPTION_OPTIONIPV4_ADDRESSMOS                    : Result := 'OPTION-IPv4_Address-MoS';
    OPTION_OPTIONIPV4_FQDNMOS                       : Result := 'OPTION-IPv4_FQDN-MoS';
    OPTION_SIP_UA_CONFIGURATION_SERVICE_DOMAINS     : Result := 'SIP UA Configuration Service Domains';
    OPTION_OPTIONIPV4_ADDRESSANDSF                  : Result := 'OPTION-IPv4_Address-ANDSF';
    OPTION_OPTION_V4_SZTP_REDIRECT                  : Result := 'OPTION_V4_SZTP_REDIRECT';
    OPTION_GEOLOC                                   : Result := 'GeoLoc';
    OPTION_FORCERENEW_NONCE_CAPABLE                 : Result := 'FORCERENEW_NONCE_CAPABLE';
    OPTION_RDNSS_SELECTION                          : Result := 'RDNSS Selection';
    OPTION_OPTION_V4_DOTS_RI                        : Result := 'OPTION_V4_DOTS_RI';
    OPTION_OPTION_V4_DOTS_ADDR                     	: Result := 'OPTION_V4_DOTS_ADDRESS';
    149                                            	: Result := 'Unassigned';
    150                                            	: Result := 'TFTP server address';
    OPTION_STATUS_CODE                             	: Result := 'status-code';
    OPTION_BASE_TIME                               	: Result := 'base-time';
    OPTION_START_TIME_OF_STATE                     	: Result := 'start-time-of-state';
    OPTION_QUERY_START_TIME                       	: Result := 'query-start-time';
    OPTION_QUERY_END_TIME                          	: Result := 'query-end-time';
    OPTION_DHCPSTATE                                : Result := 'dhcp-state';
    OPTION_DATASOURCE                               : Result := 'data-source';
    OPTION_V4_PCP_SERVER                           	: Result := 'OPTION_V4_PCP_SERVER';
    OPTION_V4_PORTPARAMS                          	: Result := 'OPTION_V4_PORTPARAMS';
    160                                            	: Result := 'Unassigned';
    OPTION_MUD_URL_V4                              	: Result := 'OPTION_MUD_URL_V4';
    OPTION_OPTION_V4_DNR                           	: Result := 'OPTION_V4_DNR';
    163..174                                       	: Result := 'Unassigned';
    175                                            	: Result := '"Etherboot (Tentatively Assigned - 2005-06-23)"';
    176                                            	: Result := '"IP Telephone (Tentatively Assigned - 2005-06-23)"';
    177                                            	: Result := '"Etherboot (Tentatively Assigned - 2005-06-23)"';  
    178..207	                                      : Result := 'Unassigned';
    OPTION_PXELINUX_MAGIC                          	: Result := 'PXELINUX Magic';
    OPTION_CONFIGURATION_FILE                      	: Result := 'Configuration File';
    OPTION_PATH_PREFIX                             	: Result := 'Path Prefix';
    211                                            	: Result := 'Reboot Time';
    OPTION_6RD                                     	: Result := 'OPTION_6RD';
    OPTION_OPTION_V4_ACCESS_DOMAIN                 	: Result := 'OPTION_V4_ACCESS_DOMAIN';
    214..219	                                      : Result := 'Unassigned';
    OPTION_SUBNET_ALLOCATION_OPTION                 : Result := 'Subnet Allocation Option';
    221	                                            : Result := 'Virtual Subnet Selection (VSS) Option';
    222..223	                                      : Result := 'Unassigned';
    224..254	                                      : Result := 'Reserved (Private Use)';
    OPTION_END                                     	: Result := 'End';    
    else Result := 'Unknown';
  end;
end;

class function TWPcapProtocolDHCP.GetNetBIOSNodeTypeString(const aNodeType: UInt8): string;
begin
  case aNodeType of
    1: Result := 'B-node';
    2: Result := 'P-node';
    4: Result := 'M-node';
    8: Result := 'H-node';
    else Result := 'Unknown';
  end;     
end;

class function TWPcapProtocolDHCP.GetOptionOverloadTypeString(const aOverloadType: UInt8): string;
begin
  case aOverloadType of
    1: Result := 'file';
    2: Result := 'sname';
    3: Result := 'both';
    else Result := 'Unknown';
  end;
end;

class function TWPcapProtocolDHCP.GetDHCPMessageTypeString(const aMessageType: UInt8): string;
begin
  case aMessageType of
    1 : Result := 'DHCPDISCOVER';
    2 : Result := 'DHCPOFFER';
    3 : Result := 'DHCPREQUEST';
    4 : Result := 'DHCPDECLINE';
    5 : Result := 'DHCPACK';
    6 : Result := 'DHCPNAK';
    7 : Result := 'DHCPRELEASE';
    8 : Result := 'DHCPINFORM';
    9 : Result := 'DHCPFORCERENEW';
    10: Result := 'DHCPLEASEQUERY';
    11: Result := 'DHCPLEASEUNASSIGNED';
    12: Result := 'DHCPLEASEUNKNOWN';
    13: Result := 'DHCPLEASEACTIVE';
    14: Result := 'DHCPBULKLEASEQUERY';
    15: Result := 'DHCPLEASEQUERYDONE';
    16: Result := 'DHCPACTIVELEASEQUERY';
    17: Result := 'DHCPLEASEQUERYSTATUS';
    18: Result := 'DHCPTLS';
    else Result := 'Unknown';
  end;
end;

class function TWPcapProtocolDHCP.GetNetWareSubOptionString(const asubOption: UInt8): string;
begin
  case asubOption of
    1 : Result := 'NWIP_DOES_NOT_EXIST';
    2 : Result := 'NWIP_EXIST_IN_OPTIONS_AREA';
    3 : Result := 'NWIP_EXIST_IN_SNAME_FILE';
    4 : Result := 'NWIP_EXIST_BUT_TOO_BIG';
    5 : Result := 'NSQ_BROADCAST';
    6 : Result := 'PREFERRED_DSS';
    7 : Result := 'NEAREST_NWIP_SERVER';
    8 : Result := 'AUTORETRIES';
    9 : Result := 'AUTORETRY_SECS';
    10: Result := 'NWIP_1_1';
    11: Result := 'PRIMARY_DSS';
    else Result := 'Unassigned';
  end;
end;

class function TWPcapProtocolDHCP.GetDHCPSubOptionDescription(const asubOptionCode: UInt8): string;
begin
  case asubOptionCode of
    1: Result := 'TSP''s Primary DHCP Server Address';
    2: Result := 'TSP''s Secondary DHCP Server Address';
    3: Result := 'TSP''s Provisioning Server Address';
    4: Result := 'TSP''s AS-REQ/AS-REP Backoff and Retry';
    5: Result := 'TSP''s AP-REQ/AP-REP Backoff and Retry';
    6: Result := 'TSP''s Kerberos Realm Name';
    7: Result := 'TSP''s Ticket Granting Server Utilization';
    8: Result := 'TSP''s Provisioning Timer Value';
    9: Result := 'TSP''s Security Ticket Control';
    10: Result := 'KDC Server Address';
    else Result := 'Unassigned';
  end;
end;

class function TWPcapProtocolDHCP.DHCPStatusCodeToStr(const aCode: UInt8): string;
begin
  case aCode of
    0: Result := 'Success';
    1: Result := 'UnspecFail';
    2: Result := 'QueryTerminated';
    3: Result := 'MalformedQuery';
    4: Result := 'NotAllowed';
    5: Result := 'DataMissing';
    6: Result := 'ConnectionActive';
    7: Result := 'CatchUpComplete';
    8: Result := 'TLSConnectionRefused';
    else Result := 'Unassigned';
  end;  
end;

class function TWPcapProtocolDHCP.DecimalToDHCPState(const aValue: UInt8): string;
const
  StateNames: array[0..8] of string = (
    'Reserved', 'AVAILABLE', 'ACTIVE', 'EXPIRED', 'RELEASED', 'ABANDONED', 'RESET',
    'REMOTE', 'TRANSITIONING');
var
  StateIndex: Integer;
begin
  if (aValue <= 8) then
    StateIndex := aValue
  else
    StateIndex := 9; // Unassigned value

  Result := StateNames[StateIndex];      
end;

class function TWPcapProtocolDHCP.DecimalToAuthenticationSuboption(avalue: Integer): string;
begin
  case avalue of
    0: Result := 'DHCPv4 Configuration Token';
    1: Result := 'DHCPv4 Delayed Authentication';
    2: Result := 'DHCPv6 Delayed Authentication (Obsolete)';
    3: Result := 'DHCPv6 Reconfigure Key Authentication';
    255: Result := 'Reserved';
    else
      Result := 'Unassigned';
  end;     
end;

class function TWPcapProtocolDHCP.DecToDhcpOptionStr(const avalue: UInt8): string;
begin
  case avalue of
    1: Result := 'Agent Circuit ID Sub-option [RFC3046]';
    2: Result := 'Agent Remote ID Sub-option [RFC3046]';
    3: Result := 'Sub-option 3 is reserved and should not be assigned at this time; proprietary and incompatible usages of this sub-option value have been seen limited deployment. [Ralph_Droms]';
    4: Result := 'DOCSIS Device Class Suboption [RFC3256]';
    5: Result := 'Link selection Sub-option [RFC3527]';
    6: Result := 'Subscriber-ID Suboption [RFC3993]';
    7: Result := 'RADIUS Attributes Sub-option [RFC4014]';
    8: Result := 'Authentication Suboption [RFC4030]';
    9: Result := 'Vendor-Specific Information Suboption [RFC4243]';
    10: Result := 'Relay Agent Flags [RFC5010]';
    11: Result := 'Server Identifier Override Suboption [RFC5107]';
    12: Result := 'Relay Agent Identifier Sub-option [RFC6925]';
    13: Result := 'Access-Technology-Type Sub-option [RFC7839]';
    14: Result := 'Access-Network-Name Sub-option [RFC7839]';
    15: Result := 'Access-Point-Name Sub-option [RFC7839]';
    16: Result := 'Access-Point-BSSID Sub-option [RFC7839]';
    17: Result := 'Operator-Identifier Sub-option [RFC7839]';
    18: Result := 'Operator-Realm Sub-option [RFC7839]';
    19: Result := 'DHCPv4 Relay Source Port Sub-Option [RFC8357]';
    151: Result := 'DHCPv4 Virtual Subnet Selection Sub-Option [RFC6607]';
    152: Result := 'DHCPv4 Virtual Subnet Selection Control Sub-Option [RFC6607]';
  else
      Result := 'Unassigned';
  end;     
end;

class function TWPcapProtocolDHCP.DhcpOptionToString(const aValue:UInt8):String;
begin
  case aValue of
    1 : Result := 'IPv4';
    2 : Result := 'IPv6';
    else Result := 'Unknown';
  end;
end;

class function TWPcapProtocolDHCP.HeaderLength(aFlag: byte): word;
begin
  Result:= SizeOf(TDHCPHeader);
end;

class function TWPcapProtocolDHCP.OptionToStringInternal(const aOption: UInt8): String;
begin
  Result := OptionToString(aOption,True);
end;

end.
                                                 
