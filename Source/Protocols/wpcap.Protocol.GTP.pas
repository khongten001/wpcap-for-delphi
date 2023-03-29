unit wpcap.Protocol.GTP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils, wpcap.StrUtils,
  System.StrUtils, Wpcap.protocol.UDP, WinApi.Windows, wpcap.BufferUtils,
  Variants, idGlobal, wpcap.IPUtils, winsock2,wpcap.MCC,IdGlobalProtocols;

type
  { https://en.wikipedia.org/wiki/GPRS_Tunnelling_Protocol}
   {
    RFC 5516: https://tools.ietf.org/html/rfc5516.
   }

  TGTPHeaderV1 = record
     Flags       : Byte;
     MessageType : Byte;
     MessageLen  : Word;
     TEID        : Cardinal;
  end;
  PTGTPHeaderV1 = ^TGTPHeaderV1;

  TGTPHeaderV2 = record
     Flags       : Byte;
     MessageType : Byte;
     MessageLen  : Word;     
  end;
  PTGTPHeaderV2 = ^TGTPHeaderV2;  

  TGTPHeaderV3 = record
     Flags       : Byte;
  end;
  PTGTPHeaderV3 = ^TGTPHeaderV3;    

  
  /// <summary>
  /// The GTP protocol implementation class.
  /// </summary>
  TWPcapProtocolGTP = Class(TWPcapProtocolBaseUDP)
  private
    CONST

    {Message Type V1}
    GTP_MSG_UNKNOWN             	  	= 0;
    GTP_MSG_ECHO_REQ            	  	= 1;
    GTP_MSG_ECHO_RESP           	  	= 2;
    GTP_MSG_VER_NOT_SUPP        	  	= 3;
    GTP_MSG_NODE_ALIVE_REQ      	  	= 4;
    GTP_MSG_NODE_ALIVE_RESP     	  	= 5;
    GTP_MSG_REDIR_REQ           	  	= 6;
    GTP_MSG_REDIR_RESP          	  	= 7;
    GTP_MSG_CREATE_PDP_REQ           	= 16;
    GTP_MSG_CREATE_PDP_RESP          	= 17;
    GTP_MSG_UPDATE_PDP_REQ           	= 18;
    GTP_MSG_UPDATE_PDP_RESP          	= 19;
    GTP_MSG_DELETE_PDP_REQ           	= 20;
    GTP_MSG_DELETE_PDP_RESP          	= 21;
    GTP_MSG_INIT_PDP_CONTEXT_ACT_REQ 	= 22;
    GTP_MSG_INIT_PDP_CONTEXT_ACT_RESP	= 23;
    GTP_MSG_DELETE_AA_PDP_REQ  		   	= 24;
    GTP_MSG_DELETE_AA_PDP_RESP 		   	= 25;
    GTP_MSG_ERR_IND            		   	= 26;
    GTP_MSG_PDU_NOTIFY_REQ     		   	= 27;
    GTP_MSG_PDU_NOTIFY_RESP    		   	= 28;
    GTP_MSG_PDU_NOTIFY_REJ_REQ 		   	= 29;
    GTP_MSG_PDU_NOTIFY_REJ_RESP		   	= 30;
    GTP_MSG_SUPP_EXT_HDR       		   	= 31;
    GTP_MSG_SEND_ROUT_INFO_REQ 		   	= 32;
    GTP_MSG_SEND_ROUT_INFO_RESP		   	= 33;
    GTP_MSG_FAIL_REP_REQ       		   	= 34;
    GTP_MSG_FAIL_REP_RESP      		   	= 35;
    GTP_MSG_MS_PRESENT_REQ     		   	= 36;
    GTP_MSG_MS_PRESENT_RESP    		   	= 37;
    GTP_MSG_IDENT_REQ          		   	= 48;
    GTP_MSG_IDENT_RESP         		   	= 49;
    GTP_MSG_SGSN_CNTXT_REQ     		   	= 50;
    GTP_MSG_SGSN_CNTXT_RESP    		   	= 51;
    GTP_MSG_SGSN_CNTXT_ACK     		   	= 52;
    GTP_MSG_FORW_RELOC_REQ     		   	= 53;
    GTP_MSG_FORW_RELOC_RESP    		   	= 54;
    GTP_MSG_FORW_RELOC_COMP    		   	= 55;
    GTP_MSG_RELOC_CANCEL_REQ   		   	= 56;
    GTP_MSG_RELOC_CANCEL_RESP  		   	= 57;
    GTP_MSG_FORW_SRNS_CNTXT    		   	= 58;
    GTP_MSG_FORW_RELOC_ACK     		   	= 59;
    GTP_MSG_FORW_SRNS_CNTXT_ACK		   	= 60;
    GTP_MSG_UE_REG_QUERY_REQ   		   	= 61;
    GTP_MSG_UE_REG_QUERY_RESP  		   	= 62;
    GTP_MSG_RAN_INFO_RELAY     		   	= 70;
    GTP_MBMS_NOTIFY_REQ        		   	= 96;
    GTP_MBMS_NOTIFY_RES        		   	= 97;
    GTP_MBMS_NOTIFY_REJ_REQ    		   	= 98;
    GTP_MBMS_NOTIFY_REJ_RES    		   	= 99;
    GTP_CREATE_MBMS_CNTXT_REQ  		   	= 100;
    GTP_CREATE_MBMS_CNTXT_RES  		   	= 101;
    GTP_UPD_MBMS_CNTXT_REQ     		   	= 102;
    GTP_UPD_MBMS_CNTXT_RES     		   	= 103;
    GTP_DEL_MBMS_CNTXT_REQ     		   	= 104;
    GTP_DEL_MBMS_CNTXT_RES     		   	= 105;
    GTP_MBMS_REG_REQ           		   	= 112;
    GTP_MBMS_REG_RES           		   	= 113;
    GTP_MBMS_DE_REG_REQ        		   	= 114;
    GTP_MBMS_DE_REG_RES        		   	= 115;
    GTP_MBMS_SES_START_REQ     		   	= 116;
    GTP_MBMS_SES_START_RES     		   	= 117;
    GTP_MBMS_SES_STOP_REQ      		   	= 118;
    GTP_MBMS_SES_STOP_RES      		   	= 119;
    GTP_MBMS_SES_UPD_REQ       		   	= 120;
    GTP_MBMS_SES_UPD_RES       		   	= 121;
    GTP_MS_INFO_CNG_NOT_REQ    		   	= 128;
    GTP_MS_INFO_CNG_NOT_RES    		   	= 129;
    GTP_MSG_DATA_TRANSF_REQ    		   	= 160;
    GTP_MSG_DATA_TRANSF_RESP   		   	= 161;
    GTP_MSG_END_MARKER         		   	= 254;
    GTP_MSG_TPDU               		   	= 255;


    {IE Type costanti}
    GTP_IEI_IMSI                                 = 1;
    GTP_IEI_CAUSE                                = 2;
    GTP_IEI_RECOVERY_RESTART                     = 3;   
    //* 4-34 Reserved for S101 interface Extendable / See 3GPP TS 29.276 [14] */
    //* 35-50  / See 3GPP TS 29.276 */
    {TODO} 
    //* 63-70 For future Sv interface use */     
    GTP_IEI_APN                                  = 71; 
    GTP_IEI_AMBR                                 = 72; 
    GTP_EPS_BEARER_ID                            = 73;
    GTP_IEI_MEI                                  = 75;
    GTP_IEI_MSISDN                               = 76;
    GTP_IEI_INDICATION                           = 77;
    GTP_IEI_PCO                                  = 78;
    GTP_IEI_PAA                                  = 79;
    GTP_IEI_BEARER_LEVEL_QoS                     = 80;
    GTP_IEI_RAT_TYPE                             = 82;
    GTP_IEI_SERVING_NETWORK                      = 83;
    GTP_IEI_F_TFT                                = 84;
    GTP_IEI_ULI                                  = 86;
    GTP_IEI_F_TEID                               = 87; 
    GTP_IEI_TFT                                  = 89;
    GTP_IEI_SDF_FILTER                           = 91;
    GTP_IEI_DELAY_VALUE                          = 92;
    GTP_IEI_BEARER_CONTEXT                       = 93;
    GTP_IEI_CHARGING_ID                          = 94;
    GTP_IEI_IPV6_ADDRESS                         = 95;
    GTP_IEI_PDN_TYPE                             = 99;  
    GTP_IEI_UE_TIME_ZONE                         = 114;
    GTP_IEI_UDP_PORT                             = 126;    
    GTP_IEI_APN_RESTICTION                       = 127;
    GTP_IEI_SELECTION_MODE                       = 128;  
    GTP_IEI_SGW_ADDRESS                          = 133;
    GTP_IEI_FQDN                                 = 136;
    GTP_IEI_ECGI                                 = 140;    
    GTP_IEI_PRIVATE                              = 255;

    (*   GTPv2  IE Type TODO
/*Start SRVCC Messages ETSI TS 129 280 V10.1.0 (2011-06) 6.1*/
    { 51, "STN-SR"},                                                            /* Variable Length / 6.2 */
    { 52, "Source to Target Transparent Container"},                            /* Variable Length / 6.3 */
    { 53, "Target to Source Transparent Container"},                            /* Variable Length / 6.4 */
    { 54, "MM Context for E-UTRAN SRVCC"},                                      /* Variable Length / 6.5 */
    { 55, "MM Context for UTRAN SRVCC"},                                        /* Variable Length / 6.6 */
    { 56, "SRVCC Cause"},                                                       /* Fixed Length / 6.7 */  //CauseToString_vals
    { 57, "Target RNC ID"},                                                     /* Variable Length / 6.8 */
    { 58, "Target Global Cell ID"},                                             /* Variable Length / 6.9 */
    { 59, "TEID-C"},                                                            /* Extendable / 6.10 */
    { 60, "Sv Flags" },                                                         /* Extendable / 6.11 */
    { 61, "Service Area Identifier" },                                          /* Extendable / 6.12 */
    { 62, "MM Context for CS to PS SRVCC" },                                    /* Extendable / 6.13 */
    { 74, "IP Address"},                                                        /* Extendable / 8.9 */
    { 81, "Flow Quality of Service (Flow QoS)"},                                /* Extendable / 8.16 */
    { 85, "Traffic Aggregation Description (TAD)"},                             /* Variable Length / 8.20 */
    { 88, "TMSI"},                                                              /* Variable Length / 8.23 */
    { 90, "S103 PDN Data Forwarding Info (S103PDF)"},                           /* Variable Length / 8.25 */
    { 96, "Trace Information"},                                                 /* Extendable / 8.31 */
    { 97, "Bearer Flags"},                                                      /* Extendable / 8.32 */
    { 98, "Paging Cause"},                                                      /* Variable Length / 8.33 */
    {100, "Procedure Transaction ID"},                                          /* Extendable / 8.35 */
    {101, "DRX Parameter"},                                                     /* Variable Length/ 8.36 */
    {102, "UE Network Capability"},                                             /* Variable Length / 8.37 */
    {103, "MM Context (GSM Key and Triplets)"},                                 /* Variable Length / 8.38 */
    {104, "MM Context (UMTS Key, Used Cipher and Quintuplets)"},                /* Variable Length / 8.38 */
    {105, "MM Context (GSM Key, Used Cipher and Quintuplets)"},                 /* Variable Length / 8.38 */
    {106, "MM Context (UMTS Key and Quintuplets)"},                             /* Variable Length / 8.38 */
    {107, "MM Context (EPS Security Context, Quadruplets and Quintuplets)"},    /* Variable Length / 8.38 */
    {108, "MM Context (UMTS Key, Quadruplets and Quintuplets)"},                /* Variable Length / 8.38 */
    {109, "PDN Connection"},                                                    /* Extendable / 8.39 */
    {110, "PDU Numbers"},                                                       /* Extendable / 8.40 */
    {111, "P-TMSI"},                                                            /* Variable Length / 8.41 */
    {112, "P-TMSI Signature"},                                                  /* Variable Length / 8.42 */
    {113, "Hop Counter"},                                                       /* Extendable / 8.43 */
    {115, "Trace Reference"},                                                   /* Fixed Length / 8.45 */
    {116, "Complete Request Message"},                                          /* Variable Length / 8.46 */
    {117, "GUTI"},                                                              /* Variable Length / 8.47 */
    {118, "F-Container"},                                                       /* Variable Length / 8.48 */
    {119, "F-Cause"},                                                           /* Variable Length / 8.49 */
    {120, "Selected PLMN ID"},                                                  /* Variable Length / 8.50 */
    {121, "Target Identification"},                                             /* Variable Length / 8.51 */
    {122, "NSAPI"},                                                             /* Extendable / 8.52 */
    {123, "Packet Flow ID"},                                                    /* Variable Length / 8.53 */
    {124, "RAB Context"},                                                       /* Fixed Length / 8.54 */
    {125, "Source RNC PDCP Context Info"},                                      /* Variable Length / 8.55 */
    {129, "Source Identification"},                                             /* Variable Length / 8.50 */
    {130, "Bearer Control Mode"},                                               /* Extendable / 8.60 */
    {131, "Change Reporting Action"},                                           /* Variable Length / 8.61 */
    {132, "Fully Qualified PDN Connection Set Identifier (FQ-CSID)"},           /* Variable Length / 8.62 */
    {134, "eMLPP Priority"},                                                    /* Extendable / 8.64 */
    {135, "Node Type"},                                                         /* Extendable / 8.65 */
    {137, "Transaction Identifier (TI)"},                                       /* Variable Length / 8.68 */
    {138, "MBMS Session Duration"},                                             /* Duration Extendable / 8.69 */
    {139, "MBMS Service Area"},                                                 /* Extendable / 8.70 */
    {141, "MBMS Flow Identifier"},                                              /* Extendable / 8.72 */
    {142, "MBMS IP Multicast Distribution"},                                    /* Extendable / 8.73 */
    {143, "MBMS Distribution Acknowledge"},                                     /* Extendable / 8.74 */
    {144, "RFSP Index"},                                                        /* Fixed Length / 8.77 */
    {145, "User CSG Information (UCI)"},                                        /* Extendable / 8.75 */
    {146, "CSG Information Reporting Action"},                                  /* Extendable / 8.76 */
    {147, "CSG ID"},                                                            /* Extendable / 8.78 */
    {148, "CSG Membership Indication (CMI)"},                                   /* Extendable / 8.79 */
    {149, "Service indicator"},                                                 /* Fixed Length / 8.80 */
    {150, "Detach Type"},                                                       /* Fixed Length / 8.81 */
    {151, "Local Distinguished Name (LDN)"},                                    /* Variable Length / 8.82 */
    {152, "Node Features"},                                                     /* Extendable / 8.83 */
    {153, "MBMS Time to Data Transfer"},                                        /* Extendable / 8.84 */
    {154, "Throttling"},                                                        /* Extendable / 8.85 */
    {155, "Allocation/Retention Priority (ARP)"},                               /* Extendable / 8.86 */
    {156, "EPC Timer"},                                                         /* Extendable / 8.87 */
    {157, "Signalling Priority Indication"},                                    /* Extendable / 8.88 */
    {158, "Temporary Mobile Group Identity"},                                   /* Extendable / 8.89 */
    {159, "Additional MM context for SRVCC"},                                   /* Extendable / 8.90 */
    {160, "Additional flags for SRVCC"},                                        /* Extendable / 8.91 */
    {161, "Max MBR/APN-AMBR (MMBR)"},                                           /* Extendable / 8.92 */
    {162, "MDT Configuration"},                                                 /* Extendable / 8.93 */
    {163, "Additional Protocol Configuration Options (APCO)"},                  /* Extendable / 8.94 */
    {164, "Absolute Time of MBMS Data Transfer"},                               /* Extendable / 8.95 */
    {165, "H(e)NB Information Reporting"},                                      /* Extendable / 8.96*/
    {166, "IPv4 Configuration Parameters (IP4CP)"},                             /* Extendable / 8.97*/
    {167, "Change to Report Flags"},                                            /* Extendable / 8.98 */
    {168, "Action Indication"},                                                 /* Extendable / 8.99 */
    {169, "TWAN Identifier "},                                                  /* Extendable / 8.100 */
    {170, "ULI Timestamp"},                                                     /* Extendable / 8.101 */
    {171, "MBMS Flags"},                                                        /* Extendable / 8.102 */
    {172, "RAN/NAS Cause"},                                                     /* Extendable / 8.103 */
    {173, "CN Operator Selection Entity"},                                      /* Extendable / 8.104 */
    {174, "Trusted WLAN Mode Indication"},                                      /* Extendable / 8.105 */
    {175, "Node Number"},                                                       /* Extendable / 8.106 */
    {176, "Node Identifier"},                                                   /* Extendable / 8.107 */
    {177, "Presence Reporting Area Action"},                                    /* Extendable / 8.108 */
    {178, "Presence Reporting Area Information"},                               /* Extendable / 8.109 */
    {179, "TWAN Identifier Timestamp"},                                         /* Extendable / 8.110 */
    {180, "Overload Control Information"},                                      /* Extendable / 8.111 */
    {181, "Load Control Information"},                                          /* Extendable / 8.112 */
    {182, "Metric"},                                                            /* Fixed Length / 8.113 */
    {183, "Sequence Number"},                                                   /* Fixed Length / 8.114 */
    {184, "APN and Relative Capacity"},                                         /* Extendable / 8.115 */
    {185, "WLAN Offloadability Indication"},                                    /* Extendable / 8.116 */
    {186, "Paging and Service Information"},                                    /* Extendable / 8.117 */
    {187, "Integer Number" },                                                   /* Variable / 8.118 */
    {188, "Millisecond Time Stamp" },                                           /* Extendable / 8.119 */
    {189, "Monitoring Event Information"},                                      /* Extendable / 8.120 */
    {190, "ECGI List"},                                                         /* Extendable / 8.121 */
    {191, "Remote UE Context"},                                                 /* Extendable / 8.122 */
    {192, "Remote User ID"},                                                    /* Extendable / 8.123 */
    {193, "Remote UE IP information"},                                          /* Variable Length / 8.124 */
    {194, "CIoT Optimizations Support Indication"},                             /* Extendable / 8.125 */
    {195, "SCEF PDN Connection"},                                               /* Extendable / 8.126 */
    {196, "Header Compression Configuration"},                                  /* Extendable / 8.127 */
    {197, "Extended Protocol Configuration Options(ePCO)"},                     /* Variable Length / 8.128 */
    {198, "Serving PLMN Rate Control"},                                         /* Extendable / 8.129 */
    {199, "Counter" },                                                          /* Extendable / 8.130 */
    {200, "Mapped UE Usage Type" },                                             /* Extendable / 8.131 */
    {201, "Secondary RAT Usage Data Report" },                                  /* Extendable / 8.132 */
    {202, "UP Function Selection Indication Flags" },                           /* Extendable / 8.133 */
    {203, "Maximum Packet Loss Rate" },                                         /* Extendable / 8.134 */
    {204, "APN Rate Control Status" },                                          /* Extendable / 8.135 */
    {205, "Extended Trace Information" },                                       /* Extendable / 8.136 */
    {206, "Monitoring Event Extension Information" },                           /* Extendable / 8.137 */
    {207, "Additional RRM Policy Index" },                                      /* Fixed Length / 8.138 */
    {208, "V2X Context" },                                                      /* Extendable / 8.139 */
    {209, "PC5 QoS Parameters" },                                               /* Extendable / 8.140 */
    {210, "Services Authorized" },                                              /* Extendable / 8.141 */
    {211, "Bit Rate" },                                                         /* Extendable / 8.142 */
    {212, "PC5 QoS Flow" },                                                     /* Extendable / 8.143 */
    {213, "SGi PtP Tunnel Address" },                                           /* Extendable / 8.144 */
    {214, "PGW Change Info" },                                                  /* Extendable / 8.145 */
    {215, "PGW Set FQDN" },                                                     /* Extendable / 8.146 */
    {216, "Group Id" },                                                         /* Variable Length / 8.147 */
    {217, "PSCell ID" },                                                        /* Fixed Length / 8.148*/
    {218, "UP Security Policy" },                                               /* Extendable / 8.149*/
    {219, "Alternative IMSI" },                                                 /* Variable Length / 8.150 */
                                                                                /* 220 to 254    Spare. For future use.    */
    *)
    
    class function ProtoTypeToString(const aProtoType: Byte): String; static;
    class function MessageTypeToString(aMsgType: Byte): String; static;
    class function IETypeToString(aIEType: Byte): string; static;
    class procedure ParserIEType(var aCurrentPos: Integer; aMaxLen,aStartLevel: Integer; const aPayload: PByte;AListDetail: TListHeaderString); static;
    class function IETypeToLabel(aIEType: Byte): string; static;
    class function CauseToString(const aCause: Byte): String; static;
    class function CauseToString_vals(const aCause: Byte): String; static;
    class function RatToString(const aRat: Byte): String; static;
    class function InterfaceTypeToString(const aType: Byte): String; static;
    class function PdnTypeToString(const aType: Byte): String; static;
    class function SelectModeToString(const aMode: Byte): String; static;
    class function APNrestrictionToString(const aRest: Byte): String; static;
    class function MessageTypeV2ToString(const aMsgType: Byte): String; static;
    class function TimeZoneTypeToString(const aRest: Byte): String; static;
  protected
  public
    /// <summary>
    /// Returns the default GTP port (110).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the GTP protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the GTP protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the GTP protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean; override;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; override;        
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolGTP }
class function TWPcapProtocolGTP.DefaultPort: Word;
begin
  Result := PROTO_GTP_PORT;
end;

class function TWPcapProtocolGTP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_GTP
end;

class function TWPcapProtocolGTP.ProtoName: String;
begin
  Result := 'GPRS Tunnelling Protocol';
end;

class function TWPcapProtocolGTP.IsValid(const aPacket: PByte;aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var LUDPPPtr    : PUDPHdr;
    LUDPPayLoad : PByte;
    LVersion    : Byte;
begin
  Result  := inherited IsValid(aPacket,aPacketSize,aAcronymName,aIdProtoDetected);  

  if not HeaderUDP(aPacket,aPacketSize,LUDPPPtr) then exit;
  
  if not Result then
    Result := IsValidByPort(PROTO_GTP_C_PORT,DstPort(LUDPPPtr),SrcPort(LUDPPPtr),aAcronymName,aIdProtoDetected);
  if not Result then
    Result := IsValidByPort(PROTO_GTP_U_PORT,DstPort(LUDPPPtr),SrcPort(LUDPPPtr),aAcronymName,aIdProtoDetected);  

  if Result then
  begin
    LUDPPayLoad  := GetUDPPayLoad(aPacket,aPacketSize);
    LVersion     := ( PByte(LUDPPayLoad)^ shr 5);      
    aAcronymName := Format('%s%s',[aAcronymName,ifthen(LVersion=1,'','v2')]);
  end;
  
end;

class function TWPcapProtocolGTP.AcronymName: String;
begin
  Result := 'GTP';
end;

class function TWPcapProtocolGTP.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;
var LUDPPayLoad        : PByte;
    LPUDPHdr           : PUDPHdr;
    LVersion           : Byte;
    LGTPHeaderV1       : PTGTPHeaderV1;
    LGTPHeaderV2       : PTGTPHeaderV2;
    LGTPHeaderV3       : PTGTPHeaderV3;  
    LCurrentPos        : Integer;    
    LByteValue         : Byte;
    LWordValue         : Word;
    LCardinalValue     : Cardinal;          
    LIn64Value         : UInt64;
    LMessageType       : Byte;
    LPayLoadLen        : Integer;
    LBytes             : TidBytes; 
begin
  Result := False;

  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LUDPPayLoad   := GetUDPPayLoad(aPacketData,aPacketSize);
  LPayLoadLen   := UDPPayLoadLength(LPUDPHdr)-8;
  LMessageType  := 0;
  LVersion      := ( PByte(LUDPPayLoad)^ shr 5);  
  FIsFilterMode := aIsFilterMode;
  
 AListDetail.Add(AddHeaderInfo(aStartLevel, AcronymName, Format('%s (%s)', [ProtoName, AcronymName]), null, LUDPPayLoad,LPayLoadLen));

  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Version',[AcronymName]), 'Version:', LVersion, @LVersion,sizeOf(LVersion)));  
  case LVersion of
    1:
      begin      
        LGTPHeaderV1 := PTGTPHeaderV1(LUDPPayLoad);
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Flags',[AcronymName]), 'Flags:', ByteToBinaryString(LGTPHeaderV1.Flags), @LGTPHeaderV1.Flags,sizeOf(LGTPHeaderV1.Flags), LGTPHeaderV1.Flags ));  
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.ProtocolType',[AcronymName]), 'Protocol type:', ProtoTypeToString(GetBitValue(LGTPHeaderV1.Flags,4)), @LGTPHeaderV1.Flags,sizeOf(LGTPHeaderV1.Flags), GetBitValue(LGTPHeaderV1.Flags,4) ));
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.Reserver',[AcronymName]), 'Reserver:', GetBitValue(LGTPHeaderV1.Flags,5), @LGTPHeaderV1.Flags,sizeOf(LGTPHeaderV1.Flags) ));        
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.NextExtHeaderPresent',[AcronymName]), 'Next extension header present:', GetBitValue(LGTPHeaderV1.Flags,6)=1, @LGTPHeaderV1.Flags,sizeOf(LGTPHeaderV1.Flags), GetBitValue(LGTPHeaderV1.Flags,6) ));                        
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.SeqNumberPresent',[AcronymName]), 'Seq number present:', GetBitValue(LGTPHeaderV1.Flags,7)=1, @LGTPHeaderV1.Flags,sizeOf(LGTPHeaderV1.Flags), GetBitValue(LGTPHeaderV1.Flags,7)));                
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.NPDUNumberPresent',[AcronymName]), 'N-PDU number present:', GetBitValue(LGTPHeaderV1.Flags,8)=1, @LGTPHeaderV1.Flags,sizeOf(LGTPHeaderV1.Flags), GetBitValue(LGTPHeaderV1.Flags,8)));                        
        LMessageType := LGTPHeaderV1.MessageType;
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Type',[AcronymName]), 'Type:', MessageTypeToString(LMessageType), @LMessageType,sizeOf(LMessageType), LMessageType ));
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Len',[AcronymName]), 'Length:', wpcapntohs( LGTPHeaderV1.MessageLen ), @LGTPHeaderV1.MessageLen,sizeOf(LGTPHeaderV1.MessageLen) ));        
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.TEID',[AcronymName]), 'TEID:', wpcapntohl( LGTPHeaderV1.TEID ), @LGTPHeaderV1.TEID,sizeOf(LGTPHeaderV1.TEID) ));  
         
        LCurrentPos := SizeOf(TGTPHeaderV1);      
        if GetBitValue(LGTPHeaderV1.Flags,7)=1 then      
          ParserWordValue(LUDPPayLoad,aStartLevel+1,Format('%s.SequenceNumber',[AcronymName]), 'Sequence number:',AListDetail,LCurrentPos);;
          
        if GetBitValue(LGTPHeaderV1.Flags,8)=1 then
        begin
         { N-PDU number
           an (optional) 8-bit field. This field exists if any of the E, S, or PN bits are on. The field must be interpreted only if the PN bit is on.
         }
         
        end;
        Inc(LCurrentPos,2);
        if GetBitValue(LGTPHeaderV1.Flags,6)=1 then
        begin
          {
          Next extension header type
             an (optional) 8-bit field. This field exists if any of the E, S, or PN bits are on. The field must be interpreted only if the E bit is on.
             Next Extension Headers are as follows:
            Extension length
            an 8-bit field. This field states the length of this extension header, including the length, the contents, and the next extension header field, in 4-octet units, so the length of the extension must always be a multiple of 4.
            Contents
            extension header contents.
            Next extension header
            an 8-bit field. It states the type of the next extension, or 0 if no next extension exists. This permits chaining several next extension headers.
          }
          ParserIEType(LCurrentPos,LPayLoadLen,aStartLevel,LUDPPayLoad,AListDetail);   
        end;
       { Contents extension header contents.}
      end;
    2:
      begin 
        LGTPHeaderV2 := PTGTPHeaderV2(LUDPPayLoad);
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Flags',[AcronymName]), 'Flags:', ByteToBinaryString(LGTPHeaderV2.Flags), @LGTPHeaderV2.Flags,sizeOf(LGTPHeaderV2.Flags), LGTPHeaderV2.Flags ));        
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.Piggybacking',[AcronymName]), 'Piggybacking flag (P):', GetBitValue(LGTPHeaderV2.Flags,4)=1, @LGTPHeaderV2.Flags,sizeOf(LGTPHeaderV2.Flags), GetBitValue(LGTPHeaderV2.Flags,4) ));
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.TEID',[AcronymName]), 'TEID flag (T):', GetBitValue(LGTPHeaderV2.Flags,5)=1, @LGTPHeaderV2.Flags,sizeOf(LGTPHeaderV2.Flags), GetBitValue(LGTPHeaderV2.Flags,5) ));        
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.MP',[AcronymName]), 'Message Priority(MP):', GetBitValue(LGTPHeaderV2.Flags,6)=1, @LGTPHeaderV2.Flags,sizeOf(LGTPHeaderV2.Flags), GetBitValue(LGTPHeaderV2.Flags,6) ));                        
        LMessageType := LGTPHeaderV2.MessageType;
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Type',[AcronymName]), 'Type:', MessageTypeV2ToString(LMessageType), @LMessageType,sizeOf(LMessageType), LMessageType ));
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Len',[AcronymName]), 'Length:', wpcapntohs( LGTPHeaderV2.MessageLen ), @LGTPHeaderV2.MessageLen,sizeOf(LGTPHeaderV2.MessageLen)));        

        LCurrentPos := SizeOf(TGTPHeaderV2);
        
        {32	TEID (only present if T=1)}
        {64 (32 if TEID not present)	Sequence number}    
        if GetBitValue(LGTPHeaderV2.Flags,5) = 1 then
        begin
          ParserCardinalValue(LUDPPayLoad,aStartLevel+1,Format('%s.TEID',[AcronymName]), 'TEID:',AListDetail,LCurrentPos);

          SetLength(LBytes,3); 
          Move((LUDPPayLoad+LCurrentPos )^,LBytes[0],3);
          AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SequenceNumber',[AcronymName]), 'Sequence number:', wpcapntohl( BytesToInt32(LBytes) ), @LBytes,sizeOf(LBytes)));
          Inc(LCurrentPos,3);
        end
        else
        begin
          LIn64Value := PUint64(LUDPPayLoad+LCurrentPos )^;
          AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SequenceNumber',[AcronymName]), 'Sequence number:', wpcapntohs( LIn64Value ), @LIn64Value,sizeOf(LIn64Value)));      
          Inc(LCurrentPos,SizeOf(LIn64Value));            
        end;
        
        ParserByteValue(LUDPPayLoad,aStartLevel+1,Format('%s.Spare',[AcronymName]), 'Spare:',AListDetail,LCurrentPos);
        ParserIEType(LCurrentPos,LPayLoadLen,aStartLevel,LUDPPayLoad,AListDetail);        
      end;
      
  else Exit;
  end;
  Result := True;
end;

Class Procedure TWPcapProtocolGTP.ParserIEType(var aCurrentPos:Integer;aMaxLen,aStartLevel : Integer;const aPayload:PByte;AListDetail: TListHeaderString);
var LBytes         : TidBytes;
    LIEType        : Byte;
    LLenIE         : Word; 
    LByteValue     : Byte;
    LCardinalValue : Cardinal;
    LWordValue     : Word;   
    LStartPos      : Integer;
    LTmpLen        : Integer;
    LUint64        : UInt64;
    LMCC           : Word;
    LLabel         : String;
    LLabelIEType   : String;
    LTmpStr        : String;
    I              : Integer;
    
    procedure AddMCC(const aLabelIEType: string; aLevel: Integer);
    var LFirstByte : Byte; 
        LSecondByte: Byte;
        LMCC3      : Byte; 
        LMCC2      : Byte;
        LMCC1      : Byte;
    begin
      LWordValue    := wpcapntohl(PCardinal(aPayload+aCurrentPos)^);

      LFirstByte  := PByte(aPayload+aCurrentPos)^;
      LMCC1       := LFirstByte and $0f;
      LMCC2       := LFirstByte shr 4;
      Inc(aCurrentPos);
      
      LSecondByte := PByte(aPayload+aCurrentPos)^ ;
      LMCC3       := LSecondByte and $0f;      
      LMCC        :=  (100 * LMCC1) + (10 * LMCC2 )+ LMCC3;
  
      AListDetail.Add(AddHeaderInfo(aLevel, Format('%s.MCC', [aLabelIEType]), 'Mobile Country Code (MCC):', LMCC, @LWordValue, SizeOf(LWordValue), LMCC));
      AListDetail.Add(AddHeaderInfo(aLevel + 1, Format('%s.MCC.Country', [aLabelIEType]), 'Country:', MCCToCountry(LMCC), nil, 0, LMCC, wetMcc ));
    end;

    Procedure AddMNC(const aLabelIEType:String;aLevel:Integer);
    var LFirstByte : Byte; 
        LMNC3      : Byte; 
        LMNC2      : Byte;
        LMNC       : Byte;    
    begin
      LWordValue  := PWord(aPayload+aCurrentPos)^;
      Inc(aCurrentPos);
      LFirstByte  := PByte(aPayload+aCurrentPos)^;
      LMNC2       := LFirstByte and $0f;
      LMNC3       := LFirstByte shr 4;
      LMNC        := (10 * LMNC2) + LMNC3;
      AListDetail.Add(AddHeaderInfo(aLevel,Format('%s.MNC',[aLabelIEType]), 'Mobile Network Code (MNC):',LMNC, @LWordValue,sizeOf(LWordValue),-1,wetMNC));
      Inc(aCurrentPos);         
    end;  

    procedure AddIMSI(const aLabelIEType: string; aLevel: Integer);
    var LIMSI      : TIdBytes;
        LIMSIString: string;
        LIndex     : Integer;
        LMCCImsi   : String;
    begin
      SetLength(LIMSI,LLenIE);
      Move(PByte(aPayload+aCurrentPos)^, LIMSI[0], LLenIE);
      LIMSIString := String.Empty;
      for LIndex := Low(LIMSI) to High(LIMSI) do
      begin
        if (LIMSI[LIndex] and $0f) <= 9 then        
          LIMSIString := Format('%s%d',[LIMSIString,(LIMSI[LIndex] and $0f)]);
          
        if (LIMSI[LIndex] shr 4) <= 9 then
          LIMSIString := Format('%s%d',[LIMSIString,(LIMSI[LIndex] shr 4)]);
      end;
      LMCCImsi := Copy(LIMSIString,1,3);
      AListDetail.Add(AddHeaderInfo(aLevel, Format('%s.IMSI', [aLabelIEType]), 'IMSI:',LIMSIString,@LIMSI,sizeOf(LIMSI)));
      AListDetail.Add(AddHeaderInfo(aLevel + 1, Format('%s.MCC.Country', [aLabelIEType]), 'Country:', MCCToCountry(LMCCImsi.ToInteger()), nil, 0, LMCCImsi.Tointeger, wetMcc ));      
      Inc(aCurrentPos,LLenIE);
    end;

    procedure AddMSISDN(const aLabelIEType: string; aLevel: Integer);
    var LMSISDN      : TIdBytes;
        LMSISDNString: String;
        LIndex       : Integer;
    begin
      SetLength(LMSISDN,LLenIE);
      Move(PByte(aPayload+aCurrentPos)^, LMSISDN[0], LLenIE);
      LMSISDNString := String.Empty;
      for LIndex := Low(LMSISDN) to High(LMSISDN) do
      begin
        if (LMSISDN[LIndex] and $0f) <= 9 then        
          LMSISDNString := Format('%s%d',[LMSISDNString,(LMSISDN[LIndex] and $0f)]);
        if (LMSISDN[LIndex] shr 4) <= 9 then
          LMSISDNString := Format('%s%d',[LMSISDNString,(LMSISDN[LIndex] shr 4)]);        
      end;
              
      AListDetail.Add(AddHeaderInfo(aLevel, Format('%s.MSISDN', [aLabelIEType]), 'MSISDN:', LMSISDNString,@LMSISDN,sizeOf(LMSISDN)));
      Inc(aCurrentPos,LLenIE);
    end;    

    procedure IncResidualLen;
    begin
      LTmpLen :=  LLenIE - (aCurrentPos-LStartPos); 
      if LTmpLen > 0 then
        Inc(aCurrentPos,LTmpLen);        
    end;  
           
begin
  if aCurrentPos+1 <= aMaxLen then
  begin
    while aCurrentPos < aMaxLen do
    begin
      LIEType := PByte(aPayload+aCurrentPos )^; 
      LLabel  := Format('%s.%s',[AcronymName,IETypeToLabel(LIEType)]);  
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, LLabel ,IETypeToString(LIEType), null, nil,0,LIEType));

      AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.IEType',[LLabel]), 'IE Type:', IETypeToString(LIEType), @LIEType,sizeOf(LIEType), LIEType ));
      Inc(aCurrentPos,SizeOf(LIEType)); 

      
      LLenIE := wpcapntohs(PWord(aPayload+aCurrentPos )^);
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.IELen',[LLabel]), 'IE Length:',LLenIE, @LLenIE,sizeOf(LLenIE)));
      Inc(aCurrentPos,SizeOf(LLenIE));  

      LByteValue := PByte(aPayload+aCurrentPos )^;
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.CR',[LLabel]), 'CR:', LByteValue shr 4, @LByteValue,sizeOf(LByteValue), LByteValue shr 4 ));
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Istance',[LLabel]), 'Istance:', LByteValue and $07, @LByteValue,sizeOf(LByteValue), LByteValue and $07 ));        
      Inc(aCurrentPos,SizeOf(LByteValue));    

      LStartPos := aCurrentPos;
      
      case LIEType of
        GTP_IEI_IMSI : AddIMSI(LLabel,aStartLevel+2);
          
        GTP_IEI_CAUSE                    :
          begin            
            LByteValue := PByte(aPayload+aCurrentPos )^; 
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Cause',[LLabel]), 'Cause:',CauseToString( LByteValue), @LByteValue,sizeOf(LByteValue) , LByteValue ));
            Inc(aCurrentPos,SizeOf(LByteValue));         

            LByteValue := PByte(aPayload+aCurrentPos )^; 
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.SpareBits',[LLabel]), 'Spare bits:', LByteValue shr 3, @LByteValue,sizeOf(LByteValue), LByteValue shr 3));
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.PCE',[LLabel]), 'PCE (PDN Connection IE Error):', GetBitValue(LByteValue,6)=1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,6) ));
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.BCE',[LLabel]), 'BCE (Bear Context IE Error):', GetBitValue(LByteValue,7)=1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,7) ));        
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.CS',[LLabel]), 'CS (Cause source):', ifthen(GetBitValue(LByteValue,8)=0,'Originated by remote node','Originated by node sending the message') , @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,8) ));
            Inc(aCurrentPos,SizeOf(LByteValue));  
          end;
                
        GTP_IEI_APN                      :
          begin
            LTmpLen :=  LLenIE - (aCurrentPos-LStartPos);

            if LTmpLen > 0 then
            begin
              SetLength(LBytes,LTmpLen); 
              Move((aPayload+aCurrentPos )^,LBytes[0],LTmpLen);
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.APN',[LLabel]), 'APN:', BytesToStringRaw(LBytes), @LBytes,sizeOf(LBytes)));
              Inc(aCurrentPos,LTmpLen);
            end;          
          end;
        
        GTP_IEI_AMBR                     :
          begin
            ParserCardinalValue(aPayload,aStartLevel+2,Format('%s.AMBRUpLink',[LLabel]), 'AMBR UpLink(Max bit rate):',AListDetail,aCurrentPos);            
            ParserCardinalValue(aPayload,aStartLevel+2,Format('%s.AMBRDownLink',[LLabel]), 'AMBR DownLink(Max Bit rate):',AListDetail,aCurrentPos);            
          end;

        GTP_EPS_BEARER_ID:
          begin
            LByteValue := PByte(aPayload+aCurrentPos)^; 
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.SpareBits',[LLabel]), 'Spare bits:', LByteValue shr 4, @LByteValue,sizeOf(LByteValue)));
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.EPSbearID',[LLabel]), 'EPS bear ID:', LByteValue and $7, @LByteValue,sizeOf(LByteValue)));        
            Inc(aCurrentPos,SizeOf(LByteValue));  
          end; 
          
        GTP_IEI_MEI :
          begin
              SetLength(LBytes,LLenIE);
              Move(PByte(aPayload+aCurrentPos)^, LBytes[0], LLenIE);
              LTmpStr := String.Empty;
              for I := Low(LBytes) to High(LBytes) do
              begin
                if (LBytes[I] and $0f) <= 9 then        
                  LTmpStr := Format('%s%d',[LTmpStr,(LBytes[I] and $0f)]);
          
                if (LBytes[I] shr 4) <= 9 then
                  LTmpStr := Format('%s%d',[LTmpStr,(LBytes[I] shr 4)]);        
              end;
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.MEI', [LLabel]), 'MEI:',LTmpStr,@LBytes,sizeOf(LBytes)));
              Inc(aCurrentPos,LLenIE);
          end;
          
        GTP_IEI_MSISDN                   : AddMSISDN(LLabelIEType,aStartLevel+2);

        GTP_IEI_INDICATION               :
          begin
            LByteValue := PByte(aPayload+aCurrentPos )^; 
            if LLenIE > 0 then
            begin
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.DAF',[LLabel]), 'DAF (Dual Address Bearer Flag):', GetBitValue(LByteValue,1) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,1) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.DTF',[LLabel]), 'DTF (Direct Tunnel Flag):', GetBitValue(LByteValue,2) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,2) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.HI',[LLabel]), 'HI (Handover Indication):', GetBitValue(LByteValue,3) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,3) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.DFI',[LLabel]), 'DFI (Direct Forwarding Indication):', GetBitValue(LByteValue,4) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,4) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.OI',[LLabel]), 'OI (Operation Indication):', GetBitValue(LByteValue,5) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,5) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.ISRSI',[LLabel]), 'ISRSI (Idle mode Signalling Reduction Supported Indication):', GetBitValue(LByteValue,6) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,6) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.ISRAI',[LLabel]), 'ISRAI (Idle mode Signalling Reduction Activation Indication):', GetBitValue(LByteValue,7) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,7) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.SGWCI',[LLabel]), 'SGWCI (SGW Change Indication):', GetBitValue(LByteValue,8) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,8) ));                                                                                    
              Inc(aCurrentPos,SizeOf(LByteValue));  
            end;        
            if LLenIE > 1 then
            begin
              LByteValue := PByte(aPayload+aCurrentPos )^; 
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.SQCI',[LLabel]), 'SQCI (Subscribed QoS Change Indication):', GetBitValue(LByteValue,1) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,1) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.UIMSI',[LLabel]), 'UIMSI (Unauthenticated IMSI):', GetBitValue(LByteValue,2) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,2) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.CFSI',[LLabel]), 'CFSI (Change F-TEID support indication):', GetBitValue(LByteValue,3) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,3) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.CRSI',[LLabel]), 'CRSI (Change Reporting support indication):', GetBitValue(LByteValue,4) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,4) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.PS',[LLabel]), 'PS (Piggybacking Supported):', GetBitValue(LByteValue,5) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,5) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.PT',[LLabel]), 'PT (Protocol Type):', GetBitValue(LByteValue,6) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,6) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.SI',[LLabel]), 'SI (Scope Indication):', GetBitValue(LByteValue,7) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,7) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.MSV',[LLabel]), 'MSV (MS Validated):', GetBitValue(LByteValue,8) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,8) ));                                                                        
              Inc(aCurrentPos,SizeOf(LByteValue)); 
            end;  
            if LLenIE > 2 then  
            begin
              LByteValue := PByte(aPayload+aCurrentPos )^; 
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.RetLoc',[LLabel]), 'RetLoc (Retrieve Location Indication Flag):', GetBitValue(LByteValue,1) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,1) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.PBIC',[LLabel]), 'PBIC (Propagate BBAI Information Change):', GetBitValue(LByteValue,2) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,2) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.SRNI',[LLabel]), 'SRNI (SGW Restoration Needed Indication)):', GetBitValue(LByteValue,3) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,3) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.S6AF',[LLabel]), 'S6AF (Static IPv6 Address Flag):', GetBitValue(LByteValue,4) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,4) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.S4AF',[LLabel]), 'S4AF (Static IPv4 Address Flag):', GetBitValue(LByteValue,5) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,5) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.MBMDT',[LLabel]), 'MBMDT (Management Based MDT allowed flag):', GetBitValue(LByteValue,6) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,6) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.ISRAU',[LLabel]), 'ISRAU (ISR is activated for the UE):', GetBitValue(LByteValue,7) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,7) ));
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.CCRSI',[LLabel]), 'CCRSI (CSG Change Reporting support indication:', GetBitValue(LByteValue,8) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,8) ));                                                                        
              Inc(aCurrentPos,SizeOf(LByteValue));    

            end;    
          end;
          
        
        GTP_IEI_PAA                      :
          begin
            LByteValue := PByte(aPayload+aCurrentPos )^;      
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.PDNType',[LLabel]), 'PDN Type:', ifthen((LByteValue and $07)=1,'IPv4','Ipv6'), @LByteValue,sizeOf(LByteValue), LByteValue and $07 ));   
            Inc(aCurrentPos,SizeOf(LByteValue)); 

            if (LByteValue and $07)=1 then
            begin
              LCardinalValue :=  PCardinal(aPayload+aCurrentPos )^;
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.PDNAddrAndPrefix',[LLabel]), 'PDN Address and Prefix(IPv4):', intToIPV4( LCardinalValue ), @LCardinalValue,sizeOf(LCardinalValue)));          
              Inc(aCurrentPos,SizeOf(LCardinalValue));
            end
            else
            begin
              LTmpLen :=  LLenIE - (aCurrentPos-LStartPos);

              if LTmpLen > 0 then
              begin
                SetLength(LBytes,LTmpLen); 
                Move((aPayload+aCurrentPos )^,LBytes[0],LTmpLen);
                AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.PDNAddrAndPrefix',[LLabel]), 'PDN Address and Prefix(IPv6):', BytesToStringRaw(LBytes), @LBytes,sizeOf(LBytes)));
                Inc(aCurrentPos,LTmpLen);
              end;
            end;
              
          end;
          
        GTP_IEI_BEARER_LEVEL_QoS:
          begin
            LByteValue := PByte(aPayload+aCurrentPos )^; 
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.PCI',[LLabel]), 'PCI (Pre-emption Capability):', GetBitValue(LByteValue,2)=1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,2) ));
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.PL',[LLabel]), 'PL (Priority Level):', ( LByteValue shl 2) and $FC, @LByteValue,sizeOf(LByteValue),  ( LByteValue shl 2) and $FC ));        
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.PVI',[LLabel]), 'PVI (Pre-emption Vulnerability): Enabled', GetBitValue(LByteValue,8)=1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,8) ));           
            Inc(aCurrentPos,SizeOf(LByteValue));        

            ParserByteValue(aPayload,aStartLevel+2,Format('%s.LabelQCI',[LLabel]), 'Label (QCI):',AListDetail,aCurrentPos);  
            
            LTmpLen := 5;

            if LTmpLen <= aMaxLen - aCurrentPos then
            begin
              SetLength(LBytes,LTmpLen); 
              Move(PByte(aPayload+aCurrentPos)^, LBytes[0], LTmpLen);
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.UpLinkMax',[LLabel]), 'UpLink(Max bit rate):',  BytesToInt64(LBytes), @LBytes,sizeOf(LBytes)));          
              Inc(aCurrentPos,LTmpLen);
            end;
              
            if LTmpLen <= aMaxLen - aCurrentPos then
            begin
              SetLength(LBytes,LTmpLen); 
              Move(PByte(aPayload+aCurrentPos)^, LBytes[0], LTmpLen);
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.DownLinkMax',[LLabel]), 'DownLink(Max Bit rate):',  BytesToInt64(LBytes), @LBytes,sizeOf(LBytes)));          
              Inc(aCurrentPos,LTmpLen);
            end;

            if LTmpLen <= aMaxLen - aCurrentPos then
            begin
              SetLength(LBytes,LTmpLen); 
              Move(PByte(aPayload+aCurrentPos)^, LBytes[0], LTmpLen);
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.UpLinkGuaranteed',[LLabel]), 'UpLink(Guaranteed bit rate):',  BytesToInt64(LBytes), @LBytes,sizeOf(LBytes)));          
              Inc(aCurrentPos,LTmpLen);
            end;
              
            if LTmpLen <= aMaxLen - aCurrentPos then
            begin
              SetLength(LBytes,LTmpLen); 
              Move(PByte(aPayload+aCurrentPos)^, LBytes[0], LTmpLen);
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.DownLinkGuaranteed',[LLabel]), 'DownLink(Guaranteed Bit rate):',   BytesToInt64(LBytes), @LBytes,sizeOf(LBytes)));          
              Inc(aCurrentPos,LTmpLen);
            end;
          end;
          
        GTP_IEI_RAT_TYPE                 :
          begin
            LByteValue := PByte(aPayload+aCurrentPos )^; 
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.RATType',[LLabel]), 'RAT type:',RatToString(LByteValue), @LByteValue,sizeOf(LByteValue) ,LByteValue));
            Inc(aCurrentPos,SizeOf(LByteValue));            
          end;
          
        GTP_IEI_SERVING_NETWORK          :
          begin
            AddMCC(LLabel,aStartLevel+2);
            AddMNC(LLabel,aStartLevel+2);                 
          end;

        GTP_IEI_F_TFT :
          begin
            LByteValue := PByte(aPayload+aCurrentPos )^; 
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.OPCode',[LLabel]), 'TFT operation code:',LByteValue and $3, @LByteValue,sizeOf(LByteValue)));
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Ebit',[LLabel]), 'E bit:',GetBitValue(LByteValue,4)=1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,4) ));   
            LWordValue := LByteValue and $7;          
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.NPacketFilter',[LLabel]), 'Number packet filter:',LWordValue, @LByteValue,sizeOf(LByteValue) ));                        
            Inc(aCurrentPos,SizeOf(LByteValue));
            
            for I := 0 to LWordValue -1 do
            begin
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.PacketFilter',[LLabel]), 'Packet filter:',null, nil,0));
              LByteValue := PByte(aPayload+aCurrentPos )^; 
              AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.PacketFilter.SpareBits',[LLabel]), 'Spare bit:',LByteValue and $2, @LByteValue,sizeOf(LByteValue)));
              AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.PacketFilte.rDirection',[LLabel]), 'Packet filter direction:',LByteValue and 30, @LByteValue,sizeOf(LByteValue), LByteValue and 30 )); 
              AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.PacketFilter.ID',[LLabel]), 'Packet filter identifier:',LByteValue and $F, @LByteValue,sizeOf(LByteValue) )); 
              inc(aCurrentPos,SizeOf(LByteValue)); 
              
              ParserByteValue(aPayload,aStartLevel+2,Format('%s.PacketFilter.EvalPre',[LLabel]), 'Packet evaluation precedence:',AListDetail,aCurrentPos);  
  
              LByteValue := PByte(aPayload+aCurrentPos )^; 
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.PacketFilter.Len  ',[LLabel]), 'Packet filter length:',LByteValue, @LByteValue,sizeOf(LByteValue)));
              inc(aCurrentPos,SizeOf(LByteValue)); 

              LCardinalValue := LByteValue;

              ParserByteValue(aPayload,aStartLevel+2,Format('%s.PacketFilter.ComponentTypeID',[LLabel]), 'Packet filter component type identifier:',AListDetail,aCurrentPos);  
          
              Inc(aCurrentPos,LByteValue-1);
                                         
            end;
          end;    
          
        GTP_IEI_ULI                      :
          begin
            LByteValue := PByte(aPayload+aCurrentPos )^; 
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.ULIFlags',[LLabel]), 'ULI Flags:', null, @LByteValue,sizeOf(LByteValue)));
            AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.ULIFlags.ExtMacroeNodeBID',[LLabel]), 'Extended Macro eNodeB ID Present:', GetBitValue(LByteValue,1) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,1) ));
            AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.ULIFlags.MacroeNodeBID',[LLabel]), 'Macro eNodeB ID Present:', GetBitValue(LByteValue,2) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,2) ));
            AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.ULIFlags.LAI',[LLabel]), 'LAI Present:', GetBitValue(LByteValue,3) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,3) ));
            AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.ULIFlags.ECGI',[LLabel]), 'ECGI Present:', GetBitValue(LByteValue,4) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,4) ));
            AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.ULIFlags.TAI',[LLabel]), 'TAI Present:', GetBitValue(LByteValue,5) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,5)));
            AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.ULIFlags.RAI',[LLabel]), 'RAI Present:', GetBitValue(LByteValue,6) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,6)));
            AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.ULIFlags.SAI',[LLabel]), 'SAI Present:', GetBitValue(LByteValue,7) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,7)));
            AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.ULIFlags.CGI',[LLabel]), 'CGI Present:', GetBitValue(LByteValue,8) = 1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,8) ));                                                                        
            Inc(aCurrentPos,SizeOf(LByteValue)); 

            if GetBitValue(LByteValue,5) = 1 then
            begin
              SetLength(LBytes,5); 
              Move((aPayload+aCurrentPos )^,LBytes[0],5);  
              LLabelIEType := Format('%s.TAI',[LLabel]);
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, LLabelIEType, 'Tracking Area Identity (TAI):', null, @LBytes,sizeOf(LBytes)));            

              AddMCC(LLabelIEType,aStartLevel+3);
              AddMNC(LLabelIEType,aStartLevel+3);   

              LWordValue := PWord(aPayload+aCurrentPos )^;
              AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%S.TAC',[LLabelIEType]),  'Tracking Area Code:', ( LWordValue ), @LWordValue,sizeOf(LWordValue),-1,wetMNC));
              Inc(aCurrentPos,SizeOf(LWordValue))                             
            end;   
            
            if GetBitValue(LByteValue,4) = 1 then
            begin
              SetLength(LBytes,7); 
              Move((aPayload+aCurrentPos )^,LBytes[0],7);  
              LLabelIEType := Format('%s.ECGI',[LLabel]);              
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, LLabelIEType, 'E-UTRAN Cell Global Identifier (ECGI):', null, @LBytes,sizeOf(LBytes)));            

              AddMCC(LLabelIEType,aStartLevel+3);
              AddMNC(LLabelIEType,aStartLevel+3);    

              LByteValue := PByte(aPayload+aCurrentPos )^;      
              AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Spare',[LLabelIEType]), 'Spare:',LByteValue, @LByteValue,sizeOf(LByteValue)));

              LCardinalValue :=  PCardinal(aPayload+aCurrentPos )^;
              AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.ECI',[LLabelIEType]), 'ECI (E-UTRAN Cell Identifier):', LCardinalValue , @LCardinalValue,sizeOf(LCardinalValue)));  
              Inc(aCurrentPos,2);     
                  
              ParserByteValue(aPayload,aStartLevel+4,Format('%s.ECI.eNodeBID',[LLabelIEType]), 'eNodeB ID:',AListDetail,aCurrentPos);      
              ParserByteValue(aPayload,aStartLevel+4,Format('%s.ECI.CellID',[LLabelIEType]), 'CellID:',AListDetail,aCurrentPos);                                                                           
            end;
    
            Inc(aCurrentPos,LlenIE-(aCurrentPos-LStartPos));                
          end;
        
        GTP_IEI_F_TEID                   :
          begin
            LByteValue := PByte(aPayload+aCurrentPos )^; 
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.IPv4',[LLabel]), 'IPv4 present:', GetBitValue(LByteValue,1)=1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,1) ));
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.IPv6',[LLabel]), 'IPv6 present:', GetBitValue(LByteValue,2)=1, @LByteValue,sizeOf(LByteValue), GetBitValue(LByteValue,2) ));        
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.InfType',[LLabel]), 'Interface type:',InterfaceTypeToString( LByteValue and $3F), @LByteValue,sizeOf(LByteValue), LByteValue and $3F ));           
            Inc(aCurrentPos,SizeOf(LByteValue));  

            ParserCardinalValue(aPayload,aStartLevel+2,Format('%s.TEIDGREKey',[LLabel]), 'TEID/GRE Key:',AListDetail,aCurrentPos);                  

            if GetBitValue(LByteValue,1)=1 then
            begin
              LCardinalValue :=  PCardinal(aPayload+aCurrentPos )^;
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.FTEID',[LLabel]), 'F-TEID IPv4:', intToIPV4( LCardinalValue ), @LCardinalValue,sizeOf(LCardinalValue) ));          
              Inc(aCurrentPos,SizeOf(LCardinalValue));
            end;

            if GetBitValue(LByteValue,2)=1 then
            begin
              LTmpLen :=  LLenIE - (aCurrentPos-LStartPos);

              if LTmpLen > 0 then      
              begin      
                SetLength(LBytes,LTmpLen); 
                Move((aPayload+aCurrentPos )^,LBytes[0],LTmpLen);
                AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.FTEID',[LLabel]), 'F-TEID IPv6:', BytesToStringRaw(LBytes), @LBytes,sizeOf(LBytes) ));
                Inc(aCurrentPos,LTmpLen);
              end;
            end;
            
          end;
          
        GTP_IEI_DELAY_VALUE       : ParserByteValue(aPayload,aStartLevel+2,Format('%s.DelayValue',[LLabel]), 'Delay value:',AListDetail,aCurrentPos);        
        
        GTP_IEI_BEARER_CONTEXT    :; //nothing

        GTP_IEI_CHARGING_ID       : ParserCardinalValue(aPayload,aStartLevel+2,Format('%s.ID',[LLabel]), 'Charging ID:',AListDetail,aCurrentPos);        

        GTP_IEI_IPV6_ADDRESS      : ParserWordValue(aPayload,aStartLevel+2,Format('%s.CharginCharacteristicg',[LLabel]), 'Charging Characteristic:',AListDetail,aCurrentPos);  
              
        GTP_IEI_PDN_TYPE          :
          begin
            LByteValue := PByte(aPayload+aCurrentPos )^; 
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.SpareBits',[LLabel]), 'Spare bits:', LByteValue shr 3, @LByteValue,sizeOf(LByteValue)));     
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.PDNType',[LLabel]), 'PDN Type:', PdnTypeToString((LByteValue  and $07)), @LByteValue,sizeOf(LByteValue),(LByteValue  and $07)));   
            Inc(aCurrentPos,SizeOf(LByteValue));  
          end;

        GTP_IEI_UE_TIME_ZONE:
          begin
            LByteValue := PByte(aPayload+aCurrentPos )^; 
            LTmpStr    := String.Empty;

            if GetBitValue(LByteValue,1) = 0 then
              LTmpStr := '+'
            else
              LTmpStr := '-';

            LWordValue := ((LByteValue shr 4) + ((LByteValue and $07) * 10));            
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Timezone',[LLabel]), 'Timezone:', Format('%s %d hours %d minutes',[LTmpStr,LWordValue div 4,(LWordValue mod 4) * 15]), @LByteValue,sizeOf(LByteValue), LByteValue ));                 
            Inc(aCurrentPos,SizeOf(LByteValue));  
            LByteValue := PByte(aPayload+aCurrentPos )^; 
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.TimeZone.Type',[LLabel]), 'Type:',TimeZoneTypeToString(GetLastNBit(LByteValue,2)), @LByteValue,sizeOf(LByteValue),GetLastNBit(LByteValue,2)));                 
            Inc(aCurrentPos,SizeOf(LByteValue));              
          end;

        GTP_IEI_UDP_PORT          : ParserWordValue(aPayload,aStartLevel+4,Format('%s.UdpPort',[LLabel]), 'UDP port:',AListDetail,aCurrentPos);  

        GTP_IEI_APN_RESTICTION    :
          begin
            LByteValue := PByte(aPayload+aCurrentPos )^; 
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.APNRestriction',[LLabel]), 'APN Restriction:',APNrestrictionToString(LByteValue), @LByteValue,sizeOf(LByteValue), LByteValue ));         
            Inc(aCurrentPos,SizeOf(LByteValue));  
          end;
          
        GTP_IEI_SELECTION_MODE           :
          begin
            LByteValue := PByte(aPayload+aCurrentPos )^; 
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.SelectionMode',[LLabel]), 'Selection mode:',SelectModeToString( LByteValue  and $07), @LByteValue,sizeOf(LByteValue), LByteValue  and $07 ));       
            Inc(aCurrentPos,SizeOf(LByteValue));  
          end;
          

        GTP_IEI_FQDN : 
        Begin
          SetLength(LBytes,LLenIE);
          Move(PByte(aPayload+aCurrentPos)^, LBytes[0], LLenIE);  
          AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.SelectionMode',[LLabel]), 'FQDN:', BytesToString(LBytes), @LBytes,Length(LBytes)));                           
          Inc(aCurrentPos,LlenIE);
        end;
        
        
        GTP_IEI_RECOVERY_RESTART         :  ParserWordValue(aPayload,aStartLevel+2,Format('%s.RestartCounter',[LLabel]), 'Restart counter:',AListDetail,aCurrentPos);  

        GTP_IEI_PRIVATE : 
          begin
            LWordValue := PWord(aPayload+aCurrentPos )^;
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.SequenceNumber',[LLabel]), 'Enterprise ID:', wpcapntohs( LWordValue ), @LWordValue,sizeOf(LWordValue)));
            
            Inc(aCurrentPos,SizeOf(LWordValue));
            SetLength(LBytes,LTmpLen-2); 
            Move(PByte(aPayload+aCurrentPos)^, LBytes[0], LTmpLen-2);
            LTmpStr := String.Empty;
            for I := Low(LBytes) to High(LBytes) do
            begin
              if (LBytes[I] and $0f) <= 9 then        
                LTmpStr := Format('%s%d',[LTmpStr,(LBytes[I] and $0f)]);
          
              if (LBytes[I] shr 4) <= 9 then
                LTmpStr := Format('%s%d',[LTmpStr,(LBytes[I] shr 4)]);
            end;            
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.ProprietaryValue',[LLabel]), 'Proprietary value:',  LTmpStr, @LBytes,sizeOf(LBytes)));          
            Inc(aCurrentPos,LTmpLen-2);            
          end;

        GTP_IEI_TFT          :Inc(aCurrentPos,LlenIE);
        GTP_IEI_SDF_FILTER   :Inc(aCurrentPos,LlenIE);
        GTP_IEI_PCO          :Inc(aCurrentPos,LlenIE);    
        GTP_IEI_SGW_ADDRESS  :Inc(aCurrentPos,LlenIE);
        GTP_IEI_ECGI         :Inc(aCurrentPos,LlenIE);        
        
      else  Inc(aCurrentPos,LlenIE);
      end;  
                  
      if aCurrentPos -3 <= aMaxLen  then
      begin
        if ( aCurrentPos - LStartPos) < LLenIE -3 then
        begin
          LTmpLen := aCurrentPos+ LLenIE - (aCurrentPos-LStartPos);
          ParserIEType(aCurrentPos,LTmpLen,aStartLevel+1,aPayload,AListDetail);
        end;  
      end;
      
    end;
  
  end;
end;


class function TWPcapProtocolGTP.IETypeToLabel(aIEType: Byte): string;
begin
  case aIEType of
    GTP_IEI_IMSI                      : Result := 'Imsi';
    GTP_IEI_CAUSE                     : Result := 'Cause';
    GTP_IEI_RECOVERY_RESTART          : Result := 'RecoveryRestart';
    GTP_IEI_APN                       : Result := 'Apn';
    GTP_IEI_AMBR                      : Result := 'Ambr';
    GTP_EPS_BEARER_ID                 : Result := 'BearerId';
    GTP_IEI_MEI                       : Result := 'MEI';
    GTP_IEI_MSISDN                    : Result := 'Msisdn';
    GTP_IEI_INDICATION                : Result := 'Indication';
    GTP_IEI_PCO                       : Result := 'Pco';
    GTP_IEI_PAA                       : Result := 'Paa';
    GTP_IEI_BEARER_LEVEL_QoS          : Result := 'BearerLevelQos';
    GTP_IEI_RAT_TYPE                  : Result := 'RatType';
    GTP_IEI_SERVING_NETWORK           : Result := 'ServingNetwork';
    GTP_IEI_F_TFT                     : Result := 'BearerTFT';
    GTP_IEI_ULI                       : Result := 'Uli';
    GTP_IEI_F_TEID                    : Result := 'FTeid';
    GTP_IEI_TFT                       : Result := 'Tft';
    GTP_IEI_SDF_FILTER                : Result := 'SdfFilter';
    GTP_IEI_DELAY_VALUE               : Result := 'DelayValue';
    GTP_IEI_BEARER_CONTEXT            : Result := 'BearerContext';
    GTP_IEI_CHARGING_ID               : Result := 'ChargingID'; 
    GTP_IEI_IPV6_ADDRESS              : Result := 'Ipv6Address';
    GTP_IEI_PDN_TYPE                  : Result := 'PdnType';
    GTP_IEI_UE_TIME_ZONE              : Result := 'UeTimeZone';
    GTP_IEI_UDP_PORT                  : Result := 'UDPPort';
    GTP_IEI_APN_RESTICTION            : Result := 'ApnRestiction';
    GTP_IEI_SELECTION_MODE            : Result := 'SelectionMode';
    GTP_IEI_SGW_ADDRESS               : Result := 'SgwAddress';
    GTP_IEI_FQDN                      : Result := 'FQDN';         
    GTP_IEI_ECGI                      : Result := 'Ecgi';
    GTP_IEI_PRIVATE                   : Result := 'Private';
  else
      Result := 'Unknown';
  end;
end;

class function TWPcapProtocolGTP.IETypeToString(aIEType: Byte): string;
begin
  case aIEType of
    GTP_IEI_IMSI                      : Result := 'International Mobile Subscriber Identity (IMSI)';
    GTP_IEI_CAUSE                     : Result := 'Cause';
    GTP_IEI_RECOVERY_RESTART          : Result := 'Recovery (Restart Counter)';        
    GTP_IEI_APN                       : Result := 'Access Point Name (APN)';
    GTP_IEI_AMBR                      : Result := 'Aggregate Maximum Bit Rate (AMBR)';
    GTP_EPS_BEARER_ID                 : Result := 'EPS Bearer ID (EBI)';
    GTP_IEI_MEI                       : Result := 'Mobile Equipment Identity (MEI)';
    GTP_IEI_MSISDN                    : Result := 'MSISDN - (Mobile Station International Subscriber Directory Number)';
    GTP_IEI_INDICATION                : Result := 'Indication';
    GTP_IEI_PCO                       : Result := 'Protocol Configuration Options (PCO)';
    GTP_IEI_PAA                       : Result := 'PDN Address Allocation (PAA)';
    GTP_IEI_BEARER_LEVEL_QoS          : Result := 'Bearer Level Quality of Service (Bearer QoS)';
    GTP_IEI_RAT_TYPE                  : Result := 'RAT Type';
    GTP_IEI_SERVING_NETWORK           : Result := 'Serving Network';
    GTP_IEI_F_TFT                     : Result := 'EPS Bearer Level Traffic Flow Template (Bearer TFT)';
    GTP_IEI_ULI                       : Result := 'User Location Info (ULI)';   
    GTP_IEI_F_TEID                    : Result := 'Fully Qualified Tunnel Endpoint Identifier (F-TEID)';
    GTP_IEI_TFT                       : Result := 'TFT';
    GTP_IEI_SDF_FILTER                : Result := 'Service Data Flow (SDF) Filter';   
    GTP_IEI_DELAY_VALUE               : Result := 'Delay value';              
    GTP_IEI_BEARER_CONTEXT            : Result := 'Bearer Context';
    GTP_IEI_CHARGING_ID               : Result := 'Charging ID';
    GTP_IEI_IPV6_ADDRESS              : Result := 'Charging Characteristics:';
    GTP_IEI_PDN_TYPE                  : Result := 'PDN Type';
    GTP_IEI_UE_TIME_ZONE              : Result := 'UE Time Zone';
    GTP_IEI_UDP_PORT                  : Result := 'UDP Source Port Number';
    GTP_IEI_APN_RESTICTION            : Result := 'APN Restriction';
    GTP_IEI_SELECTION_MODE            : Result := 'Selection Mode';
    GTP_IEI_SGW_ADDRESS               : Result := 'Serving Gateway address';     
    GTP_IEI_FQDN                      : Result := 'Fully Qualified Domain Name (FQDN)';          
    GTP_IEI_ECGI                      : Result := 'E-UTRAN Cell Global Identity (ECGI)';
    GTP_IEI_PRIVATE                   : Result := 'Private Extension';
  else
      Result := 'Unknown';
  end;
end;

class function TWPcapProtocolGTP.MessageTypeToString(aMsgType:Byte):String;
begin
 case aMsgType of  
    GTP_MSG_UNKNOWN            		    	: Result := 'For future use';
    GTP_MSG_ECHO_REQ           		    	: Result := 'Echo request';
    GTP_MSG_ECHO_RESP          		    	: Result := 'Echo response';
    GTP_MSG_VER_NOT_SUPP       		    	: Result := 'Version not supported';
    GTP_MSG_NODE_ALIVE_REQ     		    	: Result := 'Node alive request';
    GTP_MSG_NODE_ALIVE_RESP    		    	: Result := 'Node alive response';
    GTP_MSG_REDIR_REQ          		    	: Result := 'Redirection request';
    GTP_MSG_REDIR_RESP         		    	: Result := 'Redirection response';
    GTP_MSG_CREATE_PDP_REQ            	: Result := 'Create PDP context request';
    GTP_MSG_CREATE_PDP_RESP           	: Result := 'Create PDP context response';
    GTP_MSG_UPDATE_PDP_REQ            	: Result := 'Update PDP context request';
    GTP_MSG_UPDATE_PDP_RESP           	: Result := 'Update PDP context response';
    GTP_MSG_DELETE_PDP_REQ            	: Result := 'Delete PDP context request';
    GTP_MSG_DELETE_PDP_RESP           	: Result := 'Delete PDP context response';
    GTP_MSG_INIT_PDP_CONTEXT_ACT_REQ  	: Result := 'Initiate PDP Context Activation Request';
    GTP_MSG_INIT_PDP_CONTEXT_ACT_RESP 	: Result := 'Initiate PDP Context Activation Response';
    GTP_MSG_DELETE_AA_PDP_REQ   	     	: Result := 'Delete AA PDP Context Request';
    GTP_MSG_DELETE_AA_PDP_RESP  	     	: Result := 'Delete AA PDP Context Response';
    GTP_MSG_ERR_IND             	     	: Result := 'Error indication';
    GTP_MSG_PDU_NOTIFY_REQ      	     	: Result := 'PDU notification request';
    GTP_MSG_PDU_NOTIFY_RESP     	     	: Result := 'PDU notification response';
    GTP_MSG_PDU_NOTIFY_REJ_REQ  	     	: Result := 'PDU notification reject request';
    GTP_MSG_PDU_NOTIFY_REJ_RESP 	     	: Result := 'PDU notification reject response';
    GTP_MSG_SUPP_EXT_HDR        	     	: Result := 'Supported extension header notification';
    GTP_MSG_SEND_ROUT_INFO_REQ  	     	: Result := 'Send routing information for GPRS request';
    GTP_MSG_SEND_ROUT_INFO_RESP 	     	: Result := 'Send routing information for GPRS response';
    GTP_MSG_FAIL_REP_REQ        	     	: Result := 'Failure report request';
    GTP_MSG_FAIL_REP_RESP       	     	: Result := 'Failure report response';
    GTP_MSG_MS_PRESENT_REQ      	     	: Result := 'Note MS GPRS present request';
    GTP_MSG_MS_PRESENT_RESP     	     	: Result := 'Note MS GPRS present response';
    GTP_MSG_IDENT_REQ           	     	: Result := 'Identification request';
    GTP_MSG_IDENT_RESP          	     	: Result := 'Identification response';
    GTP_MSG_SGSN_CNTXT_REQ      	     	: Result := 'SGSN context request';
    GTP_MSG_SGSN_CNTXT_RESP     	     	: Result := 'SGSN context response';
    GTP_MSG_SGSN_CNTXT_ACK      	     	: Result := 'SGSN context acknowledgement';
    GTP_MSG_FORW_RELOC_REQ      	     	: Result := 'Forward relocation request';
    GTP_MSG_FORW_RELOC_RESP     	     	: Result := 'Forward relocation response';
    GTP_MSG_FORW_RELOC_COMP     	     	: Result := 'Forward relocation complete';
    GTP_MSG_RELOC_CANCEL_REQ    	     	: Result := 'Relocation cancel request';
    GTP_MSG_RELOC_CANCEL_RESP   	     	: Result := 'Relocation cancel response';
    GTP_MSG_FORW_SRNS_CNTXT     	     	: Result := 'Forward SRNS context';
    GTP_MSG_FORW_RELOC_ACK      	     	: Result := 'Forward relocation complete acknowledge';
    GTP_MSG_FORW_SRNS_CNTXT_ACK 	     	: Result := 'Forward SRNS context acknowledge';
    GTP_MSG_UE_REG_QUERY_REQ    	     	: Result := 'UE Registration Query Request';
    GTP_MSG_UE_REG_QUERY_RESP   	     	: Result := 'UE Registration Query Response';
    GTP_MSG_RAN_INFO_RELAY      	     	: Result := 'RAN Information Relay';
    GTP_MBMS_NOTIFY_REQ         	     	: Result := 'MBMS Notification Request';
    GTP_MBMS_NOTIFY_RES         	     	: Result := 'MBMS Notification Response';
    GTP_MBMS_NOTIFY_REJ_REQ     	     	: Result := 'MBMS Notification Reject Request';
    GTP_MBMS_NOTIFY_REJ_RES     	     	: Result := 'MBMS Notification Reject Response';
    GTP_CREATE_MBMS_CNTXT_REQ   	     	: Result := 'Create MBMS Context Request';
    GTP_CREATE_MBMS_CNTXT_RES   	     	: Result := 'Create MBMS Context Response';
    GTP_UPD_MBMS_CNTXT_REQ      	     	: Result := 'Update MBMS Context Request';
    GTP_UPD_MBMS_CNTXT_RES      	     	: Result := 'Update MBMS Context Response';
    GTP_DEL_MBMS_CNTXT_REQ      	     	: Result := 'Delete MBMS Context Request';
    GTP_DEL_MBMS_CNTXT_RES      	     	: Result := 'Delete MBMS Context Response';
    GTP_MBMS_REG_REQ            	     	: Result := 'MBMS Registration Request';
    GTP_MBMS_REG_RES            	     	: Result := 'MBMS Registration Response';
    GTP_MBMS_DE_REG_REQ         	     	: Result := 'MBMS De-Registration Request';
    GTP_MBMS_DE_REG_RES         	     	: Result := 'MBMS De-Registration Response';
    GTP_MBMS_SES_START_REQ      	     	: Result := 'MBMS Session Start Request';
    GTP_MBMS_SES_START_RES      	     	: Result := 'MBMS Session Start Response';
    GTP_MBMS_SES_STOP_REQ       	     	: Result := 'MBMS Session Stop Request';
    GTP_MBMS_SES_STOP_RES       	     	: Result := 'MBMS Session Stop Response';
    GTP_MBMS_SES_UPD_REQ        	     	: Result := 'MBMS Session Update Request';
    GTP_MBMS_SES_UPD_RES        	     	: Result := 'MBMS Session Update Response';
    GTP_MS_INFO_CNG_NOT_REQ     	     	: Result := 'MS Info Change Notification Request';
    GTP_MS_INFO_CNG_NOT_RES     	     	: Result := 'MS Info Change Notification Response';
    GTP_MSG_DATA_TRANSF_REQ     	     	: Result := 'Data record transfer request';
    GTP_MSG_DATA_TRANSF_RESP    	     	: Result := 'Data record transfer response';
    GTP_MSG_END_MARKER          	     	: Result := 'End Marker';
    GTP_MSG_TPDU                	     	: Result := 'T-PDU';
 
  else
      Result := 'Unknown';
  end;
end;

class function TWPcapProtocolGTP.ProtoTypeToString(const aProtoType:Byte): String;
begin
  case aProtoType of
    1 : Result := 'GTP-U';
    2 : Result := 'GTP-C';
    3 : Result := 'GTP';
  else
      Result := 'Unknown';
  end;
end;

class function TWPcapProtocolGTP.CauseToString(const aCause : Byte):String;
begin
  case aCause of
      0 : Result := 'Reserved';   
      1 : Result := 'Reserved';
      2 : Result := 'Local Detach';
      3 : Result := 'Complete Detach';
      4 : Result := 'RAT changed from 3GPP to Non-3GPP';
      5 : Result := 'ISR deactivation';
      6 : Result := 'Error Indication received from RNC/eNodeB/S4-SGSN';
      7 : Result := 'IMSI Detach Only';
      8 : Result := 'Reactivation Requested';
      9 : Result := 'PDN reconnection to this APN disallowed';
     10 : Result := 'Access changed from Non-3GPP to 3GPP';
     11 : Result := 'PDN connection inactivity timer expires';
     12 : Result := 'PGW not responding';
     13 : Result := 'Network Failure';
     14 : Result := 'QoS parameter mismatch';
     15 : Result := 'EPS to 5GS Mobility';    
     16 : Result := 'Request accepted';
     17 : Result := 'Request accepted partially';
     18 : Result := 'New PDN type due to network preference';
     19 : Result := 'New PDN type due to single address bearer only';    
     20 : Result := 'Spare';
     21 : Result := 'Spare';
     22 : Result := 'Spare';
     23 : Result := 'Spare';
     24 : Result := 'Spare';
     25 : Result := 'Spare';
     26 : Result := 'Spare';
     27 : Result := 'Spare';
     28 : Result := 'Spare';
     29 : Result := 'Spare';
     30 : Result := 'Spare';
     31 : Result := 'Spare';
     32 : Result := 'Spare';
     33 : Result := 'Spare';
     34 : Result := 'Spare';
     35 : Result := 'Spare';
     36 : Result := 'Spare';
     37 : Result := 'Spare';
     38 : Result := 'Spare';
     39 : Result := 'Spare';
     40 : Result := 'Spare';
     41 : Result := 'Spare';
     42 : Result := 'Spare';
     43 : Result := 'Spare';
     44 : Result := 'Spare';
     45 : Result := 'Spare';
     46 : Result := 'Spare';
     47 : Result := 'Spare';
     48 : Result := 'Spare';
     49 : Result := 'Spare';
     50 : Result := 'Spare';
     51 : Result := 'Spare';
     52 : Result := 'Spare';
     53 : Result := 'Spare';
     54 : Result := 'Spare';
     55 : Result := 'Spare';
     56 : Result := 'Spare';
     57 : Result := 'Spare';
     58 : Result := 'Spare';
     59 : Result := 'Spare';
     60 : Result := 'Spare';
     61 : Result := 'Spare';
     62 : Result := 'Spare';
     63 : Result := 'Spare';   
     64 : Result := 'Context Not Found';
     65 : Result := 'Invalid Message Format';
     66 : Result := 'Version not supported by next peer';
     67 : Result := 'Invalid length';
     68 : Result := 'Service not supported';
     69 : Result := 'Mandatory IE incorrect';
     70 : Result := 'Mandatory IE missing';
     71 : Result := 'Shall not be used';
     72 : Result := 'System failure';
     73 : Result := 'No resources available';
     74 : Result := 'Semantic error in the TFT operation';
     75 : Result := 'Syntactic error in the TFT operation';
     76 : Result := 'Semantic errors in packet filter(s)';
     77 : Result := 'Syntactic errors in packet filter(s)';
     78 : Result := 'Missing or unknown APN';
     79 : Result := 'Shall not be used';
     80 : Result := 'GRE key not found';
     81 : Result := 'Relocation failure';
     82 : Result := 'Denied in RAT';
     83 : Result := 'Preferred PDN type not supported';
     84 : Result := 'All dynamic addresses are occupied';
     85 : Result := 'UE context without TFT already activated';
     86 : Result := 'Protocol type not supported';
     87 : Result := 'UE not responding';
     88 : Result := 'UE refuses';
     89 : Result := 'Service denied';
     90 : Result := 'Unable to page UE';
     91 : Result := 'No memory available';
     92 : Result := 'User authentication failed';
     93 : Result := 'APN access denied - no subscription';
     94 : Result := 'Request rejected(reason not specified)';
     95 : Result := 'P-TMSI Signature mismatch';
     96 : Result := 'IMSI/IMEI not known';
     97 : Result := 'Semantic error in the TAD operation';
     98 : Result := 'Syntactic error in the TAD operation';
     99 : Result := 'Shall not be used';
    100 : Result := 'Remote peer not responding';
    101 : Result := 'Collision with network initiated request';
    102 : Result := 'Unable to page UE due to Suspension';
    103 : Result := 'Conditional IE missing';
    104 : Result := 'APN Restriction type Incompatible with currently active PDN connection';
    105 : Result := 'Invalid overall length of the triggered response message and a piggybacked initial message';
    106 : Result := 'Data forwarding not supported';
    107 : Result := 'Invalid reply from remote peer';
    108 : Result := 'Fallback to GTPv1';
    109 : Result := 'Invalid peer';
    110 : Result := 'Temporarily rejected due to handover/TAU/RAU procedure in progress';
    111 : Result := 'Modifications not limited to S1-U bearers';
    112 : Result := 'Request rejected for a PMIPv6 reason ';
    113 : Result := 'APN Congestion';
    114 : Result := 'Bearer handling not supported';
    115 : Result := 'UE already re-attached';
    116 : Result := 'Multiple PDN connections for a given APN not allowed';
    117 : Result := 'Target access restricted for the subscriber';
    118 : Result := 'Shall not be used. See NOTE 2 and NOTE 3.';
    119 : Result := 'MME/SGSN refuses due to VPLMN Policy';
    120 : Result := 'GTP-C Entity Congestion';
    121 : Result := 'Late Overlapping Request';
    122 : Result := 'Timed out Request';
    123 : Result := 'UE is temporarily not reachable due to power saving';
    124 : Result := 'Relocation failure due to NAS message redirection';
    125 : Result := 'UE not authorised by OCS or external AAA Server';
    126 : Result := 'Multiple accesses to a PDN connection not allowed';
    127 : Result := 'Request rejected due to UE capability';
    128 : Result := 'S1-U Path Failure';
    129 : Result := '5GC not allowed';
    130 : Result := 'PGW mismatch with network slice subscribed by the UE';
    131 : Result := 'Rejection due to paging restriction';
  else
      Result := 'Unknown';       
  end; 
end;

class function TWPcapProtocolGTP.CauseToString_vals(const aCause : Byte):String;
begin
  case aCause of
    0   : Result := 'Reserved';
    1   : Result := 'Unspecified';
    2   : Result := 'Handover/Relocation cancelled by source system ';
    3   : Result := 'Handover /Relocation Failure with Target system';
    4   : Result := 'Handover/Relocation Target not allowed';
    5   : Result := 'Unknown Target ID';
    6   : Result := 'Target Cell not available';
    7   : Result := 'No Radio Resources Available in Target Cell';
    8   : Result := 'Failure in Radio Interface Procedure';
    9   : Result := 'Permanent session leg establishment error';
    10  : Result := 'Temporary session leg establishment error';
  else
      Result := 'Unknown';           
  end;
end;

class function TWPcapProtocolGTP.RatToString(const aRat : Byte):String;
begin
  case aRat of
    0  : Result := 'Reserved';
    1  : Result := 'UTRAN';
    2  : Result := 'GERAN';
    3  : Result := 'WLAN';
    4  : Result := 'GAN';
    5  : Result := 'HSPA Evolution';
    6  : Result := 'EUTRAN';
    7  : Result := 'Virtual';
    8  : Result := 'EUTRAN-NB-IoT';
    9  : Result := 'LTE-M';
    10 : Result := 'NR';
    11 : Result := 'WB-E-UTRAN(LEO)';
    12 : Result := 'WB-E-UTRAN(MEO)';
    13 : Result := 'WB-E-UTRAN(GEO)';
    14 : Result := 'WB-E-UTRAN(OTHERSAT)';
    15 : Result := 'EUTRAN-NB-IoT(LEO)';
    16 : Result := 'EUTRAN-NB-IoT(MEO)';
    17 : Result := 'EUTRAN-NB-IoT(GEO)';
    18 : Result := 'EUTRAN-NB-IoT(OTHERSAT)';
    19 : Result := 'LTE-M(LEO)';
    20 : Result := 'LTE-M(MEO)';
    21 : Result := 'LTE-M(GEO)';
    22 : Result := 'LTE-M(OTHERSAT)';
  else
      Result := 'Unknown';           
  end;
end;

class function TWPcapProtocolGTP.InterfaceTypeToString(const aType : Byte):String;
begin
  case aType of
     0 : Result := 'S1-U eNodeB GTP-U interface';
     1 : Result := 'S1-U SGW GTP-U interface';
     2 : Result := 'S12 RNC GTP-U interface';
     3 : Result := 'S12 SGW GTP-U interface';
     4 : Result := 'S5/S8 SGW GTP-U interface';
     5 : Result := 'S5/S8 PGW GTP-U interface';
     6 : Result := 'S5/S8 SGW GTP-C interface';
     7 : Result := 'S5/S8 PGW GTP-C interface';
     8 : Result := 'S5/S8 SGW PMIPv6 interface'; 
     9 : Result := 'S5/S8 PGW PMIPv6 interface';
    10 : Result := 'S11 MME GTP-C interface';
    11 : Result := 'S11/S4 SGW GTP-C interface';
    12 : Result := 'S10 MME GTP-C interface';
    13 : Result := 'S3 MME GTP-C interface';
    14 : Result := 'S3 SGSN GTP-C interface';
    15 : Result := 'S4 SGSN GTP-U interface';
    16 : Result := 'S4 SGW GTP-U interface';
    17 : Result := 'S4 SGSN GTP-C interface';
    18 : Result := 'S16 SGSN GTP-C interface';
    19 : Result := 'eNodeB/gNodeB GTP-U interface for DL data forwarding';
    20 : Result := 'eNodeB GTP-U interface for UL data forwarding';
    21 : Result := 'RNC GTP-U interface for data forwarding';
    22 : Result := 'SGSN GTP-U interface for data forwarding';
    23 : Result := 'SGW GTP-U interface for data forwarding';
    24 : Result := 'Sm MBMS GW GTP-C interface';
    25 : Result := 'Sn MBMS GW GTP-C interface';
    26 : Result := 'Sm MME GTP-C interface';
    27 : Result := 'Sn SGSN GTP-C interface';
    28 : Result := 'SGW GTP-U interface for UL data forwarding';
    29 : Result := 'Sn SGSN GTP-U interface';
    30 : Result := 'S2b ePDG GTP-C interface';
    31 : Result := 'S2b-U ePDG GTP-U interface';
    32 : Result := 'S2b PGW GTP-C interface';
    33 : Result := 'S2b-U PGW GTP-U interface';
    34 : Result := 'S2a TWAN GTP-U interface';
    35 : Result := 'S2a TWAN GTP-C interface';
    36 : Result := 'S2a PGW GTP-C interface';
    37 : Result := 'S2a PGW GTP-U interface';
    38 : Result := 'S11 MME GTP-U interface';
    39 : Result := 'S11 SGW GTP-U interface';
    40 : Result := 'N26 AMF GTP-C interface';
    41 : Result := 'N19mb UPF GTP-U interface';
  else
      Result := 'Unknown';           
  end;
end;

class function TWPcapProtocolGTP.PdnTypeToString(const aType : Byte):String;
begin
  case aType of
    1 : Result := 'IPv4';
    2 : Result := 'IPv6';
    3 : Result := 'IPv4/IPv6';
    4 : Result := 'Non-IP';
    5 : Result := 'Ethernet';
  else
      Result := 'Unknown';           
  end;
end;

class function TWPcapProtocolGTP.SelectModeToString(const aMode : Byte):String;
begin
  case aMode of
    0: Result := 'MS or network provided APN, subscribed verified';
    1: Result := 'MS provided APN, subscription not verified';
    2: Result := 'Network provided APN, subscription not verified';
    3: Result := 'Network provided APN, subscription not verified (Basically for Future use';
  else
      Result := 'Unknown';           
  end;
end;

class function TWPcapProtocolGTP.APNrestrictionToString(const aRest : Byte):String;
begin
  case aRest of
    0: Result := 'No Existing Contexts or Restriction';
    1: Result := 'Public-1';
    2: Result := 'Public-2';
    3: Result := 'Private-1';
    4: Result := 'Private-2';
  else
      Result := 'Unknown';           
  end;
end;

class function TWPcapProtocolGTP.TimeZoneTypeToString(const aRest : Byte):String;
begin
  case aRest of
    0: Result := 'No Adjustments for Daylight Saving Time';
    1: Result := '+1 Hour Adjustments for Daylight Saving Time';
    2: Result := '+2 Hour Adjustments for Daylight Saving Time';
    3: Result := 'Spare"';
  else
      Result := 'Unknown';           
  end;
end;

class function TWPcapProtocolGTP.MessageTypeV2ToString(const aMsgType : Byte):String;
begin
  case aMsgType of
      0 : Result := 'Reserved';
      1 : Result := 'Echo Request';
      2 : Result := 'Echo Response';
      3 : Result := 'Version Not Supported Indication';
      4 : Result := 'Node Alive Request';
      5 : Result := 'Node Alive Response';
      6 : Result := 'Redirection Request';
      7 : Result := 'Redirection Response';
     25 : Result := 'SRVCC PS to CS Request';
     26 : Result := 'SRVCC PS to CS Response';
     27 : Result := 'SRVCC PS to CS Complete Notification';
     28 : Result := 'SRVCC PS to CS Complete Acknowledge';
     29 : Result := 'SRVCC PS to CS Cancel Notification';
     30 : Result := 'SRVCC PS to CS Cancel Acknowledge';
     31 : Result := 'SRVCC CS to PS Request';
     32 : Result := 'Create Session Request';
     33 : Result := 'Create Session Response';
     34 : Result := 'Modify Bearer Request';
     35 : Result := 'Modify Bearer Response';
     36 : Result := 'Delete Session Request';
     37 : Result := 'Delete Session Response';   
     38 : Result := 'Change Notification Request';
     39 : Result := 'Change Notification Response';    
     40 : Result := 'Remote UE Report Notification';
     41 : Result := 'Remote UE Report Acknowledge';
     64 : Result := 'Modify Bearer Command';                          
     65 : Result := 'Modify Bearer Failure Indication';               
     66 : Result := 'Delete Bearer Command';                          
     67 : Result := 'Delete Bearer Failure Indication';               
     68 : Result := 'Bearer Resource Command';                        
     69 : Result := 'Bearer Resource Failure Indication';             
     70 : Result := 'Downlink Data Notification Failure Indication';  
     71 : Result := 'Trace Session Activation';
     72 : Result := 'Trace Session Deactivation';
     73 : Result := 'Stop Paging Indication';
     95 : Result := 'Create Bearer Request';
     96 : Result := 'Create Bearer Response';
     97 : Result := 'Update Bearer Request';
     98 : Result := 'Update Bearer Response';
     99 : Result := 'Delete Bearer Request';
    100 : Result := 'Delete Bearer Response';    
    101 : Result := 'Delete PDN Connection Set Request';
    102 : Result := 'Delete PDN Connection Set Response';    
    103 : Result := 'PGW Downlink Triggering Notification';
    104 : Result := 'PGW Downlink Triggering Acknowledge';
    128 : Result := 'Identification Request';
    129 : Result := 'Identification Response';
    130 : Result := 'Context Request';
    131 : Result := 'Context Response';
    132 : Result := 'Context Acknowledge';
    133 : Result := 'Forward Relocation Request';
    134 : Result := 'Forward Relocation Response';
    135 : Result := 'Forward Relocation Complete Notification';
    136 : Result := 'Forward Relocation Complete Acknowledge';
    137 : Result := 'Forward Access Context Notification';
    138 : Result := 'Forward Access Context Acknowledge';
    139 : Result := 'Relocation Cancel Request';
    140 : Result := 'Relocation Cancel Response';
    141 : Result := 'Configuration Transfer Tunnel';
    149 : Result := 'Detach Notification';
    150 : Result := 'Detach Acknowledge';
    151 : Result := 'CS Paging Indication';
    152 : Result := 'RAN Information Relay';
    153 : Result := 'Alert MME Notification';
    154 : Result := 'Alert MME Acknowledge';
    155 : Result := 'UE Activity Notification';
    156 : Result := 'UE Activity Acknowledge';
    157 : Result := 'ISR Status Indication';
    158 : Result := 'UE Registration Query Request';
    159 : Result := 'UE Registration Query Response';    
    160 : Result := 'Create Forwarding Tunnel Request';
    161 : Result := 'Create Forwarding Tunnel Response';
    162 : Result := 'Suspend Notification';
    163 : Result := 'Suspend Acknowledge';
    164 : Result := 'Resume Notification';
    165 : Result := 'Resume Acknowledge';
    166 : Result := 'Create Indirect Data Forwarding Tunnel Request';
    167 : Result := 'Create Indirect Data Forwarding Tunnel Response';
    168 : Result := 'Delete Indirect Data Forwarding Tunnel Request';
    169 : Result := 'Delete Indirect Data Forwarding Tunnel Response';
    170 : Result := 'Release Access Bearers Request';
    171 : Result := 'Release Access Bearers Response';
    176 : Result := 'Downlink Data Notification';
    177 : Result := 'Downlink Data Notification Acknowledgement';
    178 : Result := 'Reserved. Allocated in earlier version of the specification.';
    179 : Result := 'PGW Restart Notification';
    180 : Result := 'PGW Restart Notification Acknowledge';
    200 : Result := 'Update PDN Connection Set Request';
    201 : Result := 'Update PDN Connection Set Response';
    211 : Result := 'Modify Access Bearers Request';
    212 : Result := 'Modify Access Bearers Response';
    231 : Result := 'MBMS Session Start Request';
    232 : Result := 'MBMS Session Start Response';
    233 : Result := 'MBMS Session Update Request';
    234 : Result := 'MBMS Session Update Response';
    235 : Result := 'MBMS Session Stop Request';
    236 : Result := 'MBMS Session Stop Response';
    240 : Result := 'SRVCC CS to PS Response';              
    241 : Result := 'SRVCC CS to PS Complete Notification'; 
    242 : Result := 'SRVCC CS to PS Complete Acknowledge';  
    243 : Result := 'SRVCC CS to PS Cancel Notification';   
    244 : Result := 'SRVCC CS to PS Cancel Acknowledge';    
  else
      Result := 'Unknown';           
  end;
end;



end.
                                                 
