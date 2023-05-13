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

unit wpcap.Protocol.TLS;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, Wpcap.protocol.TCP, wpcap.StrUtils,system.Variants,idGlobal,System.Math, wpcap.packet,
  wpcap.Types, Vcl.Dialogs, System.StrUtils, System.Classes,system.SysUtils,wpcap.BufferUtils;
  
type  
  TTLSRecordHeader = packed record
    ContentType    : Uint8;
    ProtocolVersion: Uint16;
    Length         : Uint16;
  end;
  PTTLSRecordHeader = ^TTLSRecordHeader;

  PTLSRandom = ^TLSRandom;
  TLSRandom = record
    UnixTime   : UInt32;
    RandomBytes: array[0..27] of Uint8;
  end;
  
  /// <summary>
  ///  Implements a TLS protocol handler to interpret and validate TLS protocol.
  /// </summary>
  TWPcapProtocolTLS = Class(TWPcapProtocolBaseTCP)
  private

    {TLS}
    CONST
    TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC      = $14;
    TLS_CONTENT_TYPE_ALERT                   = $15;
    TLS_CONTENT_TYPE_HANDSHAKE               = $16;
    TLS_CONTENT_TYPE_APPLICATION_DATA        = $17;
    TLS_CONTENT_TYPE_ID_HEARTBEAT            = $18;
    TLS_CONTENT_TYPE_ID_TLS12_CID            = $19;    

    {Handshake}    
    TLS_HANDSHAKE_TYPE_HELLO_REQUEST          = 0;
    TLS_HANDSHAKE_TYPE_CLIENT_HELLO           = 1;
    TLS_HANDSHAKE_TYPE_SERVER_HELLO           = 2;
    TLS_HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST   = 3;
    TLS_HANDSHAKE_TYPE_NEWSESSION_TICKET      = 4;
    TLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA      = 5;
    TLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST    = 6;
    TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS   = 8;    
    TLS_HANDSHAKE_TYPE_CERTIFICATE            = 11;
    TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE    = 12;
    TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST    = 13;
    TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE      = 14;
    TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY     = 15;
    TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE    = 16;
    TLS_HANDSHAKE_TYPE_FINISHED               = 20;
    TLS_HANDSHAKE_TYPE_CERT_URL               = 21;
    TLS_HANDSHAKE_TYPE_CERT_STATUS            = 22;
    TLS_HANDSHAKE_TYPE_SUPPLEMENTAL_DATA      = 23;
    TLS_HANDSHAKE_TYPE_KEY_UPDATE             = 24;
    TLS_HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE = 25;
    TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTS         = 67;  

    {Extensions}
    TLS_EXTENSION_TYPE_SERVER_NAME            = 0;
    TLS_EXTENSION_TYPE_MAX_FRAGMENT_LENGTH    = 1;
    TLS_EXTENSION_TYPE_CLIENT_CERTIFICATE_URL = 2;
    TLS_EXTENSION_TYPE_TRUSTED_CA_KEYS        = 3;
    TLS_EXTENSION_TYPE_TRUNCATED_HMAC         = 4;
    TLS_EXTENSION_TYPE_STATUS_REQUEST         = 5;
    TLS_EXTENSION_TYPE_USER_MAPPING           = 6;
    TLS_EXTENSION_TYPE_CLIENT_AUTHZ           = 7;
    TLS_EXTENSION_TYPE_SERVER_AUTHZ           = 8;
    TLS_EXTENSION_TYPE_CERT_TYPE              = 9;
    TLS_EXTENSION_TYPE_SUPPORTED_GROUPS       = 10;
    TLS_EXTENSION_TYPE_EC_POINT_FORMATS       = 11;
    TLS_EXTENSION_TYPE_SRP                    = 12;
    TLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS   = 13;
    TLS_EXTENSION_TYPE_USE_SRTP               = 14;
    TLS_EXTENSION_TYPE_HEARTBEAT              = 15;
    TLS_EXTENSION_TYPE_APP_PROTO_NEGOTIATION  = 16;
    TLS_EXTENSION_TYPE_STATUS_REQUEST_V2      = 17;
    TLS_EXTENSION_TYPE_SIGNED_CERT_TIMESTAMP  = 18;
    TLS_EXTENSION_TYPE_CLIENT_CERT_TYPE       = 19;
    TLS_EXTENSION_TYPE_SERVER_CERT_TYPE       = 20;
    TLS_EXTENSION_TYPE_PADDING                = 21;
    TLS_EXTENSION_TYPE_ENCRYPT_THEN_MAC       = 22;
    TLS_EXTENSION_TYPE_EXTENDED_MASTER_SECRET = 23;
    TLS_EXTENSION_TYPE_TOKEN_BINDING          = 24;
    TLS_EXTENSION_TYPE_CACHED_INFO            = 25;
    TLS_EXTENSION_TYPE_SESSION_TICKET         = 35;
    TLS_EXTENSION_TYPE_PRE_SHARED_KEY         = 41;    
    TLS_EXTENSION_TYPE_SUPPORTED_VERSION      = 43;
    TLS_EXTENSION_TYPE_PSK_EXCHANGE_MODES     = 45;
    TLS_EXTENSION_TYPE_KEY_SHARE              = 51;
    TLS_EXTENSION_TYPE_RESERVED_GREESE        = 14906;
    TLS_EXTENSION_TYPE_RESERVED_GREESE_2      = 35466;    
    TLS_EXTENSION_TYPE_RENEGOTIATION_INFO     = 65281;

    {TLS version}    
    SSLV2_VERSION                             = $0002;
    SSLV3_VERSION                             = $0300;
    TLCPV1_VERSION                            = $101;
    TLS_VERSION_1_0                           = $103; 
    TLS_VERSION_1_1                           = $0302;
    TLS_VERSION_1_2                           = $0303;
    TLS_VERSION_1_3                           = $0304;
    DTLSV1DOT0_VERSION                        = $feff;
    DTLSV1DOT0_OPENSSL_VERSION                = $100;
    DTLSV1DOT2_VERSION                        = $fefd;
    DTLSV1DOT3_VERSION                        = $fefc;      
    class function ContentTypeToString(aContentType: Byte): string; static;
    class function TLSVersionToString(const aVersion: Uint16): string;
    class function Header(const aUDPPayLoad: PByte): PTTLSRecordHeader; static;
    class function KnowVersion(aVersion: Word): Boolean; static;
    class function ChipherToString(const aChipher: Uint16): string;
    class function HandShakeTypeToString(const aRecodType: Uint8): string;
    class function CompressionToString(const aCompression: Uint8): String;
    class function isHTTPS(const aHandshakeType: Uint8): Boolean; static;
    class function TLSExtensionToString(const aExtensionType: Uint16): string;
    class function SignatureAlgorithmToString(const aValue: Uint16): string;
    class function SupportedGroupToString(const aValue: Uint16): string;
  public
    /// <summary>
    ///  Returns the default port number for the TLS protocol (443).
    /// </summary>
    class Function DefaultPort: Word; override;

    /// <summary>
    /// Return Intenal protocol ID
    /// </summary>
    class function IDDetectProto: byte; override;
    
    /// <summary>
    ///  Returns the acronym name of the TLS protocol ("TLS").
    /// </summary>
    class function AcronymName: String; override;

    /// <summary>
    ///  Returns the protocol name of the TLS protocol ("Transport Layer Security,").
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the header length of the TLS protocol.
    /// </summary>
    class function HeaderLength(aFlag:Byte): Word; override;
    /// <summary>
    /// Checks whether the packet is valid for the TLS protocol.
    /// </summary>
    class function IsValid(const aPacket:PByte;aPacketSize:Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean; override; 
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean;override;       
End;


implementation

{ TWPcapProtocolTLS }

class function TWPcapProtocolTLS.Header(const aUDPPayLoad: PByte): PTTLSRecordHeader;
begin
  Result := PTTLSRecordHeader(aUDPPayLoad)
end;

class function TWPcapProtocolTLS.IsValid(const aPacket:PByte;aPacketSize:Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var LTCPHdr       : PTCPHdr;
    LTCPPayLoad   : PByte;
    LRecord       : PTTLSRecordHeader;
    LTCPPayLoadLen: Integer;
    LContectLen   : Integer;
    LDummy        : Integer;
    LHandshakeType: Byte;
begin
  Result := False;
  if not HeaderTCP(aPacket,aPacketSize,LTCPHdr) then exit;
                                                      //114  18292  
  LTCPPayLoad     := inherited GetPayLoad(aPacket,aPacketSize,LTCPPayLoadLen,LDummy);
  LRecord         := Header(LTCPPayLoad);
  LContectLen     := wpcapntohs(LRecord.Length);
  if KnowVersion(LRecord.ProtocolVersion) then
    Result := (LContectLen > 0)  and ( LContectLen <= LTCPPayLoadLen ) and InRange(LRecord.ContentType,TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC,TLS_CONTENT_TYPE_ID_TLS12_CID);
    
  if not Result then 
  begin  
    aAcronymName     := inherited AcronymName; 
    aIdProtoDetected := inherited IDDetectProto;
    Exit;  
  end;

  if IsValidByPort(PROTO_SMTPS_PORT,SrcPort(LTCPHdr),DstPort(LTCPHdr),aAcronymName,aIdProtoDetected) or
     IsValidByPort(PROTO_SMTPS_PORT_2,SrcPort(LTCPHdr),DstPort(LTCPHdr),aAcronymName,aIdProtoDetected)
   then
    aAcronymName := 'SMTPs'      
  else if IsValidByPort(PROTO_POP3S_PORT,SrcPort(LTCPHdr),DstPort(LTCPHdr),aAcronymName,aIdProtoDetected) then
    aAcronymName := 'POP3s'  
  else if IsValidByPort(PROTO_IMAPS_PORT,SrcPort(LTCPHdr),DstPort(LTCPHdr),aAcronymName,aIdProtoDetected) then
    aAcronymName := 'IMAPs'  
  else if (LRecord.ContentType = TLS_CONTENT_TYPE_HANDSHAKE) then
  begin
    LHandshakeType := LTCPPayLoad[SizeOf(TTLSRecordHeader)];

    if isHTTPS(LHandshakeType) then {TODO search HTTP on payload string and check TLS extention like server_name or status request}
      aAcronymName := 'HTTPS'
    else
      aAcronymName := TLSVersionToString(LRecord.ProtocolVersion);          
  end
  else 
    aAcronymName     := TLSVersionToString(LRecord.ProtocolVersion);
    
  aIdProtoDetected := IDDetectProto;

  if wpcapntohs(LRecord.Length) > LTCPPayLoadLen then
    aAcronymName := 'SSL';
end;

Class function TWPcapProtocolTLS.isHTTPS(const aHandshakeType: Uint8):Boolean;
begin
  Result := (aHandshakeType = TLS_HANDSHAKE_TYPE_CLIENT_HELLO) or (aHandshakeType = TLS_HANDSHAKE_TYPE_SERVER_HELLO)  or (aHandshakeType = TLS_HANDSHAKE_TYPE_CERTIFICATE)
end;

class function TWPcapProtocolTLS.DefaultPort: Word;
begin
  Result := PROTO_TLS_PORT;
end;

class function TWPcapProtocolTLS.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_TLS;
end;

class function TWPcapProtocolTLS.AcronymName: String;
begin
  Result := 'TLS';
end;

class function TWPcapProtocolTLS.ProtoName: String;
begin
  Result := 'Transport Layer Security';
end;

class function TWPcapProtocolTLS.HeaderLength(aFlag:Byte): word;
begin
  Result := SizeOF(TTLSRecordHeader)
end;

class function TWPcapProtocolTLS.HandShakeTypeToString(const aRecodType: Uint8): string;
begin
  case aRecodType of
    TLS_HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST   : Result := 'Hello verifty request';
    TLS_HANDSHAKE_TYPE_NEWSESSION_TICKET      : Result := 'New session ticket';
    TLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA      : Result := 'End of early data';   
    TLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST    : Result := 'Hello retry request';   
    TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS   : Result := 'Encrypted extensions';
    TLS_HANDSHAKE_TYPE_HELLO_REQUEST          : Result := 'Hello request';
    TLS_HANDSHAKE_TYPE_CLIENT_HELLO           : Result := 'Client hello';
    TLS_HANDSHAKE_TYPE_SERVER_HELLO           : Result := 'Server hello';    
    TLS_HANDSHAKE_TYPE_CERTIFICATE            : Result := 'Certificate';    
    TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE    : Result := 'Server key exchange';
    TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST    : Result := 'Certificate request';
    TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE      : Result := 'Server hello done'; 
    TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY     : Result := 'Certificate verify';
    TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE    : Result := 'Client key exchange';
    TLS_HANDSHAKE_TYPE_FINISHED               : Result := 'Finished';
    TLS_HANDSHAKE_TYPE_CERT_URL               : Result := 'Certificate URL';
    TLS_HANDSHAKE_TYPE_CERT_STATUS            : Result := 'Certificate status';   
    TLS_HANDSHAKE_TYPE_SUPPLEMENTAL_DATA      : Result := 'Supplemental data';
    TLS_HANDSHAKE_TYPE_KEY_UPDATE             : Result := 'Key update data';   
    TLS_HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE : Result := 'Compressed cerificate';
    TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTS         : Result := 'Encrypted extensions';    
  else
    Result := Format('Unknown (%d)', [aRecodType]);
  end;

end;

class function TWPcapProtocolTLS.ContentTypeToString(aContentType: Byte): string;
begin
  case aContentType of
    TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC       : Result := 'Change cipher spec';
    TLS_CONTENT_TYPE_ALERT                    : Result := 'Alert';
    TLS_CONTENT_TYPE_HANDSHAKE                : Result := 'Handshake';
    TLS_CONTENT_TYPE_APPLICATION_DATA         : Result := 'Application data'; 
    TLS_CONTENT_TYPE_ID_HEARTBEAT             : Result := 'Heartbeat';
    TLS_CONTENT_TYPE_ID_TLS12_CID             : Result := 'Connection ID';    
  else
    Result := Format('Unknown (%d)', [aContentType]);
  end;
end;       

class function TWPcapProtocolTLS.CompressionToString(const aCompression : Uint8):String;
begin
  case aCompression of
      0 : Result := 'null';
      1 : Result := 'DEFLATE';
     64 : Result := 'LZS';    
  else
    Result := Format('Unknown (%d)', [aCompression]);
  end;
end;


class function TWPcapProtocolTLS.ChipherToString(const aChipher: Uint16): string;
begin
  case aChipher of
    $000000 : Result := 'TLS_NULL_WITH_NULL_NULL';
    $000001 : Result := 'TLS_RSA_WITH_NULL_MD5';
    $000002 : Result := 'TLS_RSA_WITH_NULL_SHA';
    $000003 : Result := 'TLS_RSA_EXPORT_WITH_RC4_40_MD5';
    $000004 : Result := 'TLS_RSA_WITH_RC4_128_MD5';
    $000005 : Result := 'TLS_RSA_WITH_RC4_128_SHA';
    $000006 : Result := 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5';
    $000007 : Result := 'TLS_RSA_WITH_IDEA_CBC_SHA';
    $000008 : Result := 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA';
    $000009 : Result := 'TLS_RSA_WITH_DES_CBC_SHA';
    $00000a : Result := 'TLS_RSA_WITH_3DES_EDE_CBC_SHA';
    $00000b : Result := 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA';
    $00000c : Result := 'TLS_DH_DSS_WITH_DES_CBC_SHA';
    $00000d : Result := 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA';
    $00000e : Result := 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA';
    $00000f : Result := 'TLS_DH_RSA_WITH_DES_CBC_SHA';
    $000010 : Result := 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA';
    $000011 : Result := 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA';
    $000012 : Result := 'TLS_DHE_DSS_WITH_DES_CBC_SHA';
    $000013 : Result := 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA';
    $000014 : Result := 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA';
    $000015 : Result := 'TLS_DHE_RSA_WITH_DES_CBC_SHA';
    $000016 : Result := 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA';
    $000017 : Result := 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5';
    $000018 : Result := 'TLS_DH_anon_WITH_RC4_128_MD5';
    $000019 : Result := 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA';
    $00001a : Result := 'TLS_DH_anon_WITH_DES_CBC_SHA';
    $00001b : Result := 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA';
    $00001c : Result := 'SSL_FORTEZZA_KEA_WITH_NULL_SHA';
    $00001d : Result := 'SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA';
    $00001E : Result := 'TLS_KRB5_WITH_DES_CBC_SHA';
    $00001F : Result := 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA';
    $000020 : Result := 'TLS_KRB5_WITH_RC4_128_SHA';
    $000021 : Result := 'TLS_KRB5_WITH_IDEA_CBC_SHA';
    $000022 : Result := 'TLS_KRB5_WITH_DES_CBC_MD5';
    $000023 : Result := 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5';
    $000024 : Result := 'TLS_KRB5_WITH_RC4_128_MD5';
    $000025 : Result := 'TLS_KRB5_WITH_IDEA_CBC_MD5';
    $000026 : Result := 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA';
    $000027 : Result := 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA';
    $000028 : Result := 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA';
    $000029 : Result := 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5';
    $00002A : Result := 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5';
    $00002B : Result := 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5';    
    $00002C : Result := 'TLS_PSK_WITH_NULL_SHA';
    $00002D : Result := 'TLS_DHE_PSK_WITH_NULL_SHA';
    $00002E : Result := 'TLS_RSA_PSK_WITH_NULL_SHA';    
    $00002f : Result := 'TLS_RSA_WITH_AES_128_CBC_SHA';
    $000030 : Result := 'TLS_DH_DSS_WITH_AES_128_CBC_SHA';
    $000031 : Result := 'TLS_DH_RSA_WITH_AES_128_CBC_SHA';
    $000032 : Result := 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA';
    $000033 : Result := 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA';
    $000034 : Result := 'TLS_DH_anon_WITH_AES_128_CBC_SHA';
    $000035 : Result := 'TLS_RSA_WITH_AES_256_CBC_SHA';
    $000036 : Result := 'TLS_DH_DSS_WITH_AES_256_CBC_SHA';
    $000037 : Result := 'TLS_DH_RSA_WITH_AES_256_CBC_SHA';
    $000038 : Result := 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA';
    $000039 : Result := 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA';
    $00003A : Result := 'TLS_DH_anon_WITH_AES_256_CBC_SHA';
    $00003B : Result := 'TLS_RSA_WITH_NULL_SHA256';
    $00003C : Result := 'TLS_RSA_WITH_AES_128_CBC_SHA256';
    $00003D : Result := 'TLS_RSA_WITH_AES_256_CBC_SHA256';
    $00003E : Result := 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256';
    $00003F : Result := 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256';
    $000040 : Result := 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256';
    $000041 : Result := 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA';
    $000042 : Result := 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA';
    $000043 : Result := 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA';
    $000044 : Result := 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA';
    $000045 : Result := 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA';
    $000046 : Result := 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA';
    $000047 : Result := 'TLS_ECDH_ECDSA_WITH_NULL_SHA';
    $000048 : Result := 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA';
    $000049 : Result := 'TLS_ECDH_ECDSA_WITH_DES_CBC_SHA';
    $00004A : Result := 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA';
    $00004B : Result := 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA';
    $00004C : Result := 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA';
    $000060 : Result := 'TLS_RSA_EXPORT1024_WITH_RC4_56_MD5';
    $000061 : Result := 'TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5';
    $000062 : Result := 'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA';
    $000063 : Result := 'TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA';
    $000064 : Result := 'TLS_RSA_EXPORT1024_WITH_RC4_56_SHA';
    $000065 : Result := 'TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA';
    $000066 : Result := 'TLS_DHE_DSS_WITH_RC4_128_SHA';
    $000067 : Result := 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256';
    $000068 : Result := 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256';
    $000069 : Result := 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256';
    $00006A : Result := 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256';
    $00006B : Result := 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256';
    $00006C : Result := 'TLS_DH_anon_WITH_AES_128_CBC_SHA256';
    $00006D : Result := 'TLS_DH_anon_WITH_AES_256_CBC_SHA256';    
    $000084 : Result := 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA';
    $000085 : Result := 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA';
    $000086 : Result := 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA';
    $000087 : Result := 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA';
    $000088 : Result := 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA';
    $000089 : Result := 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA';    
    $00008A : Result := 'TLS_PSK_WITH_RC4_128_SHA';
    $00008B : Result := 'TLS_PSK_WITH_3DES_EDE_CBC_SHA';
    $00008C : Result := 'TLS_PSK_WITH_AES_128_CBC_SHA';
    $00008D : Result := 'TLS_PSK_WITH_AES_256_CBC_SHA';
    $00008E : Result := 'TLS_DHE_PSK_WITH_RC4_128_SHA';
    $00008F : Result := 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA';
    $000090 : Result := 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA';
    $000091 : Result := 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA';
    $000092 : Result := 'TLS_RSA_PSK_WITH_RC4_128_SHA';
    $000093 : Result := 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA';
    $000094 : Result := 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA';
    $000095 : Result := 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA';    
    $000096 : Result := 'TLS_RSA_WITH_SEED_CBC_SHA';
    $000097 : Result := 'TLS_DH_DSS_WITH_SEED_CBC_SHA';
    $000098 : Result := 'TLS_DH_RSA_WITH_SEED_CBC_SHA';
    $000099 : Result := 'TLS_DHE_DSS_WITH_SEED_CBC_SHA';
    $00009A : Result := 'TLS_DHE_RSA_WITH_SEED_CBC_SHA';
    $00009B : Result := 'TLS_DH_anon_WITH_SEED_CBC_SHA';    
    $00009C : Result := 'TLS_RSA_WITH_AES_128_GCM_SHA256';
    $00009D : Result := 'TLS_RSA_WITH_AES_256_GCM_SHA384';
    $00009E : Result := 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256';
    $00009F : Result := 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384';
    $0000A0 : Result := 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256';
    $0000A1 : Result := 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384';
    $0000A2 : Result := 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256';
    $0000A3 : Result := 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384';
    $0000A4 : Result := 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256';
    $0000A5 : Result := 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384';
    $0000A6 : Result := 'TLS_DH_anon_WITH_AES_128_GCM_SHA256';
    $0000A7 : Result := 'TLS_DH_anon_WITH_AES_256_GCM_SHA384';    
    $0000A8 : Result := 'TLS_PSK_WITH_AES_128_GCM_SHA256';
    $0000A9 : Result := 'TLS_PSK_WITH_AES_256_GCM_SHA384';
    $0000AA : Result := 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256';
    $0000AB : Result := 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384';
    $0000AC : Result := 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256';
    $0000AD : Result := 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384';
    $0000AE : Result := 'TLS_PSK_WITH_AES_128_CBC_SHA256';
    $0000AF : Result := 'TLS_PSK_WITH_AES_256_CBC_SHA384';
    $0000B0 : Result := 'TLS_PSK_WITH_NULL_SHA256';
    $0000B1 : Result := 'TLS_PSK_WITH_NULL_SHA384';
    $0000B2 : Result := 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256';
    $0000B3 : Result := 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384';
    $0000B4 : Result := 'TLS_DHE_PSK_WITH_NULL_SHA256';
    $0000B5 : Result := 'TLS_DHE_PSK_WITH_NULL_SHA384';
    $0000B6 : Result := 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256';
    $0000B7 : Result := 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384';
    $0000B8 : Result := 'TLS_RSA_PSK_WITH_NULL_SHA256';
    $0000B9 : Result := 'TLS_RSA_PSK_WITH_NULL_SHA384';    
    $0000BA : Result := 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256';
    $0000BB : Result := 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256';
    $0000BC : Result := 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256';
    $0000BD : Result := 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256';
    $0000BE : Result := 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256';
    $0000BF : Result := 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256';
    $0000C0 : Result := 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256';
    $0000C1 : Result := 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256';
    $0000C2 : Result := 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256';
    $0000C3 : Result := 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256';
    $0000C4 : Result := 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256';
    $0000C5 : Result := 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256';    
    $0000FF : Result := 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV';    
    $00c001 : Result := 'TLS_ECDH_ECDSA_WITH_NULL_SHA';
    $00c002 : Result := 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA';
    $00c003 : Result := 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA';
    $00c004 : Result := 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA';
    $00c005 : Result := 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA';
    $00c006 : Result := 'TLS_ECDHE_ECDSA_WITH_NULL_SHA';
    $00c007 : Result := 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA';
    $00c008 : Result := 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA';
    $00c009 : Result := 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA';
    $00c00a : Result := 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA';
    $00c00b : Result := 'TLS_ECDH_RSA_WITH_NULL_SHA';
    $00c00c : Result := 'TLS_ECDH_RSA_WITH_RC4_128_SHA';
    $00c00d : Result := 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA';
    $00c00e : Result := 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA';
    $00c00f : Result := 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA';
    $00c010 : Result := 'TLS_ECDHE_RSA_WITH_NULL_SHA';
    $00c011 : Result := 'TLS_ECDHE_RSA_WITH_RC4_128_SHA';
    $00c012 : Result := 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA';
    $00c013 : Result := 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA';
    $00c014 : Result := 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA';
    $00c015 : Result := 'TLS_ECDH_anon_WITH_NULL_SHA';
    $00c016 : Result := 'TLS_ECDH_anon_WITH_RC4_128_SHA';
    $00c017 : Result := 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA';
    $00c018 : Result := 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA';
    $00c019 : Result := 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA';   
    $00C01A : Result := 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA';
    $00C01B : Result := 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA';
    $00C01C : Result := 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA';
    $00C01D : Result := 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA';
    $00C01E : Result := 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA';
    $00C01F : Result := 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA';
    $00C020 : Result := 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA';
    $00C021 : Result := 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA';
    $00C022 : Result := 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA';    
    $00C023 : Result := 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256';    
  	$00C024 : Result := 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384';
    $00C025 : Result := 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256';
    $00C026 : Result := 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384';
    $00C027 : Result := 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256';
    $00C028 : Result := 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384';
    $00C029 : Result := 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256';
    $00C02A : Result := 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384';
    $00C02B : Result := 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256';
    $00C02C : Result := 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384';
    $00C02D : Result := 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256';
    $00C02E : Result := 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384';
    $00C02F : Result := 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256';
    $00C030 : Result := 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384';
    $00C031 : Result := 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256';
    $00C032 : Result := 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384';    
    $00C033 : Result := 'TLS_ECDHE_PSK_WITH_RC4_128_SHA';
    $00C034 : Result := 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA';
    $00C035 : Result := 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA';
    $00C036 : Result := 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA';
    $00C037 : Result := 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256';
    $00C038 : Result := 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384';
    $00C039 : Result := 'TLS_ECDHE_PSK_WITH_NULL_SHA';
    $00C03A : Result := 'TLS_ECDHE_PSK_WITH_NULL_SHA256';
    $00C03B : Result := 'TLS_ECDHE_PSK_WITH_NULL_SHA384';
    $00CC13 : Result := 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256';
    $00CC14 : Result := 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256';
    $00CC15 : Result := 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256';   
    $00CCA8 : Result := 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256';
    $00CCA9 : Result := 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256';
    $00CCAA : Result := 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256';
    $00CCAB : Result := 'TLS_PSK_WITH_CHACHA20_POLY1305_SHA256';
    $00CCAC : Result := 'TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256';
    $00CCAD : Result := 'TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256';
    $00CCAE : Result := 'TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256';
    $00e001 : Result := 'ECDHE_SM1_SM3';
    $00e003 : Result := 'ECC_SM1_SM3';
    $00e005 : Result := 'IBSDH_SM1_SM3';
    $00e007 : Result := 'IBC_SM1_SM3';
    $00e009 : Result := 'RSA_SM1_SM3';
    $00e00a : Result := 'RSA_SM1_SHA1';
    $00e011 : Result := 'ECDHE_SM4_CBC_SM3';
    $00e013 : Result := 'ECC_SM4_CBC_SM3';
    $00e015 : Result := 'IBSDH_SM4_CBC_SM3';
    $00e017 : Result := 'IBC_SM4_CBC_SM3';
    $00e019 : Result := 'RSA_SM4_CBC_SM3';
    $00e01a : Result := 'RSA_SM4_CBC_SHA1';
    $00e01c : Result := 'RSA_SM4_CBC_SHA256';
    $00e051 : Result := 'ECDHE_SM4_GCM_SM3';
    $00e053 : Result := 'ECC_SM4_GCM_SM3';
    $00e055 : Result := 'IBSDH_SM4_GCM_SM3';
    $00e057 : Result := 'IBC_SM4_GCM_SM3';
    $00e059 : Result := 'RSA_SM4_GCM_SM3';
    $00e05a : Result := 'RSA_SM4_GCM_SHA256';
    $00E410 : Result := 'TLS_RSA_WITH_ESTREAM_SALSA20_SHA1';
    $00E411 : Result := 'TLS_RSA_WITH_SALSA20_SHA1';
    $00E412 : Result := 'TLS_ECDHE_RSA_WITH_ESTREAM_SALSA20_SHA1';
    $00E413 : Result := 'TLS_ECDHE_RSA_WITH_SALSA20_SHA1';
    $00E414 : Result := 'TLS_ECDHE_ECDSA_WITH_ESTREAM_SALSA20_SHA1';
    $00E415 : Result := 'TLS_ECDHE_ECDSA_WITH_SALSA20_SHA1';
    $00E416 : Result := 'TLS_PSK_WITH_ESTREAM_SALSA20_SHA1';
    $00E417 : Result := 'TLS_PSK_WITH_SALSA20_SHA1';
    $00E418 : Result := 'TLS_ECDHE_PSK_WITH_ESTREAM_SALSA20_SHA1';
    $00E419 : Result := 'TLS_ECDHE_PSK_WITH_SALSA20_SHA1';
    $00E41A : Result := 'TLS_RSA_PSK_WITH_ESTREAM_SALSA20_SHA1';
    $00E41B : Result := 'TLS_RSA_PSK_WITH_SALSA20_SHA1';
    $00E41C : Result := 'TLS_DHE_PSK_WITH_ESTREAM_SALSA20_SHA1';
    $00E41D : Result := 'TLS_DHE_PSK_WITH_SALSA20_SHA1';
    $00E41E : Result := 'TLS_DHE_RSA_WITH_ESTREAM_SALSA20_SHA1';
    $00E41F : Result := 'TLS_DHE_RSA_WITH_SALSA20_SHA1';
    $00fefe : Result := 'SSL_RSA_FIPS_WITH_DES_CBC_SHA';
    $00feff : Result := 'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA';
    $00ffe0 : Result := 'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA';
    $00ffe1 : Result := 'SSL_RSA_FIPS_WITH_DES_CBC_SHA';    
 {   $010080 : Result := 'SSL2_RC4_128_WITH_MD5';
    $020080 : Result := 'SSL2_RC4_128_EXPORT40_WITH_MD5';
    $030080 : Result := 'SSL2_RC2_128_CBC_WITH_MD5';
    $040080 : Result := 'SSL2_RC2_128_CBC_EXPORT40_WITH_MD5';
    $050080 : Result := 'SSL2_IDEA_128_CBC_WITH_MD5';
    $060040 : Result := 'SSL2_DES_64_CBC_WITH_MD5';
    $0700c0 : Result := 'SSL2_DES_192_EDE3_CBC_WITH_MD5';
    $080080 : Result := 'SSL2_RC4_64_WITH_MD5';
  }  
  end;
end;

class function TWPcapProtocolTLS.TLSVersionToString(const aVersion: Uint16): string;
begin
  case aVersion of
    SSLV2_VERSION              : Result := 'SSL 2.0';
    SSLV3_VERSION              : Result := 'SSL 3.0';
    TLS_VERSION_1_0            : Result := 'TLS 1.0';
    TLCPV1_VERSION             : Result := 'TLCP';
    TLS_VERSION_1_1            : Result := 'TLS 1.1';
    TLS_VERSION_1_2            : Result := 'TLS 1.2';
    TLS_VERSION_1_3            : Result := 'TLS 1.3';
    $7F0E                      : Result := 'TLS 1.3 (draft 14)';
    $7F0F                      : Result := 'TLS 1.3 (draft 15)';
    $7F10                      : Result := 'TLS 1.3 (draft 16)';
    $7F11                      : Result := 'TLS 1.3 (draft 17)';
    $7F12                      : Result := 'TLS 1.3 (draft 18)';
    $7F13                      : Result := 'TLS 1.3 (draft 19)';
    $7F14                      : Result := 'TLS 1.3 (draft 20)';
    $7F15                      : Result := 'TLS 1.3 (draft 21)';
    $7F16                      : Result := 'TLS 1.3 (draft 22)';
    $7F17                      : Result := 'TLS 1.3 (draft 23)';
    $7F18                      : Result := 'TLS 1.3 (draft 24)';
    $7F19                      : Result := 'TLS 1.3 (draft 25)';
    $7F1A                      : Result := 'TLS 1.3 (draft 26)';
    $7F1B                      : Result := 'TLS 1.3 (draft 27)';
    $7F1C                      : Result := 'TLS 1.3 (draft 28)';
    $FB17                      : Result := 'TLS 1.3 (Facebook draft 23)';
    $FB1A                      : Result := 'TLS 1.3 (Facebook draft 26)';
    DTLSV1DOT0_OPENSSL_VERSION : Result := 'DTLS 1.0 (OpenSSL pre 0.9.8f)';
    DTLSV1DOT0_VERSION         : Result := 'DTLS 1.0';
    DTLSV1DOT2_VERSION         : Result := 'DTLS 1.2';
    $0A0A                      : Result := 'Reserved (GREASE)';//* RFC 8701 */
    $1A1A                      : Result := 'Reserved (GREASE)';//* RFC 8701 */
    $2A2A                      : Result := 'Reserved (GREASE)';//* RFC 8701 */
    $3A3A                      : Result := 'Reserved (GREASE)';//* RFC 8701 */
    $4A4A                      : Result := 'Reserved (GREASE)';//* RFC 8701 */
    $5A5A                      : Result := 'Reserved (GREASE)';//* RFC 8701 */
    $6A6A                      : Result := 'Reserved (GREASE)';//* RFC 8701 */
    $7A7A                      : Result := 'Reserved (GREASE)';//* RFC 8701 */
    $8A8A                      : Result := 'Reserved (GREASE)';//* RFC 8701 */
    $9A9A                      : Result := 'Reserved (GREASE)';//* RFC 8701 */
    $AAAA                      : Result := 'Reserved (GREASE)';//* RFC 8701 */
    $BABA                      : Result := 'Reserved (GREASE)';//* RFC 8701 */
    $CACA                      : Result := 'Reserved (GREASE)';//* RFC 8701 */
    $DADA                      : Result := 'Reserved (GREASE)';//* RFC 8701 */
    $EAEA                      : Result := 'Reserved (GREASE)';//* RFC 8701 */
    $FAFA                      : Result := 'Reserved (GREASE)';//* RFC 8701 */
  end;
end;

class function TWPcapProtocolTLS.KnowVersion(aVersion: Word): Boolean;
begin
  case aVersion of
    SSLV2_VERSION              ,
    SSLV3_VERSION              ,
    TLS_VERSION_1_0            ,
    TLCPV1_VERSION             ,
    TLS_VERSION_1_1            ,
    TLS_VERSION_1_2            , 
    TLS_VERSION_1_3            , 
    $7F0E                      , 
    $7F0F                      , 
    $7F10                      , 
    $7F11                      , 
    $7F12                      , 
    $7F13                      , 
    $7F14                      , 
    $7F15                      , 
    $7F16                      , 
    $7F17                      , 
    $7F18                      , 
    $7F19                      , 
    $7F1A                      , 
    $7F1B                      , 
    $7F1C                      , 
    $FB17                      , 
    $FB1A                      , 
    DTLSV1DOT0_OPENSSL_VERSION , 
    DTLSV1DOT0_VERSION         , 
    DTLSV1DOT2_VERSION         , 
    $0A0A                      , 
    $1A1A                      , 
    $2A2A                      , 
    $3A3A                      , 
    $4A4A                      , 
    $5A5A                      , 
    $6A6A                      , 
    $7A7A                      , 
    $8A8A                      , 
    $9A9A                      , 
    $AAAA                      , 
    $BABA                      , 
    $CACA                      , 
    $DADA                      , 
    $EAEA                      , 
    $FAFA                      : Result := True; 
  else Result := False
  end;
end;

class function TWPcapProtocolTLS.TLSExtensionToString(const aExtensionType: Uint16): string;
begin
  case aExtensionType of
    TLS_EXTENSION_TYPE_SERVER_NAME            : Result := 'Server name';
    TLS_EXTENSION_TYPE_MAX_FRAGMENT_LENGTH    : Result := 'Max fragment length';
    TLS_EXTENSION_TYPE_CLIENT_CERTIFICATE_URL : Result := 'Client certificate URL';
    TLS_EXTENSION_TYPE_TRUSTED_CA_KEYS        : Result := 'Trusted CA keys';
    TLS_EXTENSION_TYPE_TRUNCATED_HMAC         : Result := 'Truncated HMAC';
    TLS_EXTENSION_TYPE_STATUS_REQUEST         : Result := 'Status request';
    TLS_EXTENSION_TYPE_USER_MAPPING           : Result := 'User mapping';
    TLS_EXTENSION_TYPE_CLIENT_AUTHZ           : Result := 'Client authz';
    TLS_EXTENSION_TYPE_SERVER_AUTHZ           : Result := 'Server authz';
    TLS_EXTENSION_TYPE_CERT_TYPE              : Result := 'Certificate type';
    TLS_EXTENSION_TYPE_SUPPORTED_GROUPS       : Result := 'Supported groups';
    TLS_EXTENSION_TYPE_EC_POINT_FORMATS       : Result := 'EC point formats';
    TLS_EXTENSION_TYPE_SRP                    : Result := 'SRP';
    TLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS   : Result := 'Signature algorithms';
    TLS_EXTENSION_TYPE_USE_SRTP               : Result := 'Use SRTP';
    TLS_EXTENSION_TYPE_HEARTBEAT              : Result := 'Heartbeat';
    TLS_EXTENSION_TYPE_APP_PROTO_NEGOTIATION  : Result := 'Application layer protocol negotiation';
    TLS_EXTENSION_TYPE_STATUS_REQUEST_V2      : Result := 'Status request v2';
    TLS_EXTENSION_TYPE_SIGNED_CERT_TIMESTAMP  : Result := 'Signed certificate timestamp';
    TLS_EXTENSION_TYPE_CLIENT_CERT_TYPE       : Result := 'Client certificate type';
    TLS_EXTENSION_TYPE_SERVER_CERT_TYPE       : Result := 'Server certificate type';
    TLS_EXTENSION_TYPE_PADDING                : Result := 'Padding';
    TLS_EXTENSION_TYPE_ENCRYPT_THEN_MAC       : Result := 'Encrypt then MAC';
    TLS_EXTENSION_TYPE_EXTENDED_MASTER_SECRET : Result := 'Extended master secret';
    TLS_EXTENSION_TYPE_TOKEN_BINDING          : Result := 'Token binding';
    TLS_EXTENSION_TYPE_CACHED_INFO            : Result := 'Cached info';
    TLS_EXTENSION_TYPE_SESSION_TICKET         : Result := 'Session ticket';
    TLS_EXTENSION_TYPE_PRE_SHARED_KEY         : Result := 'Pre shared key';
    TLS_EXTENSION_TYPE_SUPPORTED_VERSION      : Result := 'Supported versions';
    TLS_EXTENSION_TYPE_PSK_EXCHANGE_MODES     : Result := 'psk_key_exchange_modes';
    TLS_EXTENSION_TYPE_KEY_SHARE              : Result := 'Key share';
    TLS_EXTENSION_TYPE_RESERVED_GREESE_2,
    TLS_EXTENSION_TYPE_RESERVED_GREESE        : Result := 'Reserved (GREASE)';
    TLS_EXTENSION_TYPE_RENEGOTIATION_INFO     : Result := 'Renegotiation info';

    else Result := 'Unknown TLS extension type';
  end;
end;

class function TWPcapProtocolTLS.SupportedGroupToString(const aValue: Uint16): string;
begin
  case aValue of
    1 : Result := 'sect163k1';   
    2 : Result := 'sect163r1'; 
    3 : Result := 'sect163r2';   
    4 : Result := 'sect193r1';   
    5 : Result := 'sect193r2';   
    6 : Result := 'sect233k1';  
    7 : Result := 'sect233r1';   
    8 : Result := 'sect239k1';   
    9 : Result := 'sect283k1';   
    10: Result := 'sect283r1';   
    11: Result := 'sect409k1';   
    12: Result := 'sect409r1';   
    13: Result := 'sect571k1';   
    14: Result := 'sect571r1';   
    24: Result := 'ffdhe2048';   
    28: Result := 'ffdhe3072';   
    32: Result := 'ffdhe4096';   
    36: Result := 'ffdhe6144';   
    40: Result := 'ffdhe8192';   
    29: Result := 'X25519';   
    30: Result := 'X448';   
    23: Result := 'secp256r1';   
    25: Result := 'secp384r1';
    26: Result := 'secp521r1';
    else Result := 'unknown';
  end;
end;


class function TWPcapProtocolTLS.SignatureAlgorithmToString(const aValue: Uint16): string;
var LAlgorithmValue, LHashValue: Uint8;
begin
  LAlgorithmValue := GetByteFromWord(aValue,0);
  LHashValue      := GetByteFromWord(aValue,1);
  case LAlgorithmValue of
    0: Result := 'Anonymous';
    1: Result := 'RSA';
    2: Result := 'DSA';
    3: Result := 'ECDSA';
    4: Result := 'SM2';
  else Result := 'Unknown';
  end;

  case LHashValue of
    1: Result := Result + ',MD5';
    2: Result := Result + ',SHA1';
    3: Result := Result + ',SHA128';
    4: Result := Result + ',SHA256';
    5: Result := Result + ',SHA384';
    6: Result := Result + ',SHA512';
  else Result := Result+',Unknown';    
  end;
end;

class function TWPcapProtocolTLS.HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean;
var LOffset         : Integer;
    LRecord         : PTTLSRecordHeader;    
    LTCPHdr         : PTCPHdr;
    LTCPPayLoad     : PByte;
    LTCPPayLoadLen  : Integer;
    LContectLen     : Integer;
    LindexVersion   : Integer; //TODO Update version
    LContentStr     : String;
    LByteValue      : Uint8;
    LByteValue2     : Uint8;
    LTypeRecord     : Uint8;
    LTypeRecordStr  : String;
    LtmpVaue        : Integer;
    LtmpVaue2       : Integer;
    LHandShakeLen   : integer;
    LUInt16Value    : Uint16;
    I               : Integer;
    LDummy          : Integer;
    LInfoProtocols  : String;

    Procedure LoadCommonFieldHello(const aContentType:String);
    begin
      ParserUint16Value(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,Format('%s.Handshake.%s.Version',[AcronymName,aContentType]), 'Version:',AListDetail,TLSVersionToString,False,LOffset);   
      ParserGenericBytesValue(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,32,Format('%s.Handshake.%S.Random',[AcronymName,aContentType]), 'Random:',AListDetail,BytesToHex,True,LOffset);            
      LByteValue := ParserUint8Value(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,Format('%s.Handshake.%s.SessionID.Len',[AcronymName,aContentType]), 'Session ID length:',AListDetail,nil,False,LOffset);               
      ParserGenericBytesValue(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,LByteValue,Format('%s.Handshake.%S.SessionID',[AcronymName,aContentType]), 'Session ID:',AListDetail,BytesToHex,True,LOffset);                        
    end;

    Procedure ParserExtentions(const aContentType:String);
    var LExtType : Uint16;  
        LLenExts : Uint16;
        LLenExt  : Uint16; 
        LLenTmp  : Uint16;
        LLenTmp2 : Uint16;
        LLenTmp3 : Uint16;

        Procedure SkipUnsupportlabel(const aRemove: Uint16);
        begin          
          if LLenExt - aRemove > 0 then
            Inc(LOffset,LLenExt - aRemove );
        end;

        Procedure ParserDataMod2(aLenSize:Byte;const aExtPluralName,aExtName,aPluralCaption,aSingleCaption : String;aToStringFunction:TWpcapUint16ToString;isBigEndian:Boolean);
        begin
          if aLenSize <> 1 then          
            LLenTmp  := ParserUint16Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.%s.ListLen',[AcronymName,aContentType,aExtName]), Format('%s length:',[aPluralCaption]),AListDetail,SizeWordToStr,True,LOffset)
          else
            LLenTmp  := ParserUint8Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.%s.ListLen',[AcronymName,aContentType,aExtName]), Format('%s length:',[aPluralCaption]),AListDetail,SizeaUint8ToStr,True,LOffset);   

          LLenTmp2 := LLenTmp;
          ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LLenTmp,Format('%s.Handshake.%S.Extension.%s.%s',[AcronymName,aContentType,aExtName,aExtPluralName]),Format('%s:',[aPluralCaption]),AListDetail,nil,True,LOffset); 
          Dec(LOffset,LLenTmp); 
          if LLenTmp > 0 then
          begin
             while LLenTmp > 0 do
             begin
               if LLenTmp >= 2 then
               begin
                 ParserUint16Value(LTCPPayLoad,aStartLevel+5,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.%s.%s.value',[AcronymName,aContentType,aExtName,aExtPluralName]),aSingleCaption,AListDetail,aToStringFunction,isBigEndian,LOffset);   
                 Dec(LLenTmp,2);
               end
               else
               begin
                 FisMalformed := True;
                 Break;
               end;
             end;
          end;         
          SkipUnsupportlabel(aLenSize+LLenTmp2);
        end;

        Procedure ParserDataMod1(aLenSize:Byte;const aExtPluralName,aExtName,aPluralCaption,aSingleCaption : String;aToStringFunction:TWpcapUint8ToString;isBigIndian:Boolean);
        begin
          if aLenSize <> 1 then          
            LLenTmp  := ParserUint16Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.%s.ListLen',[AcronymName,aContentType,aExtName]), Format('%s length:',[aPluralCaption]),AListDetail,SizeWordToStr,True,LOffset)
          else
            LLenTmp  := ParserUint8Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.%s.ListLen',[AcronymName,aContentType,aExtName]), Format('%s length:',[aPluralCaption]),AListDetail,SizeaUint8ToStr,True,LOffset);   

          LLenTmp2 := LLenTmp;
          ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LLenTmp,Format('%s.Handshake.%S.Extension.%s.%s',[AcronymName,aContentType,aExtName,aExtPluralName]),Format('%s:',[aPluralCaption]),AListDetail,nil,True,LOffset); 
          Dec(LOffset,LLenTmp); 
          if LLenTmp > 0 then
          begin
             while LLenTmp > 0 do
             begin
               if LLenTmp >= 1 then
               begin
                 ParserUint8Value(LTCPPayLoad,aStartLevel+5,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.%s.%s.value',[AcronymName,aContentType,aExtName,aExtPluralName]),aSingleCaption,AListDetail,aToStringFunction,isBigIndian,LOffset);   
                 Dec(LLenTmp,1);
               end
               else
               begin
                 FisMalformed := True;
                 Break;
               end;                              
             end;
          end;         
          SkipUnsupportlabel(aLenSize+LLenTmp2);
        end;        
    begin
        if LOffset < LTCPPayLoadLen then
        begin
          LLenExts := ParserUint16Value(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,Format('%s.Handshake.%s.Extensions.Len',[AcronymName,aContentType]), 'Extensions length:',AListDetail,SizeWordToStr,True,LOffset);   
          {Extens}  
          if LLenExts > 0 then
          begin
            while LLenExts > 0 do
            begin
              LExtType := ParserUint16Value(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.name',[AcronymName,aContentType]), 'Extension:',AListDetail,TLSExtensionToString,True,LOffset);  
              Dec(LLenExts,SizeOf(LExtType));
              LLenExt := ParserUint16Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.len',[AcronymName,aContentType]), 'length:',AListDetail,SizeWordToStr,True,LOffset);  
              Dec(LLenExts,2);
              if (LLenExt > 0) and (LLenExt <= LLenExts) then     
              begin
                Dec(LLenExts,LLenExt);
                case LExtType of
                
                  TLS_EXTENSION_TYPE_SERVER_NAME            : 
                    begin
                      ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LLenExt,Format('%s.Handshake.%S.Extension.ServerName',[AcronymName,aContentType]), 'Server Name Indication extension:',AListDetail,nil,True,LOffset); 
                      Dec(LOffset,LLenExt);           
                      ParserUint16Value(LTCPPayLoad,aStartLevel+5,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.ServerName.Listlen',[AcronymName,aContentType]), 'List length:',AListDetail,SizeWordToStr,True,LOffset);   
                      ParserUint8Value(LTCPPayLoad,aStartLevel+5,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.ServerName.Type',[AcronymName,aContentType]), 'Type:',AListDetail,nil,False,LOffset);               
                      LLenTmp := ParserUint16Value(LTCPPayLoad,aStartLevel+5,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.ServerName.Len',[AcronymName,aContentType]), 'Length:',AListDetail,SizeWordToStr,True,LOffset);   
                      ParserGenericBytesValue(LTCPPayLoad,aStartLevel+5,LTCPPayLoadLen,LLenTmp,Format('%s.Handshake.%S.Extension.ServerName.name',[AcronymName,aContentType]), 'Name:',AListDetail,BytesToStringRawInternal,True,LOffset);            
                      SkipUnsupportlabel(5+LLenTmp);
                    end;
                    
                  TLS_EXTENSION_TYPE_MAX_FRAGMENT_LENGTH    : 
                    begin
                      DoLog('TWPcapProtocolTLS.HeaderToString','Extentions TLS_EXTENSION_TYPE_MAX_FRAGMENT_LENGTH not implemented',TWLLWarning);
                      Inc(LOffset,LLenExt); 
                    end;  
                                      
                  TLS_EXTENSION_TYPE_CLIENT_CERTIFICATE_URL : 
                    begin
                      DoLog('TWPcapProtocolTLS.HeaderToString','Extentions TLS_EXTENSION_TYPE_CLIENT_CERTIFICATE_URL not implemented',TWLLWarning);
                      Inc(LOffset,LLenExt); 
                    end;  
                    
                  TLS_EXTENSION_TYPE_TRUSTED_CA_KEYS        : 
                    begin
                      DoLog('TWPcapProtocolTLS.HeaderToString','Extentions TLS_EXTENSION_TYPE_TRUSTED_CA_KEYS not implemented',TWLLWarning);
                      Inc(LOffset,LLenExt); 
                    end;  
                    
                  TLS_EXTENSION_TYPE_TRUNCATED_HMAC         : 
                    begin
                      DoLog('TWPcapProtocolTLS.HeaderToString','Extentions TLS_EXTENSION_TYPE_TRUSTED_CA_KEYS not implemented',TWLLWarning);
                      Inc(LOffset,LLenExt); 
                    end;                    
                  
                  TLS_EXTENSION_TYPE_STATUS_REQUEST         : 
                    begin
                      ParserUint8Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.StatusRequest.CertStatusType',[AcronymName,aContentType]), 'Certificate Status Type:',AListDetail,nil,false,LOffset);   
                      ParserUint16Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.StatusRequest.Listlen',[AcronymName,aContentType]), 'Responder ID List length:',AListDetail,SizeWordToStr,True,LOffset);   
                      ParserUint16Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.StatusRequest.ReqExtLen',[AcronymName,aContentType]), 'Request extensions length:',AListDetail,SizeWordToStr,True,LOffset);               
                      SkipUnsupportlabel(5);
                    end;
                    
                  TLS_EXTENSION_TYPE_USER_MAPPING           : 
                    begin
                      DoLog('TWPcapProtocolTLS.HeaderToString','Extentions TLS_EXTENSION_TYPE_USER_MAPPING not implemented',TWLLWarning);
                      Inc(LOffset,LLenExt); 
                    end;                          
                  TLS_EXTENSION_TYPE_CLIENT_AUTHZ           :
                    begin
                      DoLog('TWPcapProtocolTLS.HeaderToString','Extentions TLS_EXTENSION_TYPE_CLIENT_AUTHZ not implemented',TWLLWarning);
                      Inc(LOffset,LLenExt); 
                    end;                          
                  TLS_EXTENSION_TYPE_SERVER_AUTHZ           : 
                    begin
                      DoLog('TWPcapProtocolTLS.HeaderToString','Extentions TLS_EXTENSION_TYPE_SERVER_AUTHZ not implemented',TWLLWarning);
                      Inc(LOffset,LLenExt); 
                    end;                          
                  TLS_EXTENSION_TYPE_CERT_TYPE              : 
                    begin
                      DoLog('TWPcapProtocolTLS.HeaderToString','Extentions TLS_EXTENSION_TYPE_CERT_TYPE not implemented',TWLLWarning);
                      Inc(LOffset,LLenExt); 
                    end;                          
                  
                  TLS_EXTENSION_TYPE_SUPPORTED_GROUPS       :
                    ParserDataMod2(2,'SupportedGroups','SupportedGroup','Supported Groups','Supported group:',SupportedGroupToString,true);
                    
                  TLS_EXTENSION_TYPE_EC_POINT_FORMATS       : 
                    ParserDataMod1(1,'ECPointFormats','ECPointFormat','EC point formats','EC point format:',nil,False);

                  TLS_EXTENSION_TYPE_SRP                    : 
                    begin
                      DoLog('TWPcapProtocolTLS.HeaderToString','Extentions TLS_EXTENSION_TYPE_SRP not implemented',TWLLWarning);
                      Inc(LOffset,LLenExt); 
                    end;                    
                  
                  TLS_EXTENSION_TYPE_SIGNATURE_ALGORITHMS   : 
                    ParserDataMod2(2,'Signatures','Signature','Signature hash algorithms','Signature algorithm:',SignatureAlgorithmToString,true);

                  TLS_EXTENSION_TYPE_USE_SRTP               : 
                    begin
                      DoLog('TWPcapProtocolTLS.HeaderToString','Extentions TLS_EXTENSION_TYPE_USE_SRTP not implemented',TWLLWarning);
                      Inc(LOffset,LLenExt); 
                    end;                                
                  
                  TLS_EXTENSION_TYPE_HEARTBEAT              : 
                    begin
                      ParserUint8Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.HeartBeat.Mode',[AcronymName,aContentType]), 'Mode:',AListDetail,nil,false,LOffset);   
                      SkipUnsupportlabel(1); 
                    end;
                  
                  TLS_EXTENSION_TYPE_APP_PROTO_NEGOTIATION  : 
                    begin
                      LLenTmp  := ParserUint16Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.ALPN.Len',[AcronymName,aContentType]), 'ALPN Length:',AListDetail,SizeWordToStr,True,LOffset); 
                      LLenTmp2 := LLenTmp;
                      if LLenTmp > 0 then
                      begin 
                        ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LLenTmp,Format('%s.Handshake.%S.Extension.ALPN.Protocols',[AcronymName,aContentType]), 'ALPN protocol:',AListDetail,BytesToHex,True,LOffset);
                        Dec(LOffset,LLenTmp);           
                        while LLenTmp > 0 do
                        begin
                           LLenTmp3 := ParserUint8Value(LTCPPayLoad,aStartLevel+5,LTCPPayLoadLen,Format('%s.Handshake.%S.Extension.ALPN.Protocols.Len',[AcronymName,aContentType]),'ALPN string length',AListDetail,SizeaUint8ToStr,False,LOffset);   
                           ParserGenericBytesValue(LTCPPayLoad,aStartLevel+5,LTCPPayLoadLen,LLenTmp3,Format('%s.Handshake.%S.Extension.ALPN.Protocols.NextProtocol',[AcronymName,aContentType]), 'ALPN next protocol:',AListDetail,BytesToStringRawInternal,True,LOffset);
                           Dec(LLenTmp,1+LLenTmp3);
                        end;
                        SkipUnsupportlabel(2+LLenTmp2); 
                      end; 
                    end;
                    
                  TLS_EXTENSION_TYPE_STATUS_REQUEST_V2      : 
                    begin
                      DoLog('TWPcapProtocolTLS.HeaderToString','Extentions TLS_EXTENSION_TYPE_STATUS_REQUEST_V2 not implemented',TWLLWarning);
                      Inc(LOffset,LLenExt); 
                    end;                  
                  
                  TLS_EXTENSION_TYPE_SIGNED_CERT_TIMESTAMP  : Inc(LOffset,LLenExt); //nothing ??

                  TLS_EXTENSION_TYPE_CLIENT_CERT_TYPE       : 
                    begin
                      DoLog('TWPcapProtocolTLS.HeaderToString','Extentions TLS_EXTENSION_TYPE_CLIENT_CERT_TYPE not implemented',TWLLWarning);
                      Inc(LOffset,LLenExt); 
                    end;

                  TLS_EXTENSION_TYPE_SERVER_CERT_TYPE       : 
                    begin
                      DoLog('TWPcapProtocolTLS.HeaderToString','Extentions TLS_EXTENSION_TYPE_SERVER_CERT_TYPE not implemented',TWLLWarning);
                      Inc(LOffset,LLenExt); 
                    end;
                  
                  TLS_EXTENSION_TYPE_PADDING                : 
                      ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LLenExt,Format('%s.Handshake.%S.Extension.Padding.value',[AcronymName,aContentType]), 'Padding:',AListDetail,BytesToHex,True,LOffset); 

                  TLS_EXTENSION_TYPE_ENCRYPT_THEN_MAC       : 
                    begin
                      DoLog('TWPcapProtocolTLS.HeaderToString','Extentions TLS_EXTENSION_TYPE_ENCRYPT_THEN_MAC not implemented',TWLLWarning);
                      Inc(LOffset,LLenExt); 
                    end;
                  
                  TLS_EXTENSION_TYPE_EXTENDED_MASTER_SECRET : Inc(LOffset,LLenExt);  //Nothing ??

                  TLS_EXTENSION_TYPE_TOKEN_BINDING          : 
                    ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LLenExt,Format('%s.Handshake.%S.Extension.TokenBinding.value',[AcronymName,aContentType]), 'Data:',AListDetail,BytesToHex,True,LOffset); 
                    
                  TLS_EXTENSION_TYPE_CACHED_INFO            : 
                    begin
                      DoLog('TWPcapProtocolTLS.HeaderToString','Extentions TLS_EXTENSION_TYPE_CACHED_INFO not implemented',TWLLWarning);
                      Inc(LOffset,LLenExt); 
                    end;
                  
                  TLS_EXTENSION_TYPE_SESSION_TICKET         : 
                      ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LLenExt,Format('%s.Handshake.%S.Extension.SessionTicket.value',[AcronymName,aContentType]), 'Data:',AListDetail,BytesToHex,True,LOffset); 

                  TLS_EXTENSION_TYPE_PRE_SHARED_KEY         :
                    begin
                      ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LLenExt,Format('%s.Handshake.%S.Extension.PreSharedKey',[AcronymName,aContentType]), 'Pre-shared key extension:',AListDetail,nil,True,LOffset); 
                      Dec(LOffset,LLenExt);  
                      LLenTmp := ParserUint16Value(LTCPPayLoad,aStartLevel+5,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.PreSharedKey.IdentitiesLen',[AcronymName,aContentType]), 'Identities Length:',AListDetail,SizeWordToStr,True,LOffset);    
                      ParserGenericBytesValue(LTCPPayLoad,aStartLevel+5,LTCPPayLoadLen,LLenTmp,Format('%s.Handshake.%S.Extension.PreSharedKey.Identities',[AcronymName,aContentType]), 'PSK identities:',AListDetail,nil,True,LOffset); 
                      Dec(LOffset,LLenTmp);  
                      LLenTmp2 := ParserUint16Value(LTCPPayLoad,aStartLevel+6,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.PreSharedKey.Identities.Len',[AcronymName,aContentType]), 'Identities Length:',AListDetail,SizeWordToStr,True,LOffset);    
                      ParserGenericBytesValue(LTCPPayLoad,aStartLevel+6,LTCPPayLoadLen,LLenTmp2,Format('%s.Handshake.%S.Extension.PreSharedKey.Identities.value',[AcronymName,aContentType]), 'Identities:',AListDetail,BytesToHex,True,LOffset);                       
                      ParserUint32Value(LTCPPayLoad,aStartLevel+6,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.PreSharedKey.Identities.ObTicketAge',[AcronymName,aContentType]), 'Obfuscated Ticket Age:',AListDetail,nil,True,LOffset);    
                      LLenTmp2 := ParserUint16Value(LTCPPayLoad,aStartLevel+5,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.PreSharedKey.PSKBindersLen',[AcronymName,aContentType]), 'PSK  binders Length:',AListDetail,SizeWordToStr,True,LOffset);    
                      ParserGenericBytesValue(LTCPPayLoad,aStartLevel+5,LTCPPayLoadLen,LLenTmp2,Format('%s.Handshake.%S.Extension.PreSharedKey.PSKBinders',[AcronymName,aContentType]), 'PSK  binders:',AListDetail,BytesToHex,True,LOffset);                       
                      SkipUnsupportlabel(2+LLenTmp);   
                    end;
                    
                  TLS_EXTENSION_TYPE_SUPPORTED_VERSION      :
                    ParserDataMod2(1,'SupportedVersions','SupportedVersion','Supported versions','Supported version:',TLSVersionToString,false);

                  TLS_EXTENSION_TYPE_PSK_EXCHANGE_MODES     : 
                    ParserDataMod1(1,'PSKKeyExchangeModes','PSKKeyExchangeMode','PSK key exchange modes','PSK key exchange mode:',nil,False);
    
                  TLS_EXTENSION_TYPE_KEY_SHARE :
                    begin
                      ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LLenExt,Format('%s.Handshake.%S.Extension.KeyShare',[AcronymName,aContentType]), 'Key share Indication extension:',AListDetail,nil,True,LOffset); 
                      Dec(LOffset,LLenExt);  
                      LLenTmp := ParserUint16Value(LTCPPayLoad,aStartLevel+5,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.KeyShare.Len',[AcronymName,aContentType]), 'Client Key Share Length:',AListDetail,SizeWordToStr,True,LOffset);    
                      LLenTmp2:= 0;
                      if LLenTmp > 0 then
                      begin
                        ParserGenericBytesValue(LTCPPayLoad,aStartLevel+5,LTCPPayLoadLen,LLenTmp,Format('%s.Handshake.%S.Extension.KeyShare.Entry',[AcronymName,aContentType]), 'Key share entry:',AListDetail,nil,True,LOffset); 
                        Dec(LOffset,LLenTmp);  
                        ParserUint16Value(LTCPPayLoad,aStartLevel+6,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.KeyShare.Entry.Group',[AcronymName,aContentType]), 'Group:',AListDetail,SupportedGroupToString,True,LOffset);    
                        LLenTmp2 := ParserUint16Value(LTCPPayLoad,aStartLevel+6,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.KeyShare.Entry.KeyExchange.len',[AcronymName,aContentType]), 'Key Exchange Length:',AListDetail,SizeWordToStr,True,LOffset);    
                        ParserGenericBytesValue(LTCPPayLoad,aStartLevel+6,LTCPPayLoadLen,LLenTmp2,Format('%s.Handshake.%S.Extension.KeyShare.Entry.KeyExchange.value',[AcronymName,aContentType]), 'Key Exchange:',AListDetail,BytesToHex,True,LOffset); 
                      end;
                      SkipUnsupportlabel(6+LLenTmp2);                     
                    end;

                  TLS_EXTENSION_TYPE_RESERVED_GREESE,
                  TLS_EXTENSION_TYPE_RESERVED_GREESE_2:  
                      ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LLenExt,Format('%s.Handshake.%S.Extension.Reservered.value',[AcronymName,aContentType]), 'Data:',AListDetail,BytesToHex,True,LOffset);                     
                      
                  TLS_EXTENSION_TYPE_RENEGOTIATION_INFO :
                    begin             
                      ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LLenExt,Format('%s.Handshake.%S.Extension.Renegotiation',[AcronymName,aContentType]), 'Renegotiation info extension:',AListDetail,BytesToHex,True,LOffset);
                      Dec(LOffset,LLenExt);           
                      ParserUint8Value(LTCPPayLoad,aStartLevel+5,LTCPPayLoadLen,Format('%s.Handshake.%s.Extension.Renegotiation.Len',[AcronymName,aContentType]), 'Length:',AListDetail,SizeaUint8ToStr,False,LOffset);               
                      SkipUnsupportlabel(1);                      
                    end
                else
                  Inc(LOffset,LLenExt);
                end;
              end
              else if (LLenExt > LLenExts) then break;
            end;
          end                              
        end;                
    
    end;
begin
  Result        := False;
  FIsFilterMode := aIsFilterMode;
  LInfoProtocols:= String.Empty;

  if aPacketSize < SizeOf(TTLSRecordHeader) then Exit;
  if not HeaderTCP(aPacketData,aPacketSize,LTCPHdr) then exit;
  
  LTCPPayLoad    := inherited GetPayLoad(aPacketData,aPacketSize,LTCPPayLoadLen,LDummy);
  LOffset        := 0;

  if aPacketSize < TCPPayLoadLength(LTCPHdr,aPacketData,aPacketSize)-1+SizeOf(TTLSRecordHeader) then exit;
  
  AListDetail.Add(AddHeaderInfo(aStartLevel,AcronymName, Format('%s (%s)', [ProtoName, AcronymName]), null, LTCPPayLoad,LTCPPayLoadLen ));

  while LOffset < LTCPPayLoadLen do
  begin
    if LOffset + SizeOf(TTLSRecordHeader) > LTCPPayLoadLen then break;
    
    LRecord      := PTTLSRecordHeader(LTCPPayLoad + LOffset);
    LContectLen  := wpcapntohs(LRecord.Length);

    if LContectLen <= 0 then exit;
    if LContectLen > LTCPPayLoadLen then exit;

    if LContectLen < SizeOf(TTLSRecordHeader) then
    begin
      Inc(LOffset, SizeOf(TTLSRecordHeader));
      Continue;
    end;
    
    LContentStr  := ContentTypeToString(LRecord.ContentType);

    if LInfoProtocols.IsEmpty then
      LInfoProtocols := LContentStr
    else if not LInfoProtocols.Contains(LContentStr) then         
      LInfoProtocols := Format('%s %s',[LInfoProtocols,LContentStr]);
        
    ParserGenericBytesValue(LTCPPayLoad,aStartLevel+1,LTCPPayLoadLen,LContectLen,Format('%s.RecordLayer',[AcronymName]),Format('%s record layer: %s', [TLSVersionToString(LRecord.ProtocolVersion), ContentTypeToString(LRecord.ContentType)]),AListDetail,nil,True,LOffset);
    Dec(LOffset,LContectLen);
        
    Inc(LOffset, SizeOf(TTLSRecordHeader));
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.ContentType',[AcronymName]), 'Content type', LContentStr, @LRecord.ContentType, SizeOf(LRecord.ContentType), LRecord.ContentType ));  
    LindexVersion := AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Version',[AcronymName]), 'Version', TLSVersionToString(LRecord.ProtocolVersion), @LRecord.ProtocolVersion, SizeOf(LRecord.ProtocolVersion), LRecord.ProtocolVersion ));    
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.ContentLen',[AcronymName]), 'Content length',SizeToStr(LContectLen), @LRecord.Length, SizeOf(LRecord.Length),LContectLen ));  

    {* In TLS 1.3 only Handshake and Application Data can be fragmented.
     * Alert messages MUST NOT be fragmented across }
    case LRecord.ContentType of

      TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC   :
          ParserUint8Value(LTCPPayLoad,aStartLevel+2,LTCPPayLoadLen,Format('%s.ChangeCipherr.Type',[AcronymName]), 'Change cipher:',AListDetail,nil,True,LOffset);   

      TLS_CONTENT_TYPE_ALERT                : 
          ParserGenericBytesValue(LTCPPayLoad,aStartLevel+2,LTCPPayLoadLen,LContectLen,Format('%s.Alert.Message',[AcronymName]), 'Alert Message:',AListDetail,BytesToHex,True,LOffset);            
            
      TLS_CONTENT_TYPE_HANDSHAKE            :
        begin

          LTypeRecord          := PByte(LTCPPayLoad+LOffset)^;
          LTypeRecordStr       := HandShakeTypeToString(LTypeRecord);
          if not LInfoProtocols.Contains(LTypeRecordStr) then            
            LInfoProtocols := Format('%s %s',[LInfoProtocols,LTypeRecordStr]);            
          AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Handshake.%s',[AcronymName,LTypeRecordStr]), Format('Handshake: %s',[LTypeRecordStr]),null,PByte(LTCPPayLoad+LOffset),LContectLen ));                 
            
          ParserUint8Value(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,Format('%s.Handshake.%s.Type',[AcronymName,LTypeRecordStr]), 'Handshake type:',AListDetail,HandShakeTypeToString,True,LOffset);   
            
          LHandShakeLen := ParserUint24Value(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,Format('%s.Handshake.%s.Len',[AcronymName,LTypeRecordStr]), 'Length:',AListDetail,SizeCardinalToStr,true,LOffset);            

          if LHandShakeLen <= 0 then  continue;
          if LHandShakeLen > 16384  then Break;
           
          case LTypeRecord of
            TLS_HANDSHAKE_TYPE_HELLO_REQUEST,
            TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE,
            TLS_HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST : ;//nothing to do!!
              
            TLS_HANDSHAKE_TYPE_CLIENT_HELLO :
              begin
                LoadCommonFieldHello('ClientHello');
                LUInt16Value := ParserUint16Value(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,Format('%s.Handshake.ClientHello.CipherSuites.Len',[AcronymName]), 'Cipher Suites length:',AListDetail,SizeWordToStr,True,LOffset);   
                ParserGenericBytesValue(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,LUInt16Value,Format('%s.Handshake.ClientHello.CipherSuites',[AcronymName]), 'Cipher Suites:',AListDetail,nil,True,LOffset);
                Dec(LOffset,LUInt16Value);                    

                for I := 0 to (LUInt16Value div 2) - 1 do
                begin
                  if LOffset > LTCPPayLoadLen then Exit;
                    
                  ParserUint16Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.ClientHello.CipherSuites.value',[AcronymName]), 'Cipher Suites:',AListDetail,ChipherToString,True,LOffset);   
                end;

                LByteValue2 := ParserUint8Value(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,Format('%s.Handshake.ClientHello.CompressionMethods.Len',[AcronymName]), 'Compression Methods Length:',AListDetail,SizeaUint8ToStr,True,LOffset);                     
                ParserGenericBytesValue(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,LByteValue2,Format('%s..Handshake.ClientHello.CompressionMethods',[AcronymName]), 'Compression Methods:',AListDetail,nil,True,LOffset);
                Dec(LOffset,LByteValue2);         
                          
                for I := 0 to LByteValue2 - 1 do
                begin
                  if LOffset > LTCPPayLoadLen then Exit;

                  ParserUint8Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.ClientHello.CompressionMethods.value',[AcronymName]), 'Compression Methods:',AListDetail,CompressionToString,True,LOffset);                     
                end;

                ParserExtentions('ClientHello');
              end;

            TLS_HANDSHAKE_TYPE_SERVER_HELLO :
              begin
                LoadCommonFieldHello('ServerHello');

                ParserUint16Value(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,Format('%s.Handshake.ServerHello.CipherSuites',[AcronymName]), 'Cipher Suites:',AListDetail,ChipherToString,True,LOffset); 
                ParserUint8Value(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,Format('%s.Handshake.ServerHello.CompressionMethods.value',[AcronymName]), 'Compression Methods:',AListDetail,CompressionToString,True,LOffset);                     
                ParserExtentions('ServerHello');      
              end;                
                
            TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE:
              begin
                ParserGenericBytesValue(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,LHandShakeLen,Format('%s.Handshake.ClientKeyExChange.Record',[AcronymName]), 'Diffie-Hellman Server Params:',AListDetail,nil,True,LOffset);
                Dec(LOffset,LHandShakeLen);  
                LByteValue := ParserUint8Value(LTCPPayLoad,aStartLevel+4,LHandShakeLen,Format('%s.Handshake.ClientKeyExChange.PubkeyLen',[AcronymName]),'Pubkey Length:',AListDetail,nil,True,LOffset);
                ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LByteValue,Format('%s.Handshake.ClientKeyExChange.Pubkey',[AcronymName]), 'Pubkey:',AListDetail,BytesToHex,True,LOffset);            
              end;

            TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE :
              begin
                ParserGenericBytesValue(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,LHandShakeLen,Format('%s.Handshake.ServerKeyExChange.Record',[AcronymName]), 'EC Diffie-Hellman Server Params:',AListDetail,nil,True,LOffset);
                Dec(LOffset,LHandShakeLen);  
                LUInt16Value := ParserUint16Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.ServerKeyExChange.p.Len',[AcronymName]), 'p Length:',AListDetail,SizeWordToStr,True,LOffset);             
                ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LUInt16Value,Format('%s.Handshake.ServerKeyExChange.p',[AcronymName]), 'p:',AListDetail,BytesToHex,True,LOffset);                                

                LUInt16Value := ParserUint16Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.ServerKeyExChange.g.Len',[AcronymName]), 'g Length:',AListDetail,SizeWordToStr,True,LOffset);             
                ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LUInt16Value,Format('%s.Handshake.ServerKeyExChange.g',[AcronymName]), 'g:',AListDetail,BytesToHex,True,LOffset);                                                
                
                LUInt16Value := ParserUint16Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.ServerKeyExChange.PublicKey.Len',[AcronymName]), 'PublicKey Length:',AListDetail,SizeWordToStr,True,LOffset);
                ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LUInt16Value,Format('%s.Handshake.ServerKeyExChange.PublicKey',[AcronymName]), 'PublicKey:',AListDetail,BytesToHex,True,LOffset);                                                

                LUInt16Value := ParserUint16Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.ServerKeyExChange.Signature.Len',[AcronymName]), 'Signature Length:',AListDetail,SizeWordToStr,True,LOffset);             
                ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LUInt16Value,Format('%s.Handshake.ServerKeyExChange.Signature',[AcronymName]), 'Signature:',AListDetail,BytesToHex,True,LOffset);                                                                                  
              end;  

            TLS_HANDSHAKE_TYPE_CERTIFICATE :
              begin
                LtmpVaue := ParserUint24Value(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,Format('%s.Handshake.Certificates.Len',[AcronymName]), 'Certificates length:',AListDetail,nil,True,LOffset);   
                ParserGenericBytesValue(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,LtmpVaue,Format('%s.Handshake.Certificate.Certificates',[AcronymName]), 'Certificate:',AListDetail,nil,True,LOffset);
                Dec(LOffset,LtmpVaue);  
                                       
                while LOffset < LHandShakeLen do
                begin
                  LtmpVaue2 := ParserUint24Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Certificate.Certificates.Len',[AcronymName]), 'Certificate length:',AListDetail,nil,True,LOffset);      
                  ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LtmpVaue2,Format('%s.Handshake.Certificates.Certificate',[AcronymName]), 'Certificate:',AListDetail,nil,True,LOffset);
                  Dec(LOffset,LtmpVaue2);  
                  DoLog('TWPcapProtocolTLS.HeaderToString','TLS_HANDSHAKE_TYPE_CERTIFICATE not compleated',TWLLWarning);
                    
                  {TODO info certificate}
                  Inc(LOffset,LtmpVaue2);                                          
                end;                  
              end;
                      
              TLS_HANDSHAKE_TYPE_NEWSESSION_TICKET  :
                begin
                  ParserGenericBytesValue(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,LHandShakeLen,Format('%s.Handshake.TLSSessionTicket',[AcronymName]), 'TLS session ticket:',AListDetail,nil,True,LOffset);
                  Dec(LOffset,LHandShakeLen);  
                  ParserUint32Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.TLSSessionTicket.Lifetime',[AcronymName]), 'Session Ticket Lifetime Hint(s):',AListDetail,nil,True,LOffset);             
                  LUInt16Value := ParserUint16Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.Handshake.TLSSessionTicket.len',[AcronymName]), 'Session Ticket Length:',AListDetail,SizeWordToStr,True,LOffset);             
                  ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LUInt16Value,Format('%s.Handshake.TLSSessionTicket.value',[AcronymName]), 'Session Ticket:',AListDetail,BytesToHex,True,LOffset);
                end;
                  
              TLS_HANDSHAKE_TYPE_CERT_STATUS :
                begin
                  ParserUint8Value(LTCPPayLoad,aStartLevel+3,LTCPPayLoadLen,Format('%s.Handshake.CertificateStatus.Type',[AcronymName]), 'Certificate Status Type:',AListDetail,nil,True,LOffset);                                       
                  LtmpVaue2 := ParserUint24Value(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,Format('%s.CertificateStatus.Response.Len',[AcronymName]), 'OCSP response length:',AListDetail,nil,True,LOffset);      
                  ParserGenericBytesValue(LTCPPayLoad,aStartLevel+4,LTCPPayLoadLen,LtmpVaue2,Format('%s.Handshake.CertificateStatus.Response',[AcronymName]), 'OCSP Response:',AListDetail,nil,True,LOffset);
                  Dec(LOffset,LtmpVaue2);  

                  DoLog('TWPcapProtocolTLS.HeaderToString','TLS_HANDSHAKE_TYPE_CERT_STATUS not compleated',TWLLWarning);
                    
                  {TODO info reponse certificate}
                  Inc(LOffset,LtmpVaue2);                     
                end;
                  
              TLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA      ,
              TLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST    ,
              TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS   ,   
              TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST    ,
              TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY     ,    
              TLS_HANDSHAKE_TYPE_FINISHED               ,
              TLS_HANDSHAKE_TYPE_CERT_URL               ,
              TLS_HANDSHAKE_TYPE_SUPPLEMENTAL_DATA      ,
              TLS_HANDSHAKE_TYPE_KEY_UPDATE             ,
              TLS_HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE ,
              TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTS         :
                begin
                   //TODO
                  DoLog('TWPcapProtocolTLS.HeaderToString',Format('Record type [%d --> %s] not implemented',[LTypeRecord,LTypeRecordStr]),TWLLWarning);
                  Inc(LOffset,LContectLen);  
                end   
                
          else
              DoLog('TWPcapProtocolTLS.HeaderToString',Format('Record type [%d --> %s] invalid',[LTypeRecord,LTypeRecordStr]),TWLLError);                  
             Inc(LOffset,LContectLen); 
          end;
          
        end;     
             
      TLS_CONTENT_TYPE_APPLICATION_DATA     :
          ParserGenericBytesValue(LTCPPayLoad,aStartLevel+2,LTCPPayLoadLen,LContectLen,Format('%s.ApplicationData.Message',[AcronymName]), 'Application data message:',AListDetail,BytesToHex,True,LOffset);                                                                                  

      TLS_CONTENT_TYPE_ID_TLS12_CID : Inc(LOffset,LContectLen);

      TLS_CONTENT_TYPE_ID_HEARTBEAT  :
        begin             
          if LRecord.ProtocolVersion = TLS_VERSION_1_3 then
            DoLog('TWPcapProtocolTLS.HeaderToString','Record type is not allowed in TLS 1.3',TWLLError)                      
          else
            DoLog('TWPcapProtocolTLS.HeaderToString','TLS_CONTENT_TYPE_ID_HEARTBEAT not implemented',TWLLWarning);          
          Inc(LOffset,LContectLen);
        end;          
    else
      begin
        DoLog('TWPcapProtocolTLS.HeaderToString',Format('Record  ContentType [%d ] invalid',[LRecord.ContentType]),TWLLError);      
        Inc(LOffset,LContectLen); // TODO invalid
      end;
    end;
  end;
  aAdditionalParameters.Info := Format('%s TCP: %s',[LInfoProtocols,aAdditionalParameters.INfo] ).Trim;
  Result               := True;
end;


end.
