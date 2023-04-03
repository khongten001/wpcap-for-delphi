﻿unit wpcap.Protocol.TLS;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, Wpcap.protocol.TCP, wpcap.StrUtils,system.Variants,idGlobal,
  wpcap.Types, Vcl.Dialogs, System.StrUtils, System.Classes,system.SysUtils,wpcap.BufferUtils;
  
type

  
  TTLSRecordHeader = packed record
    ContentType    : Byte;
    ProtocolVersion: Word;
    Length         : Word;
  end;
  PTTLSRecordHeader = ^TTLSRecordHeader;


  PTLSRandom = ^TLSRandom;
  TLSRandom = record
    UnixTime   : UInt32;
    RandomBytes: array[0..27] of Byte;
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

  
    SSLV2_VERSION                          = $0002;
    SSLV3_VERSION                          = $0300;
    TLCPV1_VERSION                         = $101;
    TLS_VERSION_1_0                        = $103; 
    TLS_VERSION_1_1                        = $0302;
    TLS_VERSION_1_2                        = $0303;
    TLS_VERSION_1_3                        = $0304;
    DTLSV1DOT0_VERSION                     = $feff;
    DTLSV1DOT0_OPENSSL_VERSION             = $100;
    DTLSV1DOT2_VERSION                     = $fefd;
    DTLSV1DOT3_VERSION                     = $fefc;
    
  
    class function ContentTypeToString(aContentType: Byte): string; static;
    class function TLSVersionToString(aVersion: Word): string; static;
    class function Header(const aUDPPayLoad: PByte): PTTLSRecordHeader; static;
    class function KnowVersion(aVersion: Word): Boolean; static;
    class function ChipherToString(aChipher: Word): string; static;
    class function HandShakeTypeToString(aRecodType: Byte): string; static;
    class function CompressionToString(const aCompression: Byte): String; static;
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
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;override;       
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
begin
  Result := False;
  if not HeaderTCP(aPacket,aPacketSize,LTCPHdr) then exit;
  
  LTCPPayLoad    := GetTCPPayLoad(aPacket,aPacketSize);
  LRecord        := Header(LTCPPayLoad);

  if not KnowVersion(LRecord.ProtocolVersion) then
  begin
    Result           := False;
    aAcronymName     := inherited AcronymName; 
    aIdProtoDetected := inherited IDDetectProto;
    Exit;
  end
  else
    Result := True;
    
  aAcronymName     := TLSVersionToString(LRecord.ProtocolVersion);
  aIdProtoDetected := IDDetectProto;
  LTCPPayLoadLen   := TCPPayLoadLength(LTCPHdr,aPacket,aPacketSize);

  if wpcapntohs(LRecord.Length) > LTCPPayLoadLen then
    aAcronymName := 'SSL';
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

class function TWPcapProtocolTLS.HandShakeTypeToString(aRecodType: Byte): string;
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

class function TWPcapProtocolTLS.CompressionToString(const aCompression : Byte):String;
begin
  case aCompression of
      0 : Result := 'null';
      1 : Result := 'DEFLATE';
     64 : Result := 'LZS';    
  else
    Result := Format('Unknown (%d)', [aCompression]);
  end;
end;


class function TWPcapProtocolTLS.ChipherToString(aChipher: Word): string;
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

class function TWPcapProtocolTLS.TLSVersionToString(aVersion: Word): string;
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

class function TWPcapProtocolTLS.HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;
var LOffset         : Integer;
    LRecord         : PTTLSRecordHeader;    
    LVersion        : PWord;
    LTCPHdr         : PTCPHdr;
    LTCPPayLoad     : PByte;
    LTCPPayLoadLen  : Integer;
    LContectLen     : Integer;
    LByteValue      : Byte;
    LByteValue2     : Byte;
    LTypeRecord     : Byte;
    LBytes          : TidBytes;
    LtmpVaue        : Integer;
    LtmpVaue2       : Integer;
    LHandShakeLen   : integer;
    LWordValue      : Word;
    I               : Integer;

    Procedure LoadCommonFieldHello(const aContentType:String);
    begin
        LWordValue := PWord(LTCPPayLoad+LOffset)^;
        AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.%s.Version',[aContentType,AcronymName]), 'Version:', TLSVersionToString(LWordValue), @LWordValue, SizeOf(LWordValue), LWordValue ));
        Inc(LOffset,SizeOf(LWordValue));

        SetLength(LBytes,32);
        Move(LTCPPayLoad[LOffset],LBytes[0],32);                 
        AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.%s.Random',[aContentType,AcronymName]), 'Random:',ToHex(LBytes), @LBytes, Length(LBytes) ));
        Inc(LOffset,32);            
            

        LByteValue := PByte(LTCPPayLoad+LOffset)^;
        AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.%s.SessionIDLen',[aContentType,AcronymName]), 'Session ID length:', LByteValue, @LByteValue, SizeOf(LByteValue) ));
        Inc(LOffset,SizeOf(LByteValue));
            
        if LByteValue > 0 then
        begin
          SetLength(LBytes,LByteValue);
          Move(LTCPPayLoad[LOffset],LBytes[0],LByteValue);                 
          AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.%s.SessionID',[aContentType,AcronymName]), 'Session ID:',ToHex(LBytes), @LBytes, Length(LBytes) ));
          Inc(LOffset,LByteValue);             
        end;    
    end;
begin
  Result       := False;
 FIsFilterMode := aIsFilterMode;

  if aPacketSize < SizeOf(TTLSRecordHeader) then Exit;
  if not HeaderTCP(aPacketData,aPacketSize,LTCPHdr) then exit;
  
  LTCPPayLoad    := GetTCPPayLoad(aPacketData,aPacketSize);
  LRecord        := Header(LTCPPayLoad);
  LTCPPayLoadLen := TCPPayLoadLength(LTCPHdr,aPacketData,aPacketSize);
  LOffset     := 0;

  if aPacketSize < TCPPayLoadLength(LTCPHdr,aPacketData,aPacketSize)-1+SizeOf(TTLSRecordHeader) then exit;
  
  AListDetail.Add(AddHeaderInfo(aStartLevel,AcronymName, Format('%s (%s)', [ProtoName, AcronymName]), null, LTCPPayLoad,LTCPPayLoadLen ));

  
  while LOffset < LTCPPayLoadLen do
  begin
    LRecord := PTTLSRecordHeader(LTCPPayLoad + LOffset);
    Inc(LOffset, SizeOf(TTLSRecordHeader));
    

    LContectLen :=  wpcapntohs(LRecord.Length);

    if LContectLen > LTCPPayLoadLen then exit;
    
    
    SetLength(LBytes,LContectLen);
    Move(LTCPPayLoad[LOffset],LBytes[0],LContectLen); 
                    
    AListDetail.Add(AddHeaderInfo(aStartLevel+1,Format('%s.RecordLayer',[AcronymName]), Format('%s record layer: %s', [TLSVersionToString(LRecord.ProtocolVersion), ContentTypeToString(LRecord.ContentType)]), null, @LBytes,length(LBytes) ));
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.ContentType',[AcronymName]), 'Content type', ContentTypeToString(LRecord.ContentType), @LRecord.ContentType, SizeOf(LRecord.ContentType), LRecord.ContentType ));
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Version',[AcronymName]), 'Version', TLSVersionToString(LRecord.ProtocolVersion), @LRecord.ProtocolVersion, SizeOf(LRecord.ProtocolVersion), LRecord.ProtocolVersion ));    
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.ContentLen',[AcronymName]), 'Content length',LContectLen, @LRecord.Length, SizeOf(LRecord.Length) ));  
    
      case LRecord.ContentType of

        TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC   :
          begin
            LByteValue := PByte(LTCPPayLoad+LOffset)^;
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.ChangeCipherr.Type',[AcronymName]), 'Change cipher:', ChipherToString(LByteValue), @LByteValue, SizeOf(LByteValue), LByteValue ));
            Inc(LOffset,SizeOf(LByteValue));
          end;
        TLS_CONTENT_TYPE_ALERT                : 
          begin
            SetLength(LBytes,LContectLen);
            Move(LTCPPayLoad[LOffset],LBytes[0],LContectLen);                 
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Alert.Message',[AcronymName]), 'Alert Message',ToHex(LBytes), @LBytes, Length(LBytes) ));
            Inc(LOffset,LContectLen);          
          end;      
            
          TLS_CONTENT_TYPE_HANDSHAKE            :
          begin

            LTypeRecord := PByte(LTCPPayLoad+LOffset)^;
          
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Handshake',[AcronymName]), Format('Handshake: %s',[HandShakeTypeToString(LTypeRecord)]),null,PByte(LTCPPayLoad+LOffset),LContectLen ));                 
            AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.Type',[AcronymName]), 'Handshake type:', HandShakeTypeToString(LTypeRecord), @LTypeRecord, SizeOf(LTypeRecord), LTypeRecord ));
            Inc(LOffset,SizeOf(LTypeRecord));

            SetLength(LBytes,3);
            Move(LTCPPayLoad[LOffset],LBytes[0],3);             
            LHandShakeLen := wpcapntohl(BytesToInt32(LBytes));
            AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.Len',[AcronymName]), 'Length:',LHandShakeLen, @LBytes, Length(LBytes) ));
            Inc(LOffset,3);



            case LTypeRecord of
              TLS_HANDSHAKE_TYPE_HELLO_REQUEST,
              TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE,
              TLS_HANDSHAKE_TYPE_HELLO_VERIFY_REQUEST : ;//nothing to do!!
              
              TLS_HANDSHAKE_TYPE_CLIENT_HELLO :
                begin
                  LoadCommonFieldHello('ClientHello');

                  LWordValue := wpcapntohs(PWord(LTCPPayLoad+LOffset)^);
                  AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.ClientHello.CipherSuitesLen',[AcronymName]), 'Cipher Suites length:', LWordValue, @LWordValue, SizeOf(LWordValue) ));            
                  Inc(LOffset,SizeOf(LWordValue));        

                  SetLength(LBytes,LWordValue);
                  Move(LTCPPayLoad[LOffset],LBytes[0],LWordValue);                   
                  AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.ClientHello.CipherSuites',[AcronymName]), 'Cipher Suites',null,@LBytes,Length(LBytes) ));  

                  for I := 0 to (LWordValue div 2) - 1 do
                  begin
                    if LOffset > LTCPPayLoadLen then Exit;
                    
                    LWordValue := wpcapntohs(PWord(LTCPPayLoad+LOffset)^);
                    AListDetail.Add(AddHeaderInfo(aStartLevel+4, Format('%s.Handshake.ClientHello.CipherSuitesLen',[AcronymName]), 'Cipher Suites:', ChipherToString(LWordValue), @LWordValue, SizeOf(LWordValue), LWordValue ));            
                    Inc(LOffset,SizeOf(LWordValue));                  
                  end;

                  LByteValue2 := (PWord(LTCPPayLoad+LOffset)^);
                  AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.ClientHello.CompressionMethodsLen',[AcronymName]),'Compression Methods Length:', LByteValue2, @LByteValue2, SizeOf(LByteValue2) ));            
                  Inc(LOffset,SizeOf(LByteValue2));       

                  SetLength(LBytes,LByteValue2);
                  Move(LTCPPayLoad[LOffset],LBytes[0],LByteValue2);                   
                  AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.ClientHello.CompressionMethods',[AcronymName]), 'Compression Methods',null,@LBytes,Length(LBytes) ));              
                          
                  for I := 0 to LByteValue2 - 1 do
                  begin
                    if LOffset > LTCPPayLoadLen then Exit;

                    LByteValue := PByte(LTCPPayLoad+LOffset)^;
                    AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.ClientHello.CompressionMethods.value',[AcronymName]), 'Compression method:', CompressionToString(LByteValue), @LByteValue, SizeOf(LByteValue), LByteValue ));
                    Inc(LOffset,SizeOf(LByteValue));                    
                  end;

                  if LOffset < LTCPPayLoadLen then
                  begin
                    LWordValue := wpcapntohs(PWord(LTCPPayLoad+LOffset)^);
                    AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.ClientHello.ExtensionsLen',[AcronymName]), 'Extensions Length:', LWordValue, @LWordValue, SizeOf(LWordValue) ));            
                    Inc(LOffset,SizeOf(LWordValue));
                    {//TODO Extens}    
                    Inc(LOffset,LWordValue);                               
                  end;                
                end;

              TLS_HANDSHAKE_TYPE_SERVER_HELLO :
                begin
                  LoadCommonFieldHello('ServerHello');

                  LWordValue := (PWord(LTCPPayLoad+LOffset)^);                  
                  AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.ServerHello.CipherSuites',[AcronymName]), 'Cipher Suites',ChipherToString(LWordValue),@LWordValue,SizeOf(LWordValue), LWordValue ));  
                  Inc(LOffset,SizeOf(LWordValue));

                  LByteValue := PByte(LTCPPayLoad+LOffset)^;              
                  AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.ServerHello.CompressionMethods',[AcronymName]), 'Compression Methods',CompressionToString(LByteValue),@LByteValue,SizeOf(LByteValue),LByteValue ));              
                  Inc(LOffset,SizeOf(LByteValue));                          
                  
                  if LOffset < LTCPPayLoadLen then
                  begin
                    LWordValue := wpcapntohs(PWord(LTCPPayLoad+LOffset)^);
                    AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.ClientHello.ExtensionsLen',[AcronymName]), 'Extensions Length:', LWordValue, @LWordValue, SizeOf(LWordValue) ));            
                    Inc(LOffset,SizeOf(LWordValue));
                    {Extens}    
                    Inc(LOffset,LWordValue);                               
                  end;                
                end;                

                
              TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE:
                begin
                  SetLength(LBytes,LHandShakeLen);
                  Move(LTCPPayLoad[LOffset],LBytes[0],LHandShakeLen);                 
                  AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.ClientKeyExChange.Record',[AcronymName]), 'Diffie-Hellman Server Params',null, @LBytes, Length(LBytes) ));
                  ParserByteValue(LTCPPayLoad,aStartLevel+4,Format('%s.Handshake.ClientKeyExChange.PubkeyLen',[AcronymName]),'Pubkey Length:',AListDetail,LOffset);
                  SetLength(LBytes,LHandShakeLen-1);
                  Move(LTCPPayLoad[LOffset],LBytes[0],LHandShakeLen-1);                 
                  AListDetail.Add(AddHeaderInfo(aStartLevel+4, Format('%s.Handshake.ClientKeyExChange.Pubkey',[AcronymName]), 'Pubkey:',ToHex(LBytes), @LBytes, Length(LBytes) ));                  
                  Inc(LOffset,LHandShakeLen-1);                  
                end;

              TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE :
                begin
                  SetLength(LBytes,LHandShakeLen);
                  Move(LTCPPayLoad[LOffset],LBytes[0],LHandShakeLen);                 
                  AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.ServerKeyExChange.Record',[AcronymName]), 'EC Diffie-Hellman Client Params',null, @LBytes, Length(LBytes) ));

                  LWordValue := wpcapntohs(PWord(LTCPPayLoad+LOffset)^);
                  AListDetail.Add(AddHeaderInfo(aStartLevel+4, Format('%s.Handshake.ServerKeyExChange.p.len',[AcronymName]), 'p Length:', LWordValue, @LWordValue, SizeOf(LWordValue) ));            
                  Inc(LOffset,SizeOf(LWordValue));            
                     
                  SetLength(LBytes,LWordValue);
                  Move(LTCPPayLoad[LOffset],LBytes[0],LWordValue);                 
                  AListDetail.Add(AddHeaderInfo(aStartLevel+4, Format('%s.Handshake.ServerKeyExChange.p',[AcronymName]), 'p:',ToHex(LBytes), @LBytes, Length(LBytes) ));                  
                  Inc(LOffset,LWordValue);   

                  LWordValue := wpcapntohs(PWord(LTCPPayLoad+LOffset)^);
                  AListDetail.Add(AddHeaderInfo(aStartLevel+4, Format('%s.Handshake.ServerKeyExChange.g.len',[AcronymName]), 'g Length:', LWordValue, @LWordValue, SizeOf(LWordValue) ));            
                  Inc(LOffset,SizeOf(LWordValue));                      
                
                  SetLength(LBytes,LWordValue);
                  Move(LTCPPayLoad[LOffset],LBytes[0],LWordValue);                 
                  AListDetail.Add(AddHeaderInfo(aStartLevel+4, Format('%s.Handshake.ServerKeyExChange.g',[AcronymName]), 'g:',ToHex(LBytes), @LBytes, Length(LBytes) ));                  
                  Inc(LOffset,LWordValue);   

                  LWordValue := wpcapntohs(PWord(LTCPPayLoad+LOffset)^);
                  AListDetail.Add(AddHeaderInfo(aStartLevel+4, Format('%s.Handshake.ServerKeyExChange.PublicKey.len',[AcronymName]), 'PublicKey Length:', LWordValue, @LWordValue, SizeOf(LWordValue) ));            
                  Inc(LOffset,SizeOf(LWordValue));                      
                
                  SetLength(LBytes,LWordValue);
                  Move(LTCPPayLoad[LOffset],LBytes[0],LWordValue);                 
                  AListDetail.Add(AddHeaderInfo(aStartLevel+4, Format('%s.Handshake.ServerKeyExChange.PublicKey',[AcronymName]), 'PublicKey:',ToHex(LBytes), @LBytes, Length(LBytes) ));                  
                  Inc(LOffset,LWordValue);                  

                  LWordValue := wpcapntohs(PWord(LTCPPayLoad+LOffset)^);
                  AListDetail.Add(AddHeaderInfo(aStartLevel+4, Format('%s.Handshake.ServerKeyExChange.Signature.len',[AcronymName]), 'Signature Length:', LWordValue, @LWordValue, SizeOf(LWordValue) ));            
                  Inc(LOffset,SizeOf(LWordValue));                      
                
                  SetLength(LBytes,LWordValue);
                  Move(LTCPPayLoad[LOffset],LBytes[0],LWordValue);                 
                  AListDetail.Add(AddHeaderInfo(aStartLevel+4, Format('%s.Handshake.ServerKeyExChange.Signature',[AcronymName]), 'Signature:',ToHex(LBytes), @LBytes, Length(LBytes) ));                  
                  Inc(LOffset,LWordValue);                                       
                end;  

              TLS_HANDSHAKE_TYPE_CERTIFICATE :
                begin
                  SetLength(LBytes,3);
                  Move(LTCPPayLoad[LOffset],LBytes[0],3);         
                  LtmpVaue := wpcapntohl(BytesToInt32(LBytes));     
                  AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.Certificate.len',[AcronymName]), 'Certificate length:',LtmpVaue, @LBytes, Length(LBytes) ));
                  Inc(LOffset,3);                  

                  SetLength(LBytes,LtmpVaue);
                  Move(LTCPPayLoad[LOffset],LBytes[0],LtmpVaue);   
                  AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Handshake.Certificate.Certificates',[AcronymName]), 'Certificates:',Null, @LBytes, Length(LBytes) ));                                        
                  while LOffset < LHandShakeLen do
                  begin
                    SetLength(LBytes,3);
                    Move(LTCPPayLoad[LOffset],LBytes[0],3);         
                    LtmpVaue2 := wpcapntohl(BytesToInt32(LBytes));     
                    AListDetail.Add(AddHeaderInfo(aStartLevel+4, Format('%s.Handshake.Certificate.Certificate.len',[AcronymName]), 'Certificate length:',LtmpVaue2, @LBytes, Length(LBytes) ));
                    Inc(LOffset,3);     

                    SetLength(LBytes,LtmpVaue2);
                    Move(LTCPPayLoad[LOffset],LBytes[0],LtmpVaue2);   
                    AListDetail.Add(AddHeaderInfo(aStartLevel+4, Format('%s.Handshake.Certificate.Certificates',[AcronymName]), 'Certificate:',Null, @LBytes, Length(LBytes) ));                        

                    {TODO info certificate}
                    Inc(LOffset,LtmpVaue2);                    
                  end;                  
                end;
                      
                TLS_HANDSHAKE_TYPE_NEWSESSION_TICKET      ,
                TLS_HANDSHAKE_TYPE_END_OF_EARLY_DATA      ,
                TLS_HANDSHAKE_TYPE_HELLO_RETRY_REQUEST    ,
                TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS   ,   
                TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST    ,
                TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY     ,    
                TLS_HANDSHAKE_TYPE_FINISHED               ,
                TLS_HANDSHAKE_TYPE_CERT_URL               ,
                TLS_HANDSHAKE_TYPE_CERT_STATUS            ,
                TLS_HANDSHAKE_TYPE_SUPPLEMENTAL_DATA      ,
                TLS_HANDSHAKE_TYPE_KEY_UPDATE             ,
                TLS_HANDSHAKE_TYPE_COMPRESSED_CERTIFICATE ,
                TLS_HANDSHAKE_TYPE_ENCRYPTED_EXTS         :
                  begin
                     //TODO
                    Inc(LOffset,LContectLen);  
                  end   
                
            else
               Inc(LOffset,LContectLen); 
            end;
          
          end;     
             
        TLS_CONTENT_TYPE_APPLICATION_DATA     :
          begin
            SetLength(LBytes,LContectLen);
            Move(LTCPPayLoad[LOffset],LBytes[0],LContectLen);                 
            AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.ApplicationData.Message',[AcronymName]), 'Application data message',ToHex(LBytes), @LBytes, Length(LBytes) ));
            Inc(LOffset,LContectLen);    
          end;        

        TLS_CONTENT_TYPE_ID_HEARTBEAT  :
          begin              //TODO
             Inc(LOffset,LContectLen);
          end;
        TLS_CONTENT_TYPE_ID_TLS12_CID : 
          begin             //TODO
             Inc(LOffset,LContectLen);
          end;
          
      else
        Inc(LOffset,LContectLen); // TODO invalid
      end;

  end;
  Result := True;
end;


end.
