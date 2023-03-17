unit wpcap.Protocol.TLS;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, Wpcap.protocol.TCP, wpcap.StrUtils,system.Variants,
  wpcap.Types, Vcl.Dialogs, System.StrUtils, System.Classes,system.SysUtils,wpcap.BufferUtils;
  
CONST MAXCIPHERSUITES = 1024;  
type

  {https://tools.ietf.org/html/rfc8446}
  TTLSHandshakeType = (
    htHelloRequest              = $00,
    htClientHello               = $01,
    htServerHello               = $02,
    htHelloVerifyRequest        = $03,
    htNewSessionTicket          = $04,
    htEndOfEarlyData            = $05,
    htHelloRetryRequest         = $06,
    htEncryptedExtensions       = $08,
    htCertificate               = $0b,
    htServerKeyExchange         = $0c,
    htCertificateRequest        = $0d,
    htServerHelloDone           = $0e,
    htCertificateVerify         = $0f,
    htClientKeyExchange         = $10,
    htFinished                  = $14,
    htCertificateUrl            = $15,
    htCertificateStatus         = $16,
    htSupplementalData          = $17,
    htKeyUpdate                 = $18,
    htMessageHash               = $fd,
    htUnknown                   = $ff
  );




  TTLSHandshakeHeader = packed record
    HandshakeType : Byte;                 //   Type of handshake message
    Length        : array[0..2] of Byte;  // Length of handshake message
  end;

  TTLSHandshakeHelloRequest = packed record
    // Empty struct for HelloRequest
  end;

  TTLSHandshakeClientHello = packed record
    Version                 : Word;                  // TLS version
    Random                  : array[0..31] of Byte;  // Client-generated random bytes
    SessionID               : record                 // Session identifier
      Length                : Byte;                  // Length of SessionID
      Data                  : array[0..31] of Byte;  // Session identifier data
    end;
    CipherSuitesLength      : Word;           // Length of CipherSuites array
    CipherSuites            : array of Word;  // List of cipher suites supported by client
    CompressionMethodsLength: Byte;           // Length of CompressionMethods array
    CompressionMethods      : array of Byte;  // List of compression methods supported by client
    ExtensionsLength        : Word;           // Length of extensions array
    Extensions              : array of Byte;  // List of extensions
  end;
  PTTLSHandshakeClientHello = ^TTLSHandshakeClientHello;

  TTLSHandshakeServerHello = packed record
    Version                 : Word;  // TLS version
    Random                  : array[0..31] of Byte;  // Server-generated random bytes
    SessionID               : record                 // Session identifier
      Length                : Byte;                  // Length of SessionID
      Data                  : array[0..31] of Byte;  // Session identifier data
    end;
    CipherSuite             : Word;          // Cipher suite chosen by server
    CompressionMethod       : Byte;          // Compression method chosen by server
    ExtensionsLength        : Word;          // Length of extensions array
    Extensions              : array of Byte; // List of extensions
  end;
  PTTLSHandshakeServerHello = ^TTLSHandshakeServerHello;
  
  TTLSRecordHeader = packed record
    ContentType    : Byte;
    ProtocolVersion: Word;
    Length         : Word;
  end;
  PTTLSRecordHeader = ^TTLSRecordHeader;

  
  TTLSRecordHeaderSSLv2 = packed record
    // SSLv2 has a different record header format
    LengthHigh  : Byte;  // Length of the message, high byte
    LengthLow   : Byte;  // Length of the message, low byte
    ContentType : Byte;  // Type of the message
  end;

type
  PTLSProtocolVersion = ^TLSProtocolVersion;
  TLSProtocolVersion = record
    Major: Byte;
    Minor: Byte;
  end;

  PTLSRandom = ^TLSRandom;
  TLSRandom = record
    UnixTime   : UInt32;
    RandomBytes: array[0..27] of Byte;
  end;

  PTLSExtension = ^TLSExtension;
  TLSExtension = record
    ExtensionType  : Word;
    ExtensionLength: Word;
    ExtensionData  : PByte;
  end;

  PTLSExtensions = ^TLSExtensions;
  TLSExtensions = record
    ExtensionsLength: Word;
    Extensions      : array[0..MAXCIPHERSUITES - 1] of TLSExtension;
  end;

  PTLSHandshake = ^TLSHandshake;

  TLSHandshake = record
    HandshakeType: Byte;
    Length       : UInt32;
    case Integer of
      0: (HelloRequest: array[0..0] of Byte);
      1: (ClientHello: record
           ProtocolVersion: TLSProtocolVersion;
           Random: TLSRandom;
           SessionIDLength: Byte;
           SessionID: array[0..31] of Byte;
           CipherSuitesLength: Word;
           CipherSuites: array[0..MAXCIPHERSUITES - 1] of Word;
           CompressionMethodsLength: Byte;
           CompressionMethods: array[0..MAXCIPHERSUITES - 1] of Byte;
           Extensions: TLSExtensions;
        end);
      2: (ServerHello: record
           ProtocolVersion: TLSProtocolVersion;
           Random: TLSRandom;
           SessionIDLength: Byte;
           SessionID: array[0..31] of Byte;
           CipherSuite: Word;
           CompressionMethod: Byte;
           Extensions: TLSExtensions;
         end);
      11: (Certificate: array[0..0] of Byte);
      12: (ServerKeyExchange: array[0..0] of Byte);
      13: (CertificateRequest: array[0..0] of Byte);
      14: (ServerHelloDone: array[0..0] of Byte);
      15: (CertificateVerify: array[0..0] of Byte);
      16: (ClientKeyExchange: array[0..0] of Byte);
      20: (Finished: array[0..35] of Byte);

  end;
  


  /// <summary>
  ///  Implements a TLS protocol handler to interpret and validate TLS protocol.
  /// </summary>
  TWPcapProtocolTLS = Class(TWPcapProtocolBaseTCP)
  private
    class function ContentTypeToString(aContentType: Byte): string; static;
    class function TLSVersionToString(aVersion: Word): string; static;
    class function Header(const aUDPPayLoad: PByte): PTTLSRecordHeader; static;
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
    class function HeaderToString(const aPacketData: PByte; aPacketSize: Integer; AListDetail: TListHeaderString): Boolean;override;       
End;


implementation

{ TWPcapProtocolTLS }

class function TWPcapProtocolTLS.Header(const aUDPPayLoad: PByte): PTTLSRecordHeader;
begin
  Result := PTTLSRecordHeader(aUDPPayLoad)
end;

class function TWPcapProtocolTLS.IsValid(const aPacket:PByte;aPacketSize:Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var LTCPHdr      : PTCPHdr;
    LTCPPayLoad  : PByte;
    LRecord      : PTTLSRecordHeader;
begin
  Result := inherited IsValid(aPacket,aPacketSize,aAcronymName,aIdProtoDetected);

  if Result then   
  begin
    if not HeaderTCP(aPacket,aPacketSize,LTCPHdr) then exit;

    LTCPPayLoad  := GetTCPPayLoad(aPacket,aPacketSize);
    LRecord      := Header(LTCPPayLoad);

    aAcronymName :=  TLSVersionToString(LRecord.ProtocolVersion);
  end;
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

class function TWPcapProtocolTLS.ContentTypeToString(aContentType: Byte): string;
begin
  case aContentType of
    TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC   : Result := 'Change cipher spec';
    TLS_CONTENT_TYPE_ALERT                : Result := 'Alert';
    TLS_CONTENT_TYPE_HANDSHAKE            : Result := 'Handshake';
    TLS_CONTENT_TYPE_APPLICATION_DATA     : Result := 'Application data';
    TLS_HANDSHAKE_TYPE_HELLO_REQUEST      : Result := 'Hello request';
    TLS_HANDSHAKE_TYPE_CLIENT_HELLO       : Result := 'Client hello';
    TLS_HANDSHAKE_TYPE_SERVER_HELLO       : Result := 'Server hello';    
    TLS_HANDSHAKE_TYPE_CERTIFICATE        : Result := 'Certificate';    
    TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE: Result := 'Server key exchange';
    TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST: Result := 'Certificate request';
    TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE  : Result := 'Server hello done'; 
    TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY : Result := 'Certificate verify';
    TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE: Result := 'Client key exchange';
  //  TLS_HANDSHAKE_TYPE_FINISHED           : Result := 'Finished';
  else
    Result := Format('Unknown (%d)', [aContentType]);
  end;
end;

class function TWPcapProtocolTLS.TLSVersionToString(aVersion: Word): string;
begin
  case aVersion of
    TLS_VERSION_1_0: Result := 'TLS 1.0';
    TLS_VERSION_1_1: Result := 'TLS 1.1';
    TLS_VERSION_1_2: Result := 'TLS 1.2';
    TLS_VERSION_1_3: Result := 'TLS 1.3';
    else Result := 'TLS';
  end;
end;

class function TWPcapProtocolTLS.HeaderToString(const aPacketData: PByte; aPacketSize: Integer; AListDetail: TListHeaderString): Boolean;
var LOffset                 : Integer;
    LRecord                 : PTTLSRecordHeader;
    LHandshake              : PTLSHandshake;
    LCipherSuite            : PWord;
    LCompressionMethod      : PByte;
    LExtensions             : PTLSExtension;
    LExtensionType          : PWord;
    LExtensionData          : PByte;
    LExtensionLen           : PWord;
    LClientHello            : PTTLSHandshakeClientHello;
    LServerHello            : PTTLSHandshakeServerHello;
    LVersion                : PWord;
    LRandom                 : PTLSRandom;
    LSessionID              : PByte;
    LSessionIDLen           : Byte;
    LSessionResumption      : Boolean;
    LSessionResumptionString: string;
    LSessionTicket          : PTLSExtension;
    LSessionTicketData      : PByte;
    LSessionTicketLen       : Word;
    LExtensionsLen          : Word;
    LListExtensions         : TListHeaderString;
    LTCPHdr                 : PTCPHdr;
    LTCPPayLoad             : PByte;
begin
  Result  := False;
  LOffset := 0;

  if aPacketSize < SizeOf(TTLSRecordHeader) then Exit;
  if not HeaderTCP(aPacketData,aPacketSize,LTCPHdr) then exit;
  
  LTCPPayLoad := GetTCPPayLoad(aPacketData,aPacketSize);
  LRecord     := Header(LTCPPayLoad);
  LOffset     := 0;

  if aPacketSize < TCPPayLoadLength(LTCPHdr,aPacketData,aPacketSize)-1+SizeOf(TTLSRecordHeader) then exit;
  
  AListDetail.Add(AddHeaderInfo(0, Format('%s (%s)', [ProtoName, AcronymName]), null, PByte(LRecord), SizeOf(TTLSRecordHeader)));

  while True do
  begin


    LRecord := PTTLSRecordHeader(PByte(LTCPPayLoad) + LOffset);
    Inc(LOffset, SizeOf(TTLSRecordHeader));

    AListDetail.Add(AddHeaderInfo(1, 'Content type', ContentTypeToString(LRecord.ContentType), @LRecord.ContentType, SizeOf(LRecord.ContentType)));
    AListDetail.Add(AddHeaderInfo(1, 'Protocol version', TLSVersionToString(LRecord.ProtocolVersion), @LRecord.ProtocolVersion, SizeOf(LRecord.ProtocolVersion)));
    AListDetail.Add(AddHeaderInfo(1, 'Content length', wpcapntohs(LRecord.Length), @LRecord.Length, SizeOf(LRecord.Length) ));    

    if aPacketSize >= LOffset + SizeOf(TLSHandshake) then

    if  ( aPacketSize >= LOffset + SizeOf(TTLSRecordHeader) + SizeOf(TLSHandshake) ) then
    begin
      
      case LRecord.ContentType of

        TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC   :
          begin
          
          end;
        TLS_CONTENT_TYPE_ALERT                : 
          begin
          
          end;        
        TLS_CONTENT_TYPE_HANDSHAKE            :
          begin
            LHandshake := PTLSHandshake(PByte(aPacketData) + LOffset);                  
            Inc(LOffset, SizeOf(TLSHandshake));
            AListDetail.Add(AddHeaderInfo(1,'Handshake',null,PByte(LHandshake),SizeOf(TLSHandshake)));
            AListDetail.Add(AddHeaderInfo(2, 'Handshake type', ContentTypeToString(LHandshake.HandshakeType), @LHandshake.HandshakeType, SizeOf(LHandshake.HandshakeType)));
            AListDetail.Add(AddHeaderInfo(2, 'Length', wpcapntohs(LHandshake.Length), @LHandshake.Length, SizeOf(LHandshake.Length)));
            case LHandshake.HandshakeType of
              TLS_HANDSHAKE_TYPE_CLIENT_HELLO :
              begin
                LClientHello := PTTLSHandshakeClientHello(PByte(aPacketData) + LOffset);
                Inc(LOffset, SizeOf(TTLSHandshakeClientHello));

                AListDetail.Add(AddHeaderInfo(3, 'Protocol version', TLSVersionToString(LClientHello.Version), @LClientHello.Version, SizeOf(LClientHello.Version)));
                LRandom := PTLSRandom(@LClientHello.Random);              
              end;
            end;
        
          end;        
        TLS_CONTENT_TYPE_APPLICATION_DATA     :
          begin
          
          end;        
        TLS_HANDSHAKE_TYPE_HELLO_REQUEST      :
          begin
          
          end;        
        TLS_HANDSHAKE_TYPE_CLIENT_HELLO       :
          begin
          
          end;        
        TLS_HANDSHAKE_TYPE_SERVER_HELLO       :
          begin
          
          end;        
        TLS_HANDSHAKE_TYPE_CERTIFICATE        :
          begin
          
          end;        
        TLS_HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
          begin
          
          end;        
        TLS_HANDSHAKE_TYPE_CERTIFICATE_REQUEST:
          begin
          
          end;        
        TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE  :
          begin
          
          end;        
        TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY :
          begin
          
          end;        
        TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE:
          begin
          
          end;        
      end;
    end;
    break;
  end;
  Result := True;
end;


end.
