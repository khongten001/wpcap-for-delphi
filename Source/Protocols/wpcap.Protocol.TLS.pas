unit wpcap.Protocol.TLS;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, Wpcap.protocol.TCP, wpcap.StrUtils,
  wpcap.Types, Vcl.Dialogs, System.StrUtils, System.Classes;

type
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

  TTLSRecordHeader = packed record
    ContentType : Byte;                 // Type of the message
    Version     : Word;                 // TLS version
    Length      : array[0..1] of Byte;  // Length of the message
  end;

  TTLSRecordHeaderSSLv2 = packed record
    // SSLv2 has a different record header format
    LengthHigh  : Byte;  // Length of the message, high byte
    LengthLow   : Byte;  // Length of the message, low byte
    ContentType : Byte;  // Type of the message
  end;


  /// <summary>
  ///  Implements a TLS protocol handler to interpret and validate TLS protocol.
  /// </summary>
  TWPcapProtocolTLS = Class(TWPcapProtocolBaseTCP)
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
    class function HeaderLength: Word; override;
    /// <summary>
    /// Checks whether the packet is valid for the TLS protocol.
    /// </summary>
    class function IsValid(const aPacket:PByte;aPacketSize:Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean; override;    
End;


implementation

{ TWPcapProtocolTLS }

class function TWPcapProtocolTLS.IsValid(const aPacket:PByte;aPacketSize:Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
//var LRecordType  : Byte;
//    LPayloadSize : Integer;
begin
   Result := inherited IsValid(aPacket,aPacketSize,aAcronymName,aIdProtoDetected);
  // Check if packet is using TCP
 // if not PayLoadLengthIsValid(aTCPPtr) then  Exit;
  


  // Get the size of the payload

   {
  LPayloadSize  := aPacketSize - SizeOf(TEthHdr) + SizeOf(TIPHeader) + ( aTCPPtr.DataOff * 4);
  ShowMessage(JoinStringArray(sLineBreak,DisplayHexData(aTCPPayLoad,LPayloadSize)));
  // Check if the payload has the TLS record format
  if LPayloadSize < 5 then Exit;
  LRecordType := aTCPPayLoad^;
  Result      := (LRecordType >= 20) and (LRecordType <= 23); }
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

class function TWPcapProtocolTLS.HeaderLength: word;
begin
  Result := SizeOF(TTLSRecordHeader)
end;


end.
