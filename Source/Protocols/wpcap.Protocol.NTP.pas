unit wpcap.Protocol.NTP;

interface

uses wpcap.Protocol.Base,wpcap.Conts;

type

  /// <summary>
  /// Represents the header for the Network Time Protocol (NTP).
  /// </summary>
  TNTPHeader = packed record
    LI_VN_MODE    : Byte;                // Leap indicator, version number, and mode.
    Stratum       : Byte;                // Stratum level of the local clock.
    Poll          : Byte;                // Maximum interval between successive messages.
    Precision     : Byte;                // Precision of the local clock.
    RootDelay     : Cardinal;            // Total round-trip delay to the reference clock.
    RootDispersion: Cardinal;            // Maximum error due to network congestion.
    ReferenceID   : Cardinal;            // Reference clock identifier.
    ReferenceTS   : array[0..7] of Byte; // Timestamp of the last update from the reference clock.
    OriginateTS   : array[0..7] of Byte; // Timestamp when the request was sent by the client.
    ReceiveTS     : array[0..7] of Byte; // Timestamp when the request was received by the server.
    TransmitTS    : array[0..7] of Byte; // Timestamp when the reply was sent by the server.
  end;
  PNTPHeader = ^TNTPHeader;


  /// <summary>
  /// Represents the Network Time Protocol (NTP) protocol for WireShark.
  /// </summary>
  TWPcapProtocolNTP = class(TWPcapProtocolBaseUDP)
  public
    /// <summary>
    /// Returns the default port number used by the NTP protocol.
    /// </summary>
    class function DefaultPort: Word; override;

    /// <summary>
    /// Return Intenal protocol ID
    /// </summary>
    class function IDDetectProto: Integer; override;

    /// <summary>
    /// Returns the name of the protocol for the NTP protocol
    /// </summary>
    class function ProtoName: String; override;

    /// <summary>
    /// Returns the acronym name for the NTP protocol.
    /// </summary>
    class function AcronymName: String; override;

    /// <summary>
    /// Returns the header length of the NTP protocol.
    /// </summary>
    class function HeaderLength: Word; override;

    /// <summary>
    /// Returns a pointer to the NTP header in the UDP payload.
    /// </summary>
    class function Header(const aUDPPayLoad: PByte): PNTPHeader; static;
end;


implementation

{  {// Cast del puntatore del pacchetto al tipo di header NTP
  ntpHeader := PNTPHeader(aUDPPayLoad);
                                       
  if ((ntpHeader.LI_VN_MODE and $38) shr 3 <= 4) then
  begin
    LNTPVersione := ntpHeader.LI_VN_MODE shr 3;

    if (LUDPLength > 3) and (LNTPVersione = 2) then
    begin
      Result := True;  
    end;
  end;  }

class function TWPcapProtocolNTP.DefaultPort: Word;
begin
  Result := PROTO_NTP_PORT;
end;

class function TWPcapProtocolNTP.IDDetectProto: Integer;
begin
  Result := DETECT_PROTO_NTP;
end;

class function TWPcapProtocolNTP.ProtoName: String;
begin
  Result := 'Network Time Protocol'
end;

class function TWPcapProtocolNTP.AcronymName: String;
begin
  Result := 'NTP';
end;

class function TWPcapProtocolNTP.HeaderLength: word;
begin
  Result := SizeOf(TNTPHeader);
end;

class function TWPcapProtocolNTP.Header(const aUDPPayLoad: PByte): PNTPHeader;
begin
  Result := PNTPHeader(aUDPPayLoad);
end;


end.
