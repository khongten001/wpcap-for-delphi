﻿//*************************************************************
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

unit wpcap.Protocol.NTP;

interface

uses
  wpcap.Protocol.UDP, wpcap.Conts, wpcap.Types, wpcap.BufferUtils,WinApi.Windows,wpcap.packet,
  System.SysUtils, System.Variants,System.Math,winsock,DateUtils;

type
  {https://datatracker.ietf.org/doc/html/rfc5905}

  TNtpTimestamp = packed record
    case Integer of
      0: (IntegerPart: LongWord; FractionPart: LongWord);
      1: (Bytes: array[0..7] of Uint8);
  end;
    

  /// <summary>
  /// Represents the header for the Network Time Protocol (NTP).
  /// </summary>
  TNTPHeader = packed record
    LI_VN_MODE    : Uint8;          // Leap indicator, version number, and mode.
    Stratum       : Uint8;          // Stratum level of the local clock.
    Poll          : Uint8;          // Maximum interval between successive messages.
    Precision     : Uint8;          // Precision of the local clock.
    RootDelay     : LongInt;       // Total round-trip delay to the reference clock.
    RootDispersion: LongInt;       // Maximum error due to network congestion.
    ReferenceID   : LongInt ;      // Reference clock identifier.
    ReferenceTS   : TNtpTimestamp; // Timestamp of the last update from the reference clock.
    OriginateTS   : TNtpTimestamp; // Timestamp when the request was sent by the client.
    ReceiveTS     : TNtpTimestamp; // Timestamp when the request was received by the server.
    TransmitTS    : TNtpTimestamp; // Timestamp when the reply was sent by the server.
  end;
  PNTPHeader = ^TNTPHeader;

  {

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |LI | VN  |Mode |    Stratum    |     Poll      |  Precision   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Root Delay                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Root Dispersion                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Reference Identifier                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                                |
    |                    Reference Timestamp (64)                    |
    |                                                                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                                |
    |                    Originate Timestamp (64)                    |
    |                                                                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                                |
    |                     Receive Timestamp (64)                     |
    |                                                                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                                |
    |                     Transmit Timestamp (64)                    |
    |                                                                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Key Identifier (optional) (32)                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                                |
    |                                                                |
    |                 Message Digest (optional) (128)                |
    |                                                                |
    |                                                                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    }

  
  /// <summary>
  /// Represents the Network Time Protocol (NTP) protocol for WireShark.
  /// </summary>
  TWPcapProtocolNTP = class(TWPcapProtocolBaseUDP)
  private
    class  function MessageTypeToString(aMsgType: Uint8): String;static;
    class function StratumToString(const aStratum: Uint8): String; static;
    class function GetNTPLeapIndicatorString(ALeapIndicator: Uint8): string; static;
  public
    /// <summary>
    /// Returns the default port number used by the NTP protocol.
    /// </summary>
    class function DefaultPort: Word; override;

    /// <summary>
    /// Return Intenal protocol ID
    /// </summary>
    class function IDDetectProto: byte; override;

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
    class function HeaderLength(aFlag:Byte): Word; override;

    /// <summary>
    /// Returns a pointer to the NTP header in the UDP payload.
    /// </summary>
    class function Header(const aUDPPayLoad: PByte): PNTPHeader; static;
    /// <summary>
    ///  Converts the NTP header to a string and adds it to the list of header details.
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
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalInfo: PTAdditionalInfo): Boolean; override;     
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

class function TWPcapProtocolNTP.IDDetectProto: byte;
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

class function TWPcapProtocolNTP.HeaderLength(aFlag:Byte): word;
begin
  Result := SizeOf(TNTPHeader);
end;

class function TWPcapProtocolNTP.Header(const aUDPPayLoad: PByte): PNTPHeader;
begin
  Result := PNTPHeader(aUDPPayLoad);
end;


class function TWPcapProtocolNTP.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalInfo: PTAdditionalInfo): Boolean;  
var LHeaderNTP     : PNTPHeader;
    LPUDPHdr       : PUDPHdr;
    LUDPPayLoad    : PByte;
    Loffset        : Word;
    LUDPPayLoadLen : Integer;
    LMode          : String;

  function GetDateTimeFromNTPTimeStamp(const aNTPTimestamp: TNtpTimestamp): TDateTime;
  begin
    Result := UnixToDateTime(Int64(wpcapntohl(PCardinal(@aNTPTimestamp.IntegerPart)^)) - 2208988800);
    {TODO add milliseconds...}
  end;
 
begin
  Result := False;
  if not HeaderUDP(aPacketData, aPacketSize, LPUDPHdr) then Exit;
  
  LUDPPayLoad    := GetUDPPayLoad(aPacketData, aPacketSize);
  LUDPPayLoadLen := UDPPayLoadLength(LPUDPHdr)-8; 
  LHeaderNTP     := Header(LUDPPayLoad);
  FIsFilterMode  := aIsFilterMode;

  if not Assigned(LHeaderNTP) then exit;
  
  AListDetail.Add(AddHeaderInfo(aStartLevel, AcronymName, Format('%s (%s)', [ProtoName, AcronymName]), null, LUDPPayLoad,LUDPPayLoadLen ));
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.HeaderLen',[AcronymName]), 'Header length', HeaderLength(0),nil,0));

 
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Flags',[AcronymName]), 'Flags', ByteToBinaryString(LHeaderNTP.LI_VN_MODE), @LHeaderNTP.LI_VN_MODE,SizeOf(LHeaderNTP.LI_VN_MODE), LHeaderNTP.LI_VN_MODE ));
  
  // 1-byte field that specifies the NTP message type
  //LI: 2 bit - Leap Indicator
  //VN: 3 bit - Version Number 
  //VM: 3 bit - Mode

  AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.LeapIndicator',[AcronymName]), 'Leap Indicator', GetNTPLeapIndicatorString(LHeaderNTP.LI_VN_MODE and $03), @LHeaderNTP.LI_VN_MODE,SizeOf(LHeaderNTP.LI_VN_MODE), LHeaderNTP.LI_VN_MODE and $03));   {TODO TO STRING}
  AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.Version',[AcronymName]), 'Version',  (LHeaderNTP.LI_VN_MODE and $38) shr 3, @LHeaderNTP.LI_VN_MODE,SizeOf(LHeaderNTP.LI_VN_MODE), (LHeaderNTP.LI_VN_MODE and $38) shr 3));

  LMode := MessageTypeToString(GetLastNBit(LHeaderNTP.LI_VN_MODE,3));
  AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.Mode',[AcronymName]), 'Mode',LMode ,@LHeaderNTP.LI_VN_MODE,SizeOf(LHeaderNTP.LI_VN_MODE), GetLastNBit(LHeaderNTP.LI_VN_MODE,3) ));

  // 1-byte field that specifies the stratum level of the local clock
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.PeerClockStratum',[AcronymName]), 'Peer clock stratum',StratumToString(LHeaderNTP.Stratum), @LHeaderNTP.Stratum, SizeOf(LHeaderNTP.Stratum), LHeaderNTP.Stratum )); 

  // 1-byte field that specifies the maximum interval between successive messages in seconds
  // e.g. a value of 6 means that the maximum interval between messages is 2^6 = 64 seconds
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.PeerPollingInterval',[AcronymName]), 'Peer polling interval',Format('%d (%d seconds)',[LHeaderNTP.Poll,Trunc(Power(2,LHeaderNTP.Poll))]), @LHeaderNTP.Poll, SizeOf(LHeaderNTP.Poll)));     

  // 1-byte field that specifies the precision of the local clock in seconds
  // e.g. a value of -20 means that the clock has a precision of 2^(-20) = 0.954 ns
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.PeerClockPrecision',[AcronymName]), 'Peer clock precision',Format('%.6f seconds',[Power(2,LHeaderNTP.Precision-256)]), @LHeaderNTP.Precision, SizeOf(LHeaderNTP.Precision), LHeaderNTP.Precision ));    

  // 4-byte field that specifies the total round-trip delay to the primary reference source
  // expressed in seconds as a fixed-point number with the integer part in the high-order bits
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.RootDelay',[AcronymName]), 'Root delay',Format('%.6f  seconds',[wpcapntohl(LHeaderNTP.RootDelay)/65536]), @LHeaderNTP.RootDelay, SizeOf(LHeaderNTP.RootDelay)));  

  // 4-byte field that specifies the nominal error relative to the primary reference source
  // expressed in seconds as a fixed-point number with the integer part in the high-order bits
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.RootDispersion',[AcronymName]), 'Root dispersion',Format('%.6f seconds',[(wpcapntohl(LHeaderNTP.RootDispersion))/65536]), @LHeaderNTP.RootDispersion, SizeOf(LHeaderNTP.RootDispersion)));  


  // 8-byte field that specifies the reference clock identifier
  // the first 4 bytes are the reference clock's 32-bit IP address, while the last 4 bytes are a reference ID
  // the format of the reference ID depends on the stratum level of the local clock
  // if Stratum = 0 or Stratum = 1, the reference ID should be a four-character string representing the reference source
  // if Stratum > 1, the reference ID should be the 32-bit IPv4 address of the primary reference source  
  if LHeaderNTP.Stratum > 1 then
    AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.ReferenceID',[AcronymName]), 'Reference ID',Format('%d.%d.%d.%d', [LHeaderNTP.ReferenceID shr 24, (LHeaderNTP.ReferenceID shr 16) and $FF, (LHeaderNTP.ReferenceID shr 8) and $FF, LHeaderNTP.ReferenceID and $FF]), @LHeaderNTP.ReferenceID, SizeOf(LHeaderNTP.ReferenceID)))
  else
    AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.ReferenceID',[AcronymName]), 'Reference ID',Format('%s', [PAnsiChar(@LHeaderNTP.ReferenceID)]), @LHeaderNTP.ReferenceID, SizeOf(LHeaderNTP.ReferenceID)));


  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.ReferenceTimeStamp',[AcronymName]), 'Reference Timestamp', FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', GetDateTimeFromNTPTimeStamp(LHeaderNTP.ReferenceTS)), PByte(@LHeaderNTP.ReferenceTS), SizeOf(LHeaderNTP.ReferenceTS)));
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.OriginateTimeStamp',[AcronymName]), 'Originate Timestamp', FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', GetDateTimeFromNTPTimeStamp(LHeaderNTP.OriginateTS)), PByte(@LHeaderNTP.OriginateTS), SizeOf(LHeaderNTP.OriginateTS)));
  
  // 8-byte field that specifies the time when the response was received by the client
  // expressed as a 64-bit timestamp in seconds since January 1, 1900 (in network byte order)  
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.ReceiveTimeStamp',[AcronymName]), 'Receive Timestamp', FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', GetDateTimeFromNTPTimeStamp(LHeaderNTP.ReceiveTS)), PByte(@LHeaderNTP.ReceiveTS), SizeOf(LHeaderNTP.ReceiveTS)));

  // 8-byte field that specifies the time when the request was sent by the client
  // expressed as a 64-bit timestamp in seconds since January 1, 1900 (in network byte order)
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.TrasmitTimeStamp',[AcronymName]), 'Transmit Timestamp', FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', GetDateTimeFromNTPTimeStamp(LHeaderNTP.TransmitTS)), PByte(@LHeaderNTP.TransmitTS), SizeOf(LHeaderNTP.TransmitTS)));
  aAdditionalInfo.Info := FOrmat('%s %s',[aAdditionalInfo.Info,LMode]).Trim;
  Result := True;
end;

class Function TWPcapProtocolNTP.StratumToString(const aStratum:Uint8):String;
begin
  case aStratum of
   0    : Result:= 'unspecified or unavailable';
   1    : Result:= 'primary reference (e.g. GPS, radio clock)';
   2..15: Result:= 'secondary reference levels, where higher numbers indicate less reliable sources';
  else
    Result := 'Unknown';
  end;
end;

class Function TWPcapProtocolNTP.GetNTPLeapIndicatorString(ALeapIndicator: Uint8): string;
begin
  case ALeapIndicator of
    0: Result := 'No warning';
    1: Result := 'Last minute has 61 seconds';
    2: Result := 'Last minute has 59 seconds';
    3: Result := 'Alarm condition (clock not synchronized)';
  else
    Result := 'Unknown leap indicator';
  end;
end;


class Function TWPcapProtocolNTP.MessageTypeToString(aMsgType:Uint8):String;
begin
  case aMsgType of
   0: Result := 'reserved';
   1: Result := 'symmetric active';
   2: Result := 'symmetric passive';
   3: Result := 'client';
   4: Result := 'server';
   5: Result := 'broadcast';
   6: Result := 'NTP control message';
   7: Result := 'reserved for private use';
  else
    Result := 'Unknown';
  end;
end;

end.
