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

unit wpcap.Protocol.SIP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,wpcap.StrUtils,idGlobal,
  Wpcap.protocol.UDP, WinApi.Windows,wpcap.BufferUtils,Variants;

type
   {https://www.rfc-editor.org/rfc/rfc3261.}

  
  /// <summary>
  /// The SIP protocol implementation class.
  /// </summary>
  TWPcapProtocolSIP = Class(TWPcapProtocolBaseUDP)
  private
    CONST
  protected
  public
    /// <summary>
    /// Returns the default SIP port (110).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the SIP protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the SIP protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the POP3 protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean; override;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; override;        
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolSIP }
class function TWPcapProtocolSIP.DefaultPort: Word;
begin
  Result := PROTO_SIP_PORT;
end;

class function TWPcapProtocolSIP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_SIP
end;

class function TWPcapProtocolSIP.ProtoName: String;
begin
  Result := 'Session Initiation Protocol';
end;

class function TWPcapProtocolSIP.IsValid(const aPacket: PByte;
  aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
begin
  Result  := inherited IsValid(aPacket,aPacketSize,aAcronymName,aIdProtoDetected);  
end;

class function TWPcapProtocolSIP.AcronymName: String;
begin
  Result := 'SIP';
end;

class function TWPcapProtocolSIP.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;
var LUDPPayLoad        : PByte;
    LPUDPHdr           : PUDPHdr;
    LUDPPayLoadLen     : Integer; 
    LOffSet            : Integer;
begin
  Result := False;

  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LUDPPayLoad    := GetUDPPayLoad(aPacketData,aPacketSize);
  LUDPPayLoadLen := UDPPayLoadLength(LPUDPHdr)-8; 
  FIsFilterMode  := aIsFilterMode;
  AListDetail.Add(AddHeaderInfo(aStartLevel, AcronymName , Format('%s (%s)', [ProtoName, AcronymName]), null, LUDPPayLoad,LUDPPayLoadLen));

  LOffSet    := 0;  
  Result     := ParserByEndOfLine(aStartLevel,LUDPPayLoadLen,LUDPPayLoad,AListDetail,LOffSet);
end;


end.
                                                 
