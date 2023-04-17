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

unit wpcap.Protocol.Gnutella;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,
  Wpcap.protocol.TCP, System.Variants;

type

  /// <summary>
  /// The Gnutella protocol implementation class.
  /// </summary>
  TWPcapProtocolGnutella = Class(TWPcapProtocolBaseTCP)
  private
  protected
  public
    /// <summary>
    /// Returns the default Gnutella port (143).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the Gnutella protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the Gnutella protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the Gnutella protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; override;    
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean; override;                
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolGnutella }
class function TWPcapProtocolGnutella.DefaultPort: Word;
begin
  Result := PROTO_Gnutella_PORT;
end;

class function TWPcapProtocolGnutella.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_Gnutella
end;

class function TWPcapProtocolGnutella.ProtoName: String;
begin
  Result := 'Gnutella Protocol';
end;

class function TWPcapProtocolGnutella.AcronymName: String;
begin
  Result := 'Gnutella';
end;

class function TWPcapProtocolGnutella.IsValid(const aPacket: PByte;
  aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var LTCPPHdr : PTCPHdr;
begin
  Result := False;
  if not HeaderTCP(aPacket,aPacketSize,LTCPPHdr) then exit;   
  if not PayLoadLengthIsValid(LTCPPHdr,aPacket,aPacketSize) then  Exit;
  Result := IsValidByPort(DefaultPort,DstPort(LTCPPHdr),SrcPort(LTCPPHdr),aAcronymName,aIdProtoDetected);
end;

class function TWPcapProtocolGnutella.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;
var LTCPPayLoad    : PByte;
    LTCPPayLoadLen : Integer;
    LTCPPHdr       : PTCPHdr;
begin
  Result := False;

  if not HeaderTCP(aPacketData,aPacketSize,LTCPPHdr) then Exit;

  LTCPPayLoad     := GetTCPPayLoad(aPacketData,aPacketSize);
  LTCPPayLoadLen  := TCPPayLoadLength(LTCPPHdr,aPacketData,aPacketSize);
  FIsFilterMode   := aIsFilterMode;
  AListDetail.Add(AddHeaderInfo(aStartLevel,AcronymName, Format('%s (%s)', [ProtoName, AcronymName]),null, LTCPPayLoad, LTCPPayLoadLen ));
  AListDetail.Add(AddHeaderInfo(aStartLevel+1,AcronymName,'Gnutella Upload / Download Stream',null, LTCPPayLoad, LTCPPayLoadLen ));  
end;





end.
                                                 
