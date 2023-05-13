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

unit wpcap.Protocol.SSDP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,wpcap.StrUtils,wpcap.packet,
  Wpcap.protocol.UDP, WinApi.Windows,wpcap.BufferUtils,Variants;
type
  
  /// <summary>
  /// The SSDP protocol implementation class.
  /// </summary>
  TWPcapProtocolSSDP = Class(TWPcapProtocolBaseUDP)
  private
  protected
  public
    /// <summary>
    /// Returns the default SSDP port (110).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the SSDP protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the SSDP protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the POP3 protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean; override;
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolSSDP }



class function TWPcapProtocolSSDP.DefaultPort: Word;
begin
  Result := PROTO_SSDP_PORT;
end;

class function TWPcapProtocolSSDP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_SSDP
end;

class function TWPcapProtocolSSDP.ProtoName: String;
begin
  Result := 'Trivial File Transfer Protocol';
end;

class function TWPcapProtocolSSDP.AcronymName: String;
begin
  Result := 'SSDP';
end;

class function TWPcapProtocolSSDP.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean;
var LUDPPayLoad        : PByte;
    LDummy             : Integer;    
    LUdpPayLoadLen     : integer;
    LOffSet            : Integer;
begin
  Result         := False;
  FIsFilterMode  := aIsFilterMode;
  LUDPPayLoad    := inherited GetPayLoad(aPacketData,aPacketSize,LUdpPayLoadLen,LDummy);
  
  if not Assigned(LUDPPayLoad) then
  begin
    FisMalformed := true;
    Exit;
  end;  
  
  AListDetail.Add(AddHeaderInfo(aStartLevel,AcronymName, Format('%s (%s)', [ProtoName, AcronymName]), null, LUDPPayLoad,LUdpPayLoadLen));

  LOffSet              := 0;  
  Result               := ParserByEndOfLine(aStartLevel,LUDPPayLoadLen,LUDPPayLoad,AListDetail,LOffSet,aAdditionalParameters);
end;


end.
                                                 
