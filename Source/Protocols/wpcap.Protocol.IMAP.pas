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

unit wpcap.Protocol.IMAP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,wpcap.packet,
  Wpcap.protocol.TCP, System.Variants;

type

  /// <summary>
  /// The IMAP protocol implementation class.
  /// </summary>
  TWPcapProtocolIMAP = Class(TWPcapProtocolBaseTCP)
  private
  protected
  public
    /// <summary>
    /// Returns the default IMAP port (143).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the IMAP protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the IMAP protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the IMAP protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean; override;                
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolIMAP }
class function TWPcapProtocolIMAP.DefaultPort: Word;
begin
  Result := PROTO_IMAP_PORT;
end;

class function TWPcapProtocolIMAP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_IMAP
end;

class function TWPcapProtocolIMAP.ProtoName: String;
begin
  Result := 'Internet Message Access Protocol';
end;

class function TWPcapProtocolIMAP.AcronymName: String;
begin
  Result := 'IMAP';
end;


class function TWPcapProtocolIMAP.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean;
var LTCPPayLoad    : PByte;
    LTCPPayLoadLen : Integer;
    LDummy         : Integer;
    LOffset        : Integer;
begin
  Result          := False;
  LTCPPayLoad     := inherited GetPayLoad(aPacketData,aPacketSize,LTCPPayLoadLen,LDummy);

  if not Assigned(LTCPPayLoad) then
  begin
    FisMalformed := true;
    Exit;
  end;  
  
  FIsFilterMode   := aIsFilterMode;
  AListDetail.Add(AddHeaderInfo(aStartLevel,AcronymName, Format('%s (%s)', [ProtoName, AcronymName]),null, LTCPPayLoad, LTCPPayLoadLen ));
  LOffSet              := 0;  
  Result               := ParserByEndOfLine(aStartLevel,LTCPPayLoadLen,LTCPPayLoad,AListDetail,LOffSet,aAdditionalParameters);
end;





end.
                                                 
