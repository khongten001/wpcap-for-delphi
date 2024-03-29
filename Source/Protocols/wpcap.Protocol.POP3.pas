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

unit wpcap.Protocol.POP3;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,idGlobal,wpcap.packet,
  Wpcap.protocol.TCP,System.Variants,Wpcap.BufferUtils,wpcap.StrUtils;

type

  /// <summary>
  /// The POP3 protocol implementation class.
  /// </summary>
  TWPcapProtocolPOP3 = Class(TWPcapProtocolBaseTCP)
  private
  protected
  public
    /// <summary>
    /// Returns the default POP3 port (110).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the POP3 protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the POP3 protocol.
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

{ TWPcapProtocolPOP3 }
class function TWPcapProtocolPOP3.DefaultPort: Word;
begin
  Result := PROTO_POP3_PORT;
end;

class function TWPcapProtocolPOP3.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_POP3
end;

class function TWPcapProtocolPOP3.ProtoName: String;
begin
  Result := 'Post Office Protocol';
end;

class function TWPcapProtocolPOP3.AcronymName: String;
begin
  Result := 'POP3';
end;

class function TWPcapProtocolPOP3.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean;
var LTCPPayLoad        : PByte;
    LDummy             : Integer;
    LTCPPayLoadLen     : Integer;
    LOffset            : Integer;    
begin
  Result           := False;
  FIsFilterMode    := aIsFilterMode;
  LTCPPayLoad      := inherited GetPayLoad(aPacketData,aPacketSize,LTCPPayLoadLen,LDummy);

  if not Assigned(LTCPPayLoad) then
  begin
    FisMalformed := true;
    Exit;
  end;  
      
  AListDetail.Add(AddHeaderInfo(aStartLevel,AcronymName, Format('%s (%s)', [ProtoName, AcronymName]), null, LTCPPayLoad,LTCPPayLoadLen ));

  LOffSet  := 0;  
  Result   := ParserByEndOfLine(aStartLevel,LTCPPayLoadLen,LTCPPayLoad,AListDetail,LOffSet,aAdditionalParameters);
end;


end.
                                                 
