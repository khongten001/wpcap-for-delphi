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

unit wpcap.Protocol.LLMNR;

interface

uses wpcap.Protocol.DNS,wpcap.Conts,wpcap.Types,System.SysUtils;

type
  
  /// <summary>
  /// The LLMNR protocol implementation class.
  /// </summary>
  TWPcapProtocolLLMNR = Class(TWPcapProtocolDNS)
  private
    class function IsLLMNRIPv6Address(const aAddress: TIPv6AddrBytes): Boolean; static;
  protected
    class function GetDNSClass(LDataQuestions: TBytes; aOffset: Integer): byte; override;
  public
    /// <summary>
    /// Returns the default LLMNR port (5355).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the LLMNR protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the LLMNR protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the LLMNR protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; override;    
      
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolMDNS }
class function TWPcapProtocolLLMNR.DefaultPort: Word;
begin
  Result := PROTO_LLMNR_PORT;
end;

class function TWPcapProtocolLLMNR.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_LLMNR
end;

class function TWPcapProtocolLLMNR.GetDNSClass(LDataQuestions: TBytes; aOffset: Integer): byte;
begin
  // Read the QClass field as a big-endian 16-bit integer
  result := inherited GetDNSClass(LDataQuestions,aOffset);
end;

class function TWPcapProtocolLLMNR.ProtoName: String;
begin
  Result := 'Link-Local Multicast Name Resolution';
end;

class function TWPcapProtocolLLMNR.AcronymName: String;
begin
  Result := 'LLMNR';
end;

class function TWPcapProtocolLLMNR.IsValid(const aPacket: PByte;
  aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var LAcronymNameTmp     : String;  
    LIdProtoDetectedTmp : Byte;
    aHederIPv6          : PIpv6Header;
    aIPClass            : TIpClaseType;  
begin
  Result  := inherited IsValid(aPacket,aPacketSize,LAcronymNameTmp,LIdProtoDetectedTmp);  
  aIPClass:= IpClassType(aPacket,aPacketSize); 
  if result then
  begin
    if aIPClass = imtIpv6 then
    begin
      aHederIPv6 := TWpcapIPHeader.HeaderIPv6(aPacket,aPacketSize);
      Result     := IsLLMNRIPv6Address(aHederIPv6.DestinationAddress);
    end;
  end
  else if aIPClass = imtIpv6 then
  begin
    aHederIPv6 := TWpcapIPHeader.HeaderIPv6(aPacket,aPacketSize);
    Result     := IsLLMNRIPv6Address(aHederIPv6.DestinationAddress);  
  end;
        
  if result then
  begin
    aAcronymName     := LAcronymNameTmp;
    aIdProtoDetected := LIdProtoDetectedTmp;
  end;  
  
end;

class function TWPcapProtocolLLMNR.IsLLMNRIPv6Address(const aAddress: TIPv6AddrBytes): Boolean;
{IPv6 Dest =  FF02::1:3}
const 
  MulticastPrefix: TIPv6AddrBytes = (255, 2, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 251);
begin
  Result := CompareMem(@aAddress, @MulticastPrefix, SizeOf(MulticastPrefix));
end;  



end.
                                                 
