﻿unit wpcap.protocol;

interface              

uses
  wpcap.Conts, WinSock, System.SysUtils, wpcap.Types, Winapi.Winsock2,wpcap.Protocol.Telnet,
  wpcap.Protocol.Base, wpcap.Protocol.TCP, wpcap.Protocol.POP3, vcl.Graphics,
  wpcap.Graphics, wpcap.Protocol.DNS, wpcap.Protocol.UDP,wpcap.Protocol.FTP,
  System.Generics.Collections, wpcap.Protocol.HTTP, wpcap.Protocol.L2TP, wpcap.Protocol.SIP,
  wpcap.Protocol.NTP, wpcap.Protocol.MDNS, wpcap.Protocol.LLMNR,wpcap.Protocol.TFTP,
  wpcap.Protocol.TLS, wpcap.Protocol.NBNS,wpcap.Protocol.RTP;




/// <summary>
/// Returns the color associated with a given IP protocol value, limited to a specific set of protocols.
/// </summary>
/// <param name="aEthType">The ETH type value to get the color for.</param>
/// <param name="aprotocol">The IP protocol value to get the color for.</param>
/// <param name="aBackGroundColor">Return TColor</param>
/// <param name="aFontColor">Return TColor for font</param>///
/// <returns>True if found a color for Protocol</returns>
function GetProtocolColor(aEthType,aProtocol: Word;aDetectProto:Byte;var aBackGroundColor:TColor;var aFontColor:TColor): boolean;

function IsDropboxPacket(const aUDPPtr: PUDPHdr): Boolean;


type

  TListProtolsUDPDetected = Class(TList<TWPcapProtocolBaseUDP>)
  public 
    function GetListByIDProtoDetected(const aIpProtoDetected: byte):TWPcapProtocolBaseUDP;
  end;
  
  TListProtolsTCPDetected = Class(TList<TWPcapProtocolBaseTCP>)
  public 
    function GetListByIDProtoDetected(const aIpProtoDetected: byte):TWPcapProtocolBaseTCP;
  end;

  /// <summary>
  /// Factory class for creating instances of objects that inherit from TWPcapProtocolBaseTCP.
  /// </summary>
  TProtocolFactoryUPD = class
    public
    /// <summary>
    /// Creates a new instance of a class that inherits from TWPcapProtocolBaseTCP.
    /// </summary>
    /// <typeparam name="T">The class type to create an instance of.</typeparam>
    /// <returns>An instance of the specified class type.</returns>
    class function CreateInstance<T: TWPcapProtocolBaseUDP, constructor>: T;
  end;

  /// <summary>
  /// Factory class for creating instances of objects that inherit from TWPcapProtocolBaseUDP.
  /// </summary>
  TProtocolFactoryTCP = class
  public
    /// <summary>
    /// Creates a new instance of a class that inherits from TWPcapProtocolBaseUDP.
    /// </summary>
    /// <typeparam name="T">The class type to create an instance of.</typeparam>
    /// <returns>An instance of the specified class type.</returns>
    class function CreateInstance<T: TWPcapProtocolBaseTCP, constructor>: T;
  end;

var FListProtolsUDPDetected : TListProtolsUDPDetected;
    FListProtolsTCPDetected : TListProtolsTCPDetected;

implementation


function GetProtocolColor(aEthType,aProtocol: Word;aDetectProto:Byte;var aBackGroundColor:TColor;var aFontColor:TColor): boolean;
CONST TCP_COLOR     = 16704998;
      UDP_COLOR     = 16772826;
      ICMP_COLOR    = 16769276;
      ROUTING_COLOR = $FFFACD;
      AH_COLOR      = $FFB6C1; // LightPink
      ESP_COLOR     = $D8BFD8; // Thistle;
      ARP_COLOR     = 14151930;
var LDetectProtoFound : Boolean;      
begin
  Result            := True;
  LDetectProtoFound := False;
  if aDetectProto > 0 then
  begin
    LDetectProtoFound := True;
    case aDetectProto of
       DETECT_PROTO_DNS,
       DETECT_PROTO_LLMNR,
       DETECT_PROTO_NTP,
       DETECT_PROTO_MDNS,
       DETECT_PROTO_UDP      : aBackGroundColor := UDP_COLOR;
       DETECT_PROTO_TLS,
       DETECT_PROTO_TCP      : aBackGroundColor := TCP_COLOR;
       DETECT_PROTO_ICMP     : aBackGroundColor := ICMP_COLOR;
       DETECT_PROTO_ARP      : aBackGroundColor := ARP_COLOR;
       DETECT_PROTO_HTTP     : aBackGroundColor := $008FBC8F;
       DETECT_PROTO_NBNS     : aBackGroundColor := $00D0FFFE;//Giallo
    else
      LDetectProtoFound := False;
    end;
  end;
  
  if LDetectProtoFound then Exit;
  
  case aEthType of
     ETH_P_IP : 
      begin
        case aProtocol of
          IPPROTO_HOPOPTS,        
          IPPROTO_ICMP   : aBackGroundColor := ICMP_COLOR;
          IPPROTO_IGMP   : aBackGroundColor := $00FFFF; // Cyan
          IPPROTO_GGP    : aBackGroundColor := $FFD700; // Gold
          IPPROTO_TCP    : aBackGroundColor := TCP_COLOR; 
          IPPROTO_UDP    : aBackGroundColor := UDP_COLOR; 
          IPPROTO_IPV6   : aBackGroundColor := $B0C4DE; // LightSteelBlue
          IPPROTO_PUP    : aBackGroundColor := $FFE4E1; // MistyRose
          IPPROTO_IDP    : aBackGroundColor := $9370DB; // MediumPurple
          IPPROTO_GRE    : aBackGroundColor := $FFC0CB; // Pink
          IPPROTO_ESP    : aBackGroundColor := ESP_COLOR;
          IPPROTO_AH     : aBackGroundColor := AH_COLOR;
          IPPROTO_PGM    : aBackGroundColor := $D2B48C; // Tan
          IPPROTO_SCTP   : aBackGroundColor := $87CEEB; // SkyBlue
          IPPROTO_RAW    : aBackGroundColor := $F5DEB3; // Wheat
        else
          Result := False;
        end;      
      end;
     ETH_P_IPV6 :
      case aProtocol of
          IPPROTO_HOPOPTS,
       //   IPPROTO_ICMPV62,
          IPPROTO_ICMPV6     : aBackGroundColor := ICMP_COLOR; //ICMP
          IPPROTO_TCP        : aBackGroundColor := TCP_COLOR;  //TCP
          IPPROTO_UDP        : aBackGroundColor := UDP_COLOR;  //TCP
          IPPROTO_ROUTINGV6  : aBackGroundColor := ROUTING_COLOR; 
          IPPROTO_AH         : aBackGroundColor := AH_COLOR;
          IPPROTO_ESP        : aBackGroundColor := ESP_COLOR;   
      else
        Result := False;              
      end;
      ETH_P_PAE : aBackGroundColor := clWhite;          
      ETH_P_ARP : aBackGroundColor := ARP_COLOR; //ARP

  else
    Result := False;
  end;

  if Result then
    aFontColor := GetFontColor(aBackGroundColor);
end;

function IsDropboxPacket(const aUDPPtr: PUDPHdr): Boolean;
begin
  {  by NDPI reader
   if(protocol == IPPROTO_UDP) {
    if((sport == dport) && (sport == 17500)) {
      return(NDPI_PROTOCOL_DROPBOX);
  }
  Result := (aUDPPtr.SrcPort = aUDPPtr.DstPort) and (aUDPPtr.SrcPort = 17500);
end;

{ TProtocolFactoryUPD }
class function TProtocolFactoryUPD.CreateInstance<T>: T;
begin
  Result := T.Create;
end;

{ TProtocolFactoryTCP }
class function TProtocolFactoryTCP.CreateInstance<T>: T;
begin
  Result := T.Create;
end;

procedure DoRegisterListProtocolsDetected;
begin
  {UDP}
  FListProtolsUDPDetected := TListProtolsUDPDetected.Create;

  FListProtolsUDPDetected.Add(TProtocolFactoryUPD.CreateInstance<TWPcapProtocolL2TP>);
  FListProtolsUDPDetected.Add(TProtocolFactoryUPD.CreateInstance<TWPcapProtocolDNS>);
  FListProtolsUDPDetected.Add(TProtocolFactoryUPD.CreateInstance<TWPcapProtocolNTP>);
  FListProtolsUDPDetected.Add(TProtocolFactoryUPD.CreateInstance<TWPcapProtocolMDNS>);
  FListProtolsUDPDetected.Add(TProtocolFactoryUPD.CreateInstance<TWPcapProtocolLLMNR>);
  FListProtolsUDPDetected.Add(TProtocolFactoryUPD.CreateInstance<TWPcapProtocolNBNS>);  
  FListProtolsUDPDetected.Add(TProtocolFactoryUPD.CreateInstance<TWPcapProtocolRTP>);   
  FListProtolsUDPDetected.Add(TProtocolFactoryUPD.CreateInstance<TWPcapProtocolTFTP>); 
  FListProtolsUDPDetected.Add(TProtocolFactoryUPD.CreateInstance<TWPcapProtocolSIP>);      
  {TCP}  
  FListProtolsTCPDetected := TListProtolsTCPDetected.Create;  
  FListProtolsTCPDetected.Add(TProtocolFactoryTCP.CreateInstance<TWPcapProtocolTLS>);
  FListProtolsTCPDetected.Add(TProtocolFactoryTCP.CreateInstance<TWPcapProtocolHTTP>);  
  FListProtolsTCPDetected.Add(TProtocolFactoryTCP.CreateInstance<TWPcapProtocolPOP3>);    
  FListProtolsTCPDetected.Add(TProtocolFactoryTCP.CreateInstance<TWPcapProtocolFTP>);    
  FListProtolsTCPDetected.Add(TProtocolFactoryTCP.CreateInstance<TWPcapProtocolTELNET>);      
end;

{ TListProtolsTCPDetected }

function TListProtolsTCPDetected.GetListByIDProtoDetected(const aIpProtoDetected: byte): TWPcapProtocolBaseTCP;
var I: Integer;
begin
  Result := nil;
  for I := 0 to Count -1 do
  begin
    if self[I].IDDetectProto = aIpProtoDetected then
    begin
      Result := Self[I];
      Break;
    end;
  end;
end;

{ TListProtolsUDPDetected }
function TListProtolsUDPDetected.GetListByIDProtoDetected(const aIpProtoDetected: byte): TWPcapProtocolBaseUDP;
var I: Integer;
begin
  Result := nil;
  for I := 0 to Count -1 do
  begin
    if self[I].IDDetectProto = aIpProtoDetected then
    begin
      Result := Self[I];
      Break;
    end;
  end;
end;

initialization
    DoRegisterListProtocolsDetected;

finalization
  if Assigned(FListProtolsUDPDetected) then  
    FreeAndNil(FListProtolsUDPDetected);
  if Assigned(FListProtolsTCPDetected) then  
    FreeAndNil(FListProtolsTCPDetected);

end.
