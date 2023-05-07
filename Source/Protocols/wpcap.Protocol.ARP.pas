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

unit wpcap.Protocol.ARP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils, wpcap.StrUtils,
  wpcap.packet, System.StrUtils, System.Variants, wpcap.BufferUtils, WinSock,
  WinSock2, Wpcap.IpUtils, idGlobal;

type

{   https://datatracker.ietf.org/doc/html/rfc826


     0               1               2               3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Hardware Type        |          Protocol Type        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |HwAddr Len |Prot Addr Len|      Operation Code (Opcode)        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Sender Hardware Address                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Sender Protocol Address                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Target Hardware Address                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Target Protocol Address                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Hardware Type (2 byte): identifica il tipo di hardware utilizzato nella rete (ad es. Ethernet, Token Ring, FDDI, ecc.)
    Protocol Type (2 byte): identifica il protocollo di rete utilizzato (ad es. IP)
    HwAddr Len (1 byte): indica la lunghezza dell'indirizzo fisico del destinatario (ad es. 6 byte per gli indirizzi MAC)
    Prot Addr Len (1 byte): indica la lunghezza dell'indirizzo di protocollo del destinatario (ad es. 4 byte per gli indirizzi IP)
    Operation Code (2 byte): specifica il tipo di operazione che viene eseguita (ad es. richiesta di risoluzione dell'indirizzo o risposta alla richiesta)
    Sender Hardware Address (lunghezza variabile): l'indirizzo fisico del mittente
    Sender Protocol Address (lunghezza variabile): l'indirizzo di protocollo del mittente
    Target Hardware Address (lunghezza variabile): l'indirizzo fisico del destinatario
    Target Protocol Address (lunghezza variabile): l'indirizzo di protocollo del destinatario.
}
  TARPHeader = packed record
    HardwareType: Uint16;
    ProtocolType: Uint16;
    HardwareSize: Uint8;
    ProtocolSize: Uint8;
    OpCode      : Uint16;
  end;
  PTARPHeader = ^TARPHeader;
    
  /// <summary>
  /// The ICMP protocol implementation class.
  /// </summary>
  TWPcapProtocolARP = Class(TWPcapProtocolBase)
  private
     CONST
      ARP_REQUEST = 1;
      ARP_REPLAY  = 2;
  public
    /// <summary>
    /// Returns the default ICMP 0 - No port.
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the ICMP protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the ICMP protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    ///  Returns the length of the ICMP header.
    /// </summary>
    class function HeaderLength(aFlag:Byte): word; override;

    /// <summary>
    ///  Returns a pointer to the ICMP header.
    /// </summary>
    class function Header(const aData: PByte; aSize: Integer;var aARPHeader: PTARPHeader): Boolean; static;    
    /// <summary>
    /// Returns the acronym name of the ICMP protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; static;
    class function HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalInfo: PTAdditionalInfo): Boolean; override;      
  end;


implementation

uses wpcap.Level.Eth;


{ TWPcapProtocolMDNS }
class function TWPcapProtocolARP.DefaultPort: Word;
begin
  Result := 0;
end;

class function TWPcapProtocolARP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_ARP
end;

class function TWPcapProtocolARP.ProtoName: String;
begin
  Result := 'Address Resolution Protocol';
end;

class function TWPcapProtocolARP.AcronymName: String;
begin
  Result := 'ARP';
end;

class function TWPcapProtocolARP.IsValid(const aPacket: PByte;aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean; 
begin
  result := True;
end;
  
class function TWPcapProtocolARP.HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer;AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalInfo: PTAdditionalInfo): Boolean;
var LHeaderARP     : PTARPHeader;
    LSenderIP      : string;
    LTargetIP      : string;
    LMacSrc        : String;
    LMacDst        : String;    
    LTmpBytesSender: TIdBytes;
    LTmpBytesTarget: TIdBytes;    
    LCurrentPos    : Integer;
    LPtType        : Uint16;
    LArpType       : Uint16;
    LEnrichment    : TWpcapEnrichmentType;
begin
  Result        := False;
  FIsFilterMode := aIsFilterMode;

  if not Header(aPacketData,aPacketSize,LHeaderARP) then exit;

  LArpType := wpcapntohs(LHeaderARP.OpCode);
  
  AListDetail.Add(AddHeaderInfo(aStartLevel, AcronymName, Format('%s (%s)',[ProtoName,AcronymName]),NULL,PByte(LHeaderARP),HeaderLength(0) ));    
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.HWType',[AcronymName]), 'Hardware type:', wpcapntohs(LHeaderARP.HardwareType), @LHeaderARP.HardwareType, SizeOf(LHeaderARP.HardwareType) ));
  LPtType  := wpcapntohs(LHeaderARP.ProtocolType);
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.ProtocolType',[AcronymName]), 'Protocol type:',TWpcapEthHeader.GetEthAcronymName(LPtType), @LHeaderARP.ProtocolType, SizeOf(LHeaderARP.ProtocolType), LPtType ));
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.HWLen',[AcronymName]), 'Hardware len:', LHeaderARP.HardwareSize, @LHeaderARP.HardwareSize, SizeOf(LHeaderARP.HardwareSize) ));
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.ProtocolLen',[AcronymName]), 'Protocol len:', LHeaderARP.ProtocolSize, @LHeaderARP.ProtocolSize, SizeOf(LHeaderARP.ProtocolSize) ));
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Operation',[AcronymName]), 'Operation:',  ifthen(LArpType=ARP_REQUEST,'request','replay'), @LHeaderARP.OpCode, SizeOf(LHeaderARP.OpCode), LArpType ));
  
  LCurrentPos := HeaderEthSize(aPacketData,aPacketSize) + HeaderLength(0);
  SetLength(LTmpBytesSender,LHeaderARP.HardwareSize);
  SetLength(LTmpBytesTarget,LHeaderARP.HardwareSize);

  {Sender}
  Move((aPacketData + LCurrentPos)^,LTmpBytesSender[0],LHeaderARP.HardwareSize);
  Inc(LCurrentPos,Length(LTmpBytesSender));
  
  {Target}
  Move((aPacketData+LCurrentPos+LHeaderARP.ProtocolSize)^,LTmpBytesTarget[0],LHeaderARP.HardwareSize);
  LMacSrc := MACAddressToString(LTmpBytesSender);                               
  LMacDst := MACAddressToString(LTmpBytesTarget);
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SenderMAC',[AcronymName]), 'Sender MAC:',LMacSrc , PByte(LTmpBytesSender), LHeaderARP.HardwareSize ));
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.TargetMAC',[AcronymName]), 'Target MAC:',LMacDst , PByte(LTmpBytesTarget), LHeaderARP.HardwareSize ));

  if IsFilterMode then  
    UpdateFlowInfo(LMacSrc,LMacDst,0,0,0,0,0,aAdditionalInfo);
  
  SetLength(LTmpBytesSender,LHeaderARP.ProtocolSize);
  SetLength(LTmpBytesTarget,LHeaderARP.ProtocolSize);  

  {Sender}
  Move((aPacketData + LCurrentPos)^,LTmpBytesSender[0],LHeaderARP.ProtocolSize);
  Inc(LCurrentPos,LHeaderARP.ProtocolSize);

  {Target}
  Move((aPacketData+ LCurrentPos+LHeaderARP.HardwareSize)^,LTmpBytesTarget[0],LHeaderARP.ProtocolSize);

  LSenderIP   := String.Empty;
  LTargetIP   := String.Empty;  
  LEnrichment := WetNone;
  case wpcapntohs(LHeaderARP.ProtocolType) of
    ETH_P_IP,
    ETH_P_ARP   :
      begin
        LSenderIP := BytesToIPv4Str(LTmpBytesSender);      
        if IsValidPublicIP(LSenderIP) then
        begin
          LEnrichment                       := WetIP;
          aAdditionalInfo.EnrichmentPresent := true;
        end;
      
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SenderIP',[AcronymName]), 'Sender IP:', LSenderIP, PByte(LTmpBytesSender), SizeOf(LTmpBytesSender), -1,LEnrichment ));

        LEnrichment := WetNone;          
        LTargetIP   := BytesToIPv4Str(LTmpBytesTarget);

        if IsValidPublicIP(LTargetIP) then
        begin
          LEnrichment                       := WetIP;
          aAdditionalInfo.EnrichmentPresent := true;
        end;
        
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.TargetIP',[AcronymName]), 'Target IP:', LTargetIP, PByte(LTmpBytesTarget), SizeOf(LTmpBytesTarget), -1,LEnrichment  ));           
      end;
    ETH_P_IPV6  : 
      begin       
        // convert sender IP address to string
        LSenderIP := IPv6AddressToString(LTmpBytesSender);
        if IsValidPublicIP(LSenderIP) then
        begin
          LEnrichment                       := WetIP;
          aAdditionalInfo.EnrichmentPresent := true;
        end;

        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SenderIPv6',[AcronymName]), 'Sender IP:', LSenderIP, PByte(LTmpBytesSender), SizeOf(LTmpBytesSender), -1,LEnrichment ));

        // convert target IP address to string
        LEnrichment := WetNone;              
        LTargetIP   := IPv6AddressToString(LTmpBytesTarget);

        if IsValidPublicIP(LTargetIP) then
        begin
          LEnrichment                       := WetIP;
          aAdditionalInfo.EnrichmentPresent := true;
        end;
                
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.TargetIPv6',[AcronymName]), 'Target IP:', LTargetIP, PByte(LTmpBytesTarget), SizeOf(LTmpBytesTarget), -1,LEnrichment ));      
      end;
  end;

  if not LSenderIP.IsEmpty then
  begin
    case LArpType of
      ARP_REQUEST : aAdditionalInfo.Info := Format('Who has %s ? tell %s',[LTargetIP,LSenderIP]);
      ARP_REPLAY  : aAdditionalInfo.Info := Format('%s is at %s',[LSenderIP,LMacSrc]);          
    end;
  end;
  
  Result := True;          
end;

class function TWPcapProtocolARP.HeaderLength(aFlag: Byte): word;
begin
  Result := SizeOf(TARPHeader)
end;

class function TWPcapProtocolARP.Header(const aData: PByte; aSize: Integer; var aARPHeader: PTARPHeader): Boolean;
var aSizeEthEth : Word;
begin
  Result     := False;
  aSizeEthEth := HeaderEthSize(aData,aSize);

  // Check if the data size is sufficient for the Ethernet, IP, and UDP headers
  if (aSize < aSizeEthEth + HeaderLength(0)) then Exit;  

  aARPHeader := PTARPHeader(aData + aSizeEthEth);

  Result := True;
end;

end.
                                                 
