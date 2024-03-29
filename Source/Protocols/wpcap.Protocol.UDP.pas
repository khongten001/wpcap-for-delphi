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

unit wpcap.Protocol.UDP;

interface

uses
  wpcap.Conts, wpcap.Types, WinSock, wpcap.BufferUtils, wpcap.Protocol.Base,wpcap.Packet,
  System.SysUtils, System.Variants, wpcap.StrUtils,System.DateUtils;

type
  //In this structure for UPD packet, the fields are:
  //
  //uh_sport: the source port (2 bytes)
  //uh_dport: the destination port (2 bytes)
  //uh_ulen : the length of the UDP datagram, header included (2 bytes)
  //uh_sum  : the UDP datagram checksum (2 bytes)
  PUDPHdr = ^TUDPHdr;
  TUDPHdr = packed record
    SrcPort   : Uint16;    // Source port
    DstPort   : Uint16;    // Destination port
    Length    : Uint16;    // Length of UDP packet (including header)
    CheckSum  : Uint16;    // UDP checksum (optional, can be zero)
  end;

  /// <summary>
  /// Base class for all protocols that use the User Datagram Protocol (UDP).
  /// This class extends the TWPcapProtocolBase class with UDP-specific functions.
  /// </summary>
  TWPcapProtocolBaseUDP = Class(TWPcapProtocolBase)
  private

  protected
    /// <summary>
    /// Checks whether the length of the payload is valid for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function PayLoadLengthIsValid(const aUDPPtr: PUDPHdr): Boolean; virtual;
    class function GetFlowTimeOut : Byte;override;
  public
    class function AcronymName: String; override;
    class function DefaultPort: word; override;
    class function HeaderLength(aFlag:Uint8): word; override;
    class function IDDetectProto: byte; override;  
    /// <summary>
    /// Returns the length of the UDP payload.
    /// </summary>
    class function UDPPayLoadLength(const aUDPPtr: PUDPHdr): word; static;

    /// <summary>
    /// Checks whether the packet is valid for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function IsValid(const aPacket:PByte;aPacketSize:Integer; var aAcronymName: String;
      var aIdProtoDetected: byte): Boolean; virtual;

    /// <summary>
    /// Returns the source port number for the UDP packet.
    /// </summary>
    class function SrcPort(const aUDPPtr: PUDPHdr): Uint16; static;

    /// <summary>
    /// Returns the destination port number for the UDP packet.
    /// </summary>
    class function DstPort(const aUDPPtr: PUDPHdr): Uint16; static;  

    /// <summary>
    /// Attempts to parse a UDP header from the provided data, and sets the pointer to the parsed header.
    /// </summary>
    /// <param name="aData">The data to parse.</param>
    /// <param name="aSize">The size of the data.</param>
    /// <param name="aPUDPHdr">The pointer to the parsed UDP header.</param>
    /// <param name="aIsIPV6">The the type of header IP</param>  
    /// <returns>True if a UDP header was successfully parsed, otherwise False.</returns>
    class function HeaderUDP(const aData: PByte; aSize: Integer; var aPUDPHdr: PUDPHdr): Boolean;static;

    /// <summary>
    /// Returns a pointer to the payload of the provided UDP data.
    /// </summary>
    /// <param name="AData">The UDP data to extract the payload from.</param>
    /// <param name="aSize">PacketIp</param>
    /// <returns>A pointer to the beginning of the UDP payload.</returns>
    class function GetUDPPayLoad(const AData: PByte;aSize: Uint16): PByte;static;     

    ///  <summary>
    ///    Analyzes a UDP protocol packet to determine its acronym name and protocol identifier.
    ///  </summary>
    ///  <param name="aData">
    ///    A pointer to the packet data to analyze.
    ///  </param>
    ///  <param name="aSize">
    ///    The size of the packet data.
    ///  </param>
    ///  <param name="aArcronymName">
    ///    An output parameter that will receive the acronym name of the detected protocol.
    ///  </param>
    ///  <param name="aIdProtoDetected">
    ///    An output parameter that will receive the protocol identifier of the detected protocol.
    ///  </param>
    ///  <returns>
    ///    True if a supported protocol was detected, False otherwise.
    ///  </returns>
    class function AnalyzeUDPProtocol(const aData: PByte; aSize: Integer; var aArcronymName: string; var aIdProtoDetected: Uint8): Boolean;static;
   
    /// <summary>
    /// This function returns a TListHeaderString of strings representing the fields in the UDP header. 
    //It takes a pointer to the packet data and an integer representing the size of the packet as parameters, and returns a dictionary of strings.
    /// </summary>
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer;AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean;override;            
    class function GetPayLoad(const aPacketData: PByte;aPacketSize: Integer; var aSize,aSizeTotal: Integer): PByte; override;
  end;

implementation

uses wpcap.Level.Ip,wpcap.Protocol;

{TWPcapProtocolBaseUDP}

class function TWPcapProtocolBaseUDP.DefaultPort: word;
begin
  Result := 0; 
end;

class function TWPcapProtocolBaseUDP.IDDetectProto: Uint8;
begin
  Result := DETECT_PROTO_UDP;
end;

class function TWPcapProtocolBaseUDP.HeaderLength(aFlag:byte): word;
begin
  Result := SizeOf(TUDPHdr)
end;

class function TWPcapProtocolBaseUDP.AcronymName: String;
begin
  Result := 'UDP';
end;

class function TWPcapProtocolBaseUDP.PayLoadLengthIsValid(const aUDPPtr: PUDPHdr): Boolean;
begin
  Result := UDPPayLoadLength(aUDPPtr)> HeaderLength(0);
end;

class function TWPcapProtocolBaseUDP.UDPPayLoadLength(const aUDPPtr: PUDPHdr): word;
begin
  Result := wpcapntohs(aUDPPtr.Length);
end;

class function TWPcapProtocolBaseUDP.IsValid(const aPacket:PByte;aPacketSize:Integer;var aAcronymName:String;var aIdProtoDetected:byte): Boolean;
var LPUDPHdr: PUDPHdr;
begin
  Result := False;
  if not HeaderUDP(aPacket,aPacketSize,LPUDPHdr) then Exit;
  
  if not PayLoadLengthIsValid(LPUDPHdr) then  Exit;

  Result := IsValidByDefaultPort(SrcPort(LPUDPHdr),DstPort(LPUDPHdr),aAcronymName,aIdProtoDetected);
end;

class function TWPcapProtocolBaseUDP.SrcPort(const aUDPPtr: PUDPHdr): Uint16;
begin
  Result := wpcapntohs(aUDPPtr.SrcPort);
end;

class function TWPcapProtocolBaseUDP.DstPort(const aUDPPtr: PUDPHdr): Uint16;
begin
  Result := wpcapntohs(aUDPPtr.DstPort);
end;

class function TWPcapProtocolBaseUDP.GetUDPPayLoad(const AData:Pbyte;aSize: Uint16):PByte;
begin
  Result := AData + TWpcapIPHeader.EthAndIPHeaderSize(AData,aSize)+ HeaderLength(0);
end;

class function TWPcapProtocolBaseUDP.HeaderUDP(const aData: PByte; aSize: Integer; var aPUDPHdr: PUDPHdr): Boolean;
var LSizeEthIP    : Uint16;
    LHeaderV4     : PTIPHeader;
    LNewPacketLen : Integer;
    LNewPacketData: PByte;
    LHeaderV6     : PIpv6Header;  
begin
  Result     := False;
  LSizeEthIP := TWpcapIPHeader.EthAndIPHeaderSize(AData,aSize,False);

  // Check if the data size is sufficient for the Ethernet, IP, and UDP headers
  if (aSize < LSizeEthIP + HeaderLength(0)) then Exit;

  // Parse the Ethernet header
  case TWpcapIPHeader.IpClassType(aData,aSize) of
    imtIpv4 : 
      begin
        // Parse the IPv4 header
        LHeaderV4 := TWpcapIPHeader.HeaderIPv4(aData,aSize);
        if not Assigned(LHeaderV4) then Exit;        
        if LHeaderV4.Protocol = IPPROTO_IPV6 then
        begin
	        LNewPacketData := TWpcapIPHeader.GetNextBufferHeader(aData,aSize,0,ETH_P_IP,LNewPacketLen,False);
          Try
            Result := HeaderUDP(LNewPacketData, LNewPacketLen,aPUDPHdr);
            Exit;
          Finally
            FreeMem(LNewPacketData);
          End;
        end;
        
        if LHeaderV4.Protocol <> IPPROTO_UDP then Exit;

        // Parse the UDP header
        aPUDPHdr := PUDPHdr(aData + LSizeEthIP);
        Result   := True;     
      end;
   imtIpv6:
      begin
        LHeaderV6 := TWpcapIPHeader.HeaderIPv6(aData,aSize);

        if LHeaderV6.NextHeader = IPPROTO_IP then
        begin
	        LNewPacketData := TWpcapIPHeader.GetNextBufferHeader(aData,aSize,0,IPPROTO_IPV6,LNewPacketLen,True);
          Try
            Result := HeaderUDP(LNewPacketData, LNewPacketLen,aPUDPHdr);
            Exit;
          Finally
            FreeMem(LNewPacketData);
          End;
        end;        
        if LHeaderV6.NextHeader <> IPPROTO_UDP then Exit;
        // Parse the UDP header
        aPUDPHdr := PUDPHdr(aData + LSizeEthIP);        
        Result   := True;
      end;      
  end;
end;

class function TWPcapProtocolBaseUDP.AnalyzeUDPProtocol(const aData:Pbyte;aSize:Integer;var aArcronymName:String;var aIdProtoDetected:Uint8):boolean;
var LUDPPtr : PUDPHdr;
    I       : Integer;
begin
  Result  := False;
  if not HeaderUDP(aData,aSize,LUDPPtr) then exit;
  
  aIdProtoDetected := IDDetectProto;
  Result           := True;
  for I := 0 to FListProtolsUDPDetected.Count-1 do
  begin
    FListProtolsUDPDetected[I].OnLog := OnLog;
    if FListProtolsUDPDetected[I].IsValid(aData,aSize,aArcronymName,aIdProtoDetected) then Exit;
  end;
end;

class function TWPcapProtocolBaseUDP.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean;
var LPUDPHdr     : PUDPHdr;
    LSrcPort     : Uint16;
    LDstPort     : Uint16;    
    LInternalIP  : TInternalIP;    
    LSizePayload : Integer;
begin
  Result        := False;
  FisFilterMode := aisFilterMode;
  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then exit;

  LSrcPort := SrcPort(LPUDPHdr);
  LDstPort := DstPort(LPUDPHdr);
  
  if IsFilterMode then  
  begin
    TWpcapIPHeader.InternalIP(aPacketData,aPacketSize,nil,@LInternalIP,False,False);
    UpdateFlowInfo(String.Empty,LInternalIP.Src,LInternalIP.Dst,LSrcPort,LDstPort,0,aAdditionalParameters,False);
  end;
  
  LSizePayload := UDPPayLoadLength(LPUDPHdr)-8;  
  AListDetail.Add(AddHeaderInfo(aStartLevel, AcronymName ,'User Datagram Protocol', Format('Src Port: %d, Dst Port: %d',[SrcPort(LPUDPHdr),DstPort(LPUDPHdr)]), Pbyte(LPUDPHdr),HeaderLength(0) ));
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.HaderLen',[AcronymName]), 'Header length:',HeaderLength(0),nil,0));
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SrcPort',[AcronymName]), 'Source port:',LSrcPort, @(LPUDPHdr.SrcPort),SizeOf(LPUDPHdr.SrcPort) ));
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.DstPort',[AcronymName]), 'Destination port:',LDstPort, @(LPUDPHdr.DstPort),SizeOf(LPUDPHdr.DstPort) ));
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Len',[AcronymName]), 'Length:',SizeToStr(UDPPayLoadLength(LPUDPHdr)), @(LPUDPHdr.Length),SizeOf(LPUDPHdr.Length) ));  
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Checksum',[AcronymName]), 'Checksum:',wpcapntohs(LPUDPHdr.CheckSum), @(LPUDPHdr.CheckSum),SizeOf(LPUDPHdr.CheckSum) ));    
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.PayloadLen',[AcronymName]), 'Payload length:',SizeToStr(LSizePayload), nil,0 ));
  aAdditionalParameters.PayLoadSize := LSizePayload;
  Result := True;
end;

class function TWPcapProtocolBaseUDP.GetPayLoad(const aPacketData: PByte;
  aPacketSize: Integer; var aSize, aSizeTotal: Integer): PByte;
var LUDPHdr        : PUDPHdr;
    LLikLayersSize : Integer;
    LCurentPacket  : PByte;
    LcurrentSize   : Integer;    
begin
  Result        := nil;
  aSize         := 0;
  LCurentPacket := nil;
  
  if not CheckLinkLayers(GetEthType(aPacketData,aPacketSize),aPacketData,aPacketSize,LCurentPacket,LcurrentSize,LLikLayersSize) then
  begin
    LCurentPacket := aPacketData;
    LcurrentSize  := aPacketSize;    
  end;
  
  try
    if not HeaderUDP(LCurentPacket,LcurrentSize,LUDPHdr) then exit;

    Result  := GetUDPPayLoad(LCurentPacket,LcurrentSize);
    aSize   := UDPPayLoadLength(LUDPHdr) - 8;
    if aSizeTotal = 0 then
      aSizeTotal := aSize;    
  Finally
    if LLikLayersSize > 0 then
      FreeMem(LCurentPacket,LLikLayersSize);
  End;
end;

class function TWPcapProtocolBaseUDP.GetFlowTimeOut: Byte;
begin
  Result := 15;
end;

end.
