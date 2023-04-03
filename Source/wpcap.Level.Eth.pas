unit wpcap.Level.Eth;

interface

uses
  System.Generics.Collections, wpcap.Packet, wpcap.BufferUtils, wpcap.StrUtils,Windows,
  wpcap.Conts, System.SysUtils,wpcap.Types,Variants,wpcap.IANA.Dbport,winsock2;

type  

  // This structure contains three fields:
  //
  // DestAddr : 6 byte array containing destination MAC address
  // SrcAddr  : 6 byte array that contains the source MAC address
  // EtherType: 16-bit field indicating the type of higher protocol (for example, IPv4 or ARP).
  PETHHdr = ^TETHHdr;
  TETHHdr =  record
    DestAddr : array [0..5] of Byte;  // The destination MAC address.
    SrcAddr  : array [0..5] of Byte;  // The source MAC address.
    EtherType: Word;                  // The Ethernet type.
  end;  

  /// <summary>
  /// This is a class that provides functions for working with Ethernet headers in a packet. It has several class functions:
  /// </summary>
  TWpcapEthHeader = class
   private

    /// <summary>
    /// This function checks if the size of the packet is valid. 
    //It takes an integer representing the size of the packet as a parameter and returns a Boolean value indicating whether the size is valid.
    /// </summary>
    class function isValidSize(aPacketSize: Integer): Boolean; overload;
  protected
    class var FIsFilterMode : Boolean;  
    class var aTest : Int64;
  public

    /// <summary>
    /// This function returns a pointer to the Ethernet header of the packet. 
    //It takes a pointer to the packet data and an integer representing the size of the packet as parameters, and returns a pointer to the Ethernet header.
    /// </summary>
    class function HeaderEth(const aPacketData: PByte; aPacketSize: Integer): PETHHdr; static;

    /// <summary>
    /// This function returns the size of the Ethernet header.
    /// </summary>
    class function HeaderEthSize: Word;static;

    class function AddHeaderInfo(aLevel:Byte;const aLabel,aDescription:String;aValue:Variant;aPacketInfo:PByte;aPacketInfoSize:Word;aRaWData: Integer=-1 ;aEnrichmentType : TWcapEnrichmentType=WetNone):THeaderString;static;    
    /// <summary>
    /// This function returns a dictionary of strings representing the fields in the Ethernet header. 
    //It takes a pointer to the packet data and an integer representing the size of the packet as parameters, and returns a dictionary of strings.
    /// </summary>
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer;AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;virtual;

    /// <summary>
    /// This function returns a Boolean value indicating whether the packet is a valid Ethernet packet and fills out an internal Ethernet record. 
    //It takes a pointer to the packet data, an integer representing the size of the packet, and a pointer to an internal Ethernet record as parameters, and returns a Boolean value indicating whether the packet is a valid Ethernet packet.
    /// </summary>
    class function InternalPacket(const aPacketData: PByte; aPacketSize: Integer;aIANADictionary:TDictionary<String, TIANARow>;const  aInternalPacket: PTInternalPacket;Out aLikLayersSize:Integer): Boolean; static;

    /// <summary>
    /// This function returns the IP class type for the packet (IPv4 or IPv6). 
    //It takes a pointer to the packet data and an integer representing the size of the packet as parameters, and returns the IP class type.
    /// </summary>
    class function IpClassType(const aPacketData: PByte; aPacketSize: Integer): TIpClaseType; static;

    /// <summary>
    ///  Returns a string representing of acronym of the Ethernet protocol identified by the given protocol value.
    ///  The protocol value is a 16-bit unsigned integer in network byte order.
    ///  Supported protocols are listed in the "Assigned Internet Protocol Numbers" registry maintained by IANA.
    ///  If the protocol is not recognized, the string "<unknown>" is returned.
    /// </summary>
    class function GetEthAcronymName(protocol: Word): string;static; 

    class property IsFilterMode  : Boolean read FIsFilterMode write FIsFilterMode default false;
  end;

implementation

uses wpcap.Level.Ip,wpcap.Protocol.ARP,wpcap.Protocol.UDP,wpcap.Protocol.TCp,wpcap.protocol;

{ TEthHeader }

class function TWpcapEthHeader.GetEthAcronymName(protocol: Word): string;
begin
  case protocol of
    ETH_P_LOOP     : Result := 'LOOP';
    ETH_P_PUP      : Result := 'PUP';
    ETH_P_PUPAT    : Result := 'PUPAT';
    ETH_P_IP       : Result := 'IP';
    ETH_P_X25      : Result := 'X25';
    ETH_P_ARP      : Result := 'ARP';
    ETH_P_BPQ      : Result := 'BPQ';
    ETH_P_IEEEPUP  : Result := 'IEEEPUP';
    ETH_P_IEEEPUPAT: Result := 'IEEEPUPAT';
    ETH_P_DEC      : Result := 'DEC';
    ETH_P_DNA_DL   : Result := 'DNA_DL';
    ETH_P_DNA_RC   : Result := 'DNA_RC';
    ETH_P_DNA_RT   : Result := 'DNA_RT';
    ETH_P_LAT      : Result := 'LAT';
    ETH_P_DIAG     : Result := 'DIAG';
    ETH_P_CUST     : Result := 'CUST';
    ETH_P_SCA      : Result := 'SCA';
    ETH_P_RARP     : Result := 'RARP';
    ETH_P_ATALK    : Result := 'ATALK';
    ETH_P_AARP     : Result := 'AARP';
    ETH_P_8021Q    : Result := '802.1Q';
    ETH_P_IPX      : Result := 'IPX';
    ETH_P_IPV6     : Result := 'IPv6';
    ETH_P_PAUSE    : Result := 'PAUSE';
    ETH_P_SLOW     : Result := 'SLOW';
    ETH_P_WCCP     : Result := 'WCCP';
    ETH_P_PPP_DISC : Result := 'PPP_DISC';
    ETH_P_PPP_SES  : Result := 'PPP_SES';
    ETH_P_MPLS_UC  : Result := 'MPLS_UC';
    ETH_P_ATMMPOA  : Result := 'ATMMPOA';
    ETH_P_LINK_CTL : Result := 'LINK_CTL';
    ETH_P_ATMFATE  : Result := 'ATMFATE';
    ETH_P_PAE      : Result := 'PAE';
    ETH_P_AOE      : Result := 'AOE';
    ETH_P_8021AD   : Result := '802.1AD';
//    ETH_P_802_EX1: Result := '802_EX1';
    ETH_P_TIPC     : Result := 'TIPC';
    //ETH_P_8021AH: Result := '802.1AH';
    ETH_P_IEEE1588 : Result := 'IEEE1588';
    ETH_P_FCOE     : Result := 'FCoE';
    ETH_P_FIP      : Result := 'FIP';
    ETH_P_EDSA     : Result := 'EDSA';
    ETH_P_802_3    : Result := '802.3';
    ETH_P_AX25     : Result := 'AX25';
    ETH_P_ALL      : Result := 'ALL';    
    else Result := 'Unknown protocol (' + IntToStr(protocol) + ')';
  end;
end;

class function TWpcapEthHeader.HeaderEth(const aPacketData: PByte;aPacketSize: Integer): PETHHdr;
begin
  Result := nil;
  if not isValidSize(aPacketSize) then exit;
  Result := PETHHdr(aPacketData)
end;

class function TWpcapEthHeader.HeaderEthSize: Word;
begin
  Result := SizeOf(TETHHdr);
end;

class function TWpcapEthHeader.HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer;AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;
var LInternalPacket   : PTInternalPacket;
    LHeader           : PETHHdr;
    LUDPProtoDetected : TWPcapProtocolBaseUDP;	
    LTCPProtoDetected : TWPcapProtocolBaseTCP;	
    LLikLayersSize    : Integer;  
begin
  Result := False;

  
  new(LInternalPacket);
  Try
    FIsFilterMode := aIsFilterMode;
    if not InternalPacket(aPacketData,aPacketSize,nil,LInternalPacket,LLikLayersSize) then exit;
    Try    
      
      LHeader := HeaderEth(aPacketData,aPacketSize);

      if not Assigned(AListDetail) then
        AListDetail := TListHeaderString.Create;

      AListDetail.Add(AddHeaderInfo(aStartLevel,String.Empty,Format('Frame packet size: %s',[SizeToStr(aPacketSize)]),NUlL,nil,0,aPacketSize));       
      AListDetail.Add(AddHeaderInfo(aStartLevel,'FramePacket.size', 'Size:', SizeToStr(aPacketSize), nil,0, aPacketSize));    
    
      if (LInternalPacket.Eth.SrcAddr = SRC_MAC_RAW_DATA) and ( LInternalPacket.Eth.DestAddr = DST_MAC_RAW_DATA) then    
        AListDetail.Add(AddHeaderInfo(aStartLevel,String.Empty,'Raw data',NUlL,nil,0))                
      else
      begin       
        AListDetail.Add(AddHeaderInfo(aStartLevel,'ETH','Ethernet II',Format('Src: %s, Dst %s',[LInternalPacket.Eth.SrcAddr,LInternalPacket.Eth.DestAddr]),PByte(LHeader),HeaderEthSize));      
        AListDetail.Add(AddHeaderInfo(aStartLevel+1,'ETH.Length','Header length:',HeaderEthSize,nil,0));   
        AListDetail.Add(AddHeaderInfo(aStartLevel+1,'ETH.Destination','Destination:',LInternalPacket.Eth.DestAddr,@LHeader.DestAddr,SizeOf(LHeader.DestAddr)));      
        AListDetail.Add(AddHeaderInfo(aStartLevel+1,'ETH.Source','Source:',LInternalPacket.Eth.SrcAddr,@LHeader.SrcAddr,SizeOf(LHeader.SrcAddr)));      
        AListDetail.Add(AddHeaderInfo(aStartLevel+1,'ETH.Type','Type:',LInternalPacket.Eth.Acronym,@LHeader.EtherType,SizeOf(LHeader.EtherType),LInternalPacket.Eth.EtherType));   
      end;
    
      case LInternalPacket.Eth.EtherType of

        ETH_P_IP,  
        ETH_P_IPV6:
          begin
            if TWpcapIPHeader.HeaderToString(LInternalPacket.PacketData,LInternalPacket.PacketSize,aStartLevel,aListDetail,aIsFilterMode) then
            begin
              LUDPProtoDetected := FListProtolsUDPDetected.GetListByIDProtoDetected(LInternalPacket.IP.DetectedIPProto);
              if Assigned(LUDPProtoDetected) then
                LUDPProtoDetected.HeaderToString(LInternalPacket.PacketData,LInternalPacket.PacketSize,aStartLevel,AListDetail,aIsFilterMode)
              else
              begin
                LTCPProtoDetected := FListProtolsTCPDetected.GetListByIDProtoDetected(LInternalPacket.IP.DetectedIPProto);
                if Assigned(LTCPProtoDetected) then
                  LTCPProtoDetected.HeaderToString(LInternalPacket.PacketData,LInternalPacket.PacketSize,aStartLevel,AListDetail,aIsFilterMode);
              end;
            end

          end;        
 
        ETH_P_LOOP,
        ETH_P_PUP,      
        ETH_P_PUPAT,             
        ETH_P_X25:;      
      
        ETH_P_ARP:  TWPcapProtocolARP.HeaderToString(aPacketData,aPacketSize,aStartLevel,AListDetail,aIsFilterMode);     

        ETH_P_BPQ,
        ETH_P_IEEEPUP,  
        ETH_P_DEC,      
        ETH_P_DNA_DL,   
        ETH_P_DNA_RC,   
        ETH_P_DNA_RT,   
        ETH_P_LAT,      
        ETH_P_DIAG,     
        ETH_P_CUST,     
        ETH_P_SCA,      
        ETH_P_RARP,     
        ETH_P_ATALK,    
        ETH_P_AARP,     
        ETH_P_8021Q,    
        ETH_P_IPX,             
        ETH_P_PAUSE,    
        ETH_P_SLOW,     
        ETH_P_WCCP,     
        ETH_P_PPP_DISC, 
        ETH_P_PPP_SES,  
        ETH_P_MPLS_UC,  
        ETH_P_ATMMPOA,  
        ETH_P_LINK_CTL, 
        ETH_P_ATMFATE,  
        ETH_P_PAE,      
        ETH_P_AOE,      
        ETH_P_8021AD,  
        ETH_P_TIPC,        
        ETH_P_IEEE1588, 
        ETH_P_FCOE,     
        ETH_P_FIP,      
        ETH_P_EDSA,     
        ETH_P_802_3,    
        ETH_P_AX25,     
        ETH_P_ALL:  ;
      end;    
      Result := True;
    Finally
      if LLikLayersSize > 0 then
        FreeMem(LInternalPacket.PacketData,LLikLayersSize);
    End;
  finally               
    Dispose(LInternalPacket)
  end;

end;

class function TWpcapEthHeader.InternalPacket(const aPacketData: PByte; aPacketSize: Integer;aIANADictionary:TDictionary<String, TIANARow>;const aInternalPacket: PTInternalPacket;Out aLikLayersSize:Integer): Boolean;
var LPETHHdr      : PETHHdr;
    I             : Integer;    
    LNewSize      : Integer;
    LNewData      : Pbyte;
    LIpFlagVersion: Byte;
    LEthType      : Word;
    LOffSet       : Integer;
begin
  Result                                      := False;
  aInternalPacket.PacketData                  := aPacketData;
  aInternalPacket.PacketSize                  := aPacketSize;
  aInternalPacket.IP.IpPrototr                := String.Empty;
  aInternalPacket.IP.ProtoAcronym             := String.Empty;
  aInternalPacket.IP.IpProto                  := 0;
  aInternalPacket.IP.Src                      := String.Empty;  
  aInternalPacket.IP.Dst                      := String.Empty;
  aInternalPacket.IP.PortSrc                  := 0;
  aInternalPacket.IP.PortDst                  := 0;
  aInternalPacket.IP.IsIPv6                   := False;
  aInternalPacket.IP.DetectedIPProto          := 0;  
  aInternalPacket.IP.IANAProtoStr             := String.Empty;  
  aInternalPacket.IP.SrcGeoIP.ASNumber        := String.Empty;  
  aInternalPacket.IP.SrcGeoIP.ASOrganization  := String.Empty;  
  aInternalPacket.IP.SrcGeoIP.Location        := String.Empty;  
  aInternalPacket.IP.SrcGeoIP.Latitude        := 0;
  aInternalPacket.IP.SrcGeoIP.Longitude       := 0;
  aInternalPacket.IP.DestGeoIP.ASNumber       := String.Empty;  
  aInternalPacket.IP.DestGeoIP.ASOrganization := String.Empty;  
  aInternalPacket.IP.DestGeoIP.Location       := String.Empty;  
  aInternalPacket.IP.DestGeoIP.Latitude       := 0;
  aInternalPacket.IP.DestGeoIP.Longitude      := 0;
  LPETHHdr                                    := HeaderEth(aPacketData,aPacketSize);
  
  if not Assigned(LPETHHdr) then exit;

  aInternalPacket.Eth.EtherType := wpcapntohs(LPETHHdr.EtherType);
  aInternalPacket.Eth.SrcAddr   := MACAddrToStr(LPETHHdr.SrcAddr);
  aInternalPacket.Eth.DestAddr  := MACAddrToStr(LPETHHdr.DestAddr);  
  aInternalPacket.Eth.Acronym   := GetEthAcronymName(aInternalPacket.Eth.EtherType);

  case aInternalPacket.Eth.EtherType of

    ETH_P_IP,  
    ETH_P_IPV6  : TWpcapIPHeader.InternalIP(aPacketData,aPacketSize,aIANADictionary,@(aInternalPacket.IP));
    
    ETH_P_LOOP,
    ETH_P_PUP,      
    ETH_P_PUPAT,             
    ETH_P_X25,      
    ETH_P_ARP,      
    ETH_P_BPQ,
    ETH_P_IEEEPUP,  
    ETH_P_DEC,      
    ETH_P_DNA_DL,   
    ETH_P_DNA_RC,   
    ETH_P_DNA_RT,   
    ETH_P_LAT,      
    ETH_P_DIAG,     
    ETH_P_CUST,     
    ETH_P_SCA,      
    ETH_P_RARP,     
    ETH_P_ATALK,    
    ETH_P_AARP,     
    ETH_P_8021Q,    
    ETH_P_IPX,             
    ETH_P_PAUSE,    
    ETH_P_SLOW,     
    ETH_P_WCCP,     
    ETH_P_PPP_DISC, 
    ETH_P_PPP_SES,  
    ETH_P_MPLS_UC,  
    ETH_P_ATMMPOA,  
    ETH_P_LINK_CTL, 
    ETH_P_ATMFATE,  
    ETH_P_PAE,      
    ETH_P_AOE,      
    ETH_P_8021AD,  
    ETH_P_TIPC,        
    ETH_P_IEEE1588, 
    ETH_P_FCOE,     
    ETH_P_FIP,      
    ETH_P_EDSA,     
    ETH_P_802_3,    
    ETH_P_AX25,     
    ETH_P_ALL:  ;
  else           
    begin
      {Lik layers type}
      LOffSet   := 0;
      LEthType  := 0;
      if Pbyte(aPacketData)^ = 2 then     
      begin         
        LEthType  := ntohs(ETH_P_IP);  {Loopback}
        LOffSet   := 4;
      end;      
      
      LIpFlagVersion  := Pbyte(aPacketData+LOffSet)^ shr 4;   
      
      case LIpFlagVersion of
        4  : LEthType  := ntohs(ETH_P_IP);
        6  : LEthType  := ntohs(ETH_P_IPV6);
      end;

      if LEthType <> 0 then
      begin
        aLikLayersSize := HeaderEthSize-LOffSet;
        New(LPETHHdr);
        for i := 0 to 5 do
          LPETHHdr.SrcAddr[i] := ord('A');   
        for i := 0 to 5 do
          LPETHHdr.DestAddr[i] := ord('M');

        LNewSize := aPacketSize + aLikLayersSize;
          
        LPETHHdr.EtherType  := LEthType;
        
        GetMem(LNewData,LNewSize); 
        Move( (aPacketData+LOffSet)^, (LNewData + HeaderEthSize)^, aPacketSize-LOffSet);
        Move(LPETHHdr^, LNewData^, HeaderEthSize);
        InternalPacket(LNewData,LNewSize,aIANADictionary,aInternalPacket,aLikLayersSize);
      end;
          
    end;
  end;
  
  Result := True;
end;

class function TWpcapEthHeader.isValidSize(aPacketSize: Integer): Boolean;
begin
  result := aPacketSize > HeaderEthSize;
end;

class function TWpcapEthHeader.IpClassType(const aPacketData: PByte;aPacketSize: Integer): TIpClaseType;
var aPETHHdr : PETHHdr;
begin
  Result           := imtNone;
  aPETHHdr         := HeaderEth(aPacketData,aPacketSize);

  if not Assigned(aPETHHdr) then exit;
    
  case wpcapntohs(aPETHHdr.EtherType)  of
    ETH_P_IP   : Result := imtIpv4;
    ETH_P_IPV6 : Result := imtIpv6;
  end;      
end;

class function TWpcapEthHeader.AddHeaderInfo(aLevel: Byte; const aLabel,aDescription: String; aValue: Variant; aPacketInfo: PByte;aPacketInfoSize: Word;aRaWData: Integer=-1 ;aEnrichmentType : TWcapEnrichmentType=WetNone): THeaderString;
begin
  Result.Description     := aDescription;
  Result.Labelname       := aLabel;
  Result.Value           := aValue;
  Result.Level           := aLevel;
  Result.Size            := aPacketInfoSize;
  if aRaWData <> -1 then  
    Result.RawValue := aRaWData
  else
    Result.RawValue := aValue;
    
  Result.EnrichmentType  := aEnrichmentType;   
  
  if (aPacketInfo = nil) or IsFilterMode then
    Result.Hex := String.Empty
  else
    Result.Hex := String.Join(sLineBreak,DisplayHexData(aPacketInfo,aPacketInfoSize,False));
end;

end.
