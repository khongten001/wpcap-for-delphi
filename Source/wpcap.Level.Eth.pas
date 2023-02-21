unit wpcap.Level.Eth;

interface

uses
  System.Generics.Collections, wpcap.Packet, winSock, wpcap.StrUtils,
  wpcap.Conts, System.SysUtils,wpcap.Types,Variants;

type  

  // This structure contains three fields:
  //
  // DestAddr : 6 byte array containing destination MAC address
  // SrcAddr  : 6 byte array that contains the source MAC address
  // EtherType: 16-bit field indicating the type of higher protocol (for example, IPv4 or ARP).
  PETHHdr = ^TETHHdr;
  TETHHdr = packed record
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

    /// <summary>
    /// This function returns a dictionary of strings representing the fields in the Ethernet header. 
    //It takes a pointer to the packet data and an integer representing the size of the packet as parameters, and returns a dictionary of strings.
    /// </summary>
    class function HeaderToString(const aPacketData: PByte; aPacketSize: Integer;AListDetail: TListHeaderString): Boolean;virtual;

    /// <summary>
    /// This function returns a Boolean value indicating whether the packet is a valid Ethernet packet and fills out an internal Ethernet record. 
    //It takes a pointer to the packet data, an integer representing the size of the packet, and a pointer to an internal Ethernet record as parameters, and returns a Boolean value indicating whether the packet is a valid Ethernet packet.
    /// </summary>
    class function InternalETH(const aPacketData: PByte; aPacketSize: Integer; aInternalEth: PTIntenalETH): Boolean; static;

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
  end;

implementation

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

class function TWpcapEthHeader.HeaderToString(const aPacketData: PByte; aPacketSize: Integer;AListDetail: TListHeaderString): Boolean;
var LHederInfo  : THeaderString;
    LInternalEth: PTIntenalETH;
    LHeader     : PETHHdr;
begin
  Result := False;
  new(LInternalEth);
  Try
    if not InternalETH(aPacketData,aPacketSize,LInternalEth) then exit;
    LHeader                := HeaderEth(aPacketData,aPacketSize);

    if not Assigned(AListDetail) then
      AListDetail := TListHeaderString.Create;


    LHederInfo.Level       := 0;
    LHederInfo.Description := Format('Frame packet size: %s',[SizeToStr(aPacketSize)]);
    LHederInfo.Value       := NUlL;
    LHederInfo.Hex         := String.Empty;
    AListDetail.Add(LHederInfo);
          
    LHederInfo.Level       := 0;
    LHederInfo.Description := Format('Ethernet II, Src: %s, Dst %s ',[LInternalEth.SrcAddr,LInternalEth.DestAddr]);
    LHederInfo.Value       := Null;    
    LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(LHeader),HeaderEthSize,False));
    
    AListDetail.Add(LHederInfo);

    LHederInfo.Level       := 1;
    LHederInfo.Description := 'Destination:';
    LHederInfo.Value       := LInternalEth.DestAddr;    
    LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeader.DestAddr)),5,False));
    AListDetail.Add(LHederInfo);
    
    LHederInfo.Level       := 1;
    LHederInfo.Description := 'Source:';
    LHederInfo.Value       := LInternalEth.SrcAddr;
    LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeader.SrcAddr)),5,False));
    AListDetail.Add(LHederInfo);

    LHederInfo.Level       := 1;
    LHederInfo.Description := 'Type:';
    LHederInfo.Value       := Format('%s [%d]',[LInternalEth.Acronym,LInternalEth.EtherType]);
    LHederInfo.Hex         := String.Join(sLineBreak,DisplayHexData(PByte(@(LHeader.EtherType)),2,False));
    AListDetail.Add(LHederInfo);

    Result := True;
  finally               
    Dispose(LInternalEth)
  end;
end;

class function TWpcapEthHeader.InternalETH(const aPacketData: PByte;aPacketSize: Integer;aInternalEth:PTIntenalETH): Boolean;
var aPETHHdr : PETHHdr;
begin
  Result           := False;
  aPETHHdr         := HeaderEth(aPacketData,aPacketSize);

  if not Assigned(aPETHHdr) then exit;

  aInternalEth^.EtherType := ntohs(aPETHHdr.EtherType);
  aInternalEth^.SrcAddr   := MACAddrToStr(aPETHHdr.SrcAddr);
  aInternalEth^.DestAddr  := MACAddrToStr(aPETHHdr.DestAddr);  
  aInternalEth^.Acronym   := GetEthAcronymName(aInternalEth.EtherType);
  Result                  := True;
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
    
  case ntohs(aPETHHdr.EtherType)  of
    ETH_P_IP   : Result := imtIpv4;
    ETH_P_IPV6 : Result := imtIpv6;
  end;      
end;

end.
