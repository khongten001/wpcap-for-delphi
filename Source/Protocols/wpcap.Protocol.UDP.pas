unit wpcap.Protocol.UDP;

interface

uses wpcap.Conts,wpcap.Types,WinSock,wpcap.Level.Eth;

type
  //In this structure for UPD packet, the fields are:
  //
  //uh_sport: the source port (2 bytes)
  //uh_dport: the destination port (2 bytes)
  //uh_ulen : the length of the UDP datagram, header included (2 bytes)
  //uh_sum  : the UDP datagram checksum (2 bytes)
  PUDPHdr = ^TUDPHdr;
  TUDPHdr = packed record
    SrcPort   : Word;    // Source port
    DstPort   : Word;    // Destination port
    Length    : Word;    // Length of UDP packet (including header)
    CheckSum  : Word;    // UDP checksum (optional, can be zero)
  end;

  /// <summary>
  /// Attempts to parse a UDP header from the provided data, and sets the pointer to the parsed header.
  /// </summary>
  /// <param name="aData">The data to parse.</param>
  /// <param name="aSize">The size of the data.</param>
  /// <param name="aPUDPHdr">The pointer to the parsed UDP header.</param>
  /// <param name="aIsIPV6">The the type of header IP</param>  
  /// <returns>True if a UDP header was successfully parsed, otherwise False.</returns>
  function GetHeaderUDP(const aData: PByte; aSize: Integer; var aPUDPHdr: PUDPHdr;var aIsIPV6: boolean): Boolean;

  /// <summary>
  /// Returns a pointer to the payload of the provided UDP data.
  /// </summary>
  /// <param name="AData">The UDP data to extract the payload from.</param>
  /// <param name="aIsIPV6">The the type of header IP</param>
  /// <returns>A pointer to the beginning of the UDP payload.</returns>
  function GetUDPPayLoad(const AData: PByte;aIsIPV6: boolean): PByte;


implementation

uses wpcap.Level.Ip;

function GetUDPPayLoad(const AData:Pbyte;aIsIPV6: boolean):PByte;
begin
  if aIsIPV6 then
    Result := AData +TWpcapEthHeader.HeaderSize + TWpcapIPHeader.HeaderSize(True)+ SizeOf(TUDPHdr)
  else
    Result := AData +TWpcapEthHeader.HeaderSize + TWpcapIPHeader.HeaderSize(False)+ SizeOf(TUDPHdr);
end;

function GetHeaderUDP(const aData: PByte; aSize: Integer; var aPUDPHdr: PUDPHdr;var aIsIPV6: boolean): Boolean;
begin
  Result := False;
  aIsIPV6:= False;

  // Check if the data size is sufficient for the Ethernet, IP, and UDP headers
  if (aSize < TWpcapEthHeader.HeaderSize + TWpcapIPHeader.HeaderSize(False) + SizeOf(TUDPHdr)) then Exit;

  // Parse the Ethernet header
  case TWpcapEthHeader.IpClassType(aData,aSize) of
    imtIpv4 : 
      begin
        // Parse the IPv4 header
        if TWpcapIPHeader.HeaderIPv4(aData,aSize).Protocol <> IPPROTO_UDP then Exit;

        // Parse the UDP header
        aPUDPHdr := PUDPHdr(aData + TWpcapEthHeader.HeaderSize + TWpcapIPHeader.HeaderSize(False));
        Result   := True;     
      end;
   imtIpv6:
      begin
        // Parse the IPv6 header
        if aSize < TWpcapEthHeader.HeaderSize + TWpcapIPHeader.HeaderSize(True) then Exit;

        if TWpcapIPHeader.HeaderIPv6(aData,aSize).NextHeader <> IPPROTO_UDP then Exit;
        aIsIPV6  := True;
        // Parse the UDP header
        aPUDPHdr := PUDPHdr(aData + TWpcapEthHeader.HeaderSize + TWpcapIPHeader.HeaderSize(True));
        Result   := True;
      end;      
  end;
end;




end.
