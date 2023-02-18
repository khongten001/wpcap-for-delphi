unit wpcap.Protocol.UDP;

interface

uses wpcap.Conts,wpcap.Types,WinSock;

type
 //In this structure for UPD packet, the fields are:
 //
 //uh_sport: the source port (2 bytes)
 //uh_dport: the destination port (2 bytes)
 //uh_ulen : the length of the UDP datagram, header included (2 bytes)
 //uh_sum  : the UDP datagram checksum (2 bytes)
 PUDPHdr = ^TUDPHdr;
  TUDPHdr = packed record
    SrcPort   : Word;    // UDP source port
    DstPort   : Word;    // UDP destination port
    Lenght    : Word;    // UDP length
    CheckSum  : Word;    // UDP checksum
  end;  

  /// <summary>
  /// Attempts to parse a UDP header from the provided data, and sets the pointer to the parsed header.
  /// </summary>
  /// <param name="aData">The data to parse.</param>
  /// <param name="aSize">The size of the data.</param>
  /// <param name="aPUDPHdr">The pointer to the parsed UDP header.</param>
  /// <returns>True if a UDP header was successfully parsed, otherwise False.</returns>
  function GetHeaderUDP(const aData: PByte; aSize: Integer; var aPUDPHdr: PUDPHdr): Boolean;

  /// <summary>
  /// Returns a pointer to the payload of the provided UDP data.
  /// </summary>
  /// <param name="AData">The UDP data to extract the payload from.</param>
  /// <returns>A pointer to the beginning of the UDP payload.</returns>
  function GetUDPPayLoad(const AData: PByte): PByte;


implementation

function GetUDPPayLoad(const AData:Pbyte):PByte;
begin
  Result := AData +ETH_HEADER_LEN + SizeOf(TIPHeader)+ SizeOf(TUDPHdr);
end;

Function GetHeaderUDP(const aData: PByte; aSize: Integer;var aPUDPHdr:PUDPHdr): Boolean;
var LEthHdr  : PETHHdr;
    LIPHdr   : PIPHeader;
    LIPv6Hdr : PIPv6Header;
begin
  Result := False;
  if (aSize < ETH_HEADER_LEN + SizeOf(TIPHeader) + SizeOf(TUDPHdr)) then  Exit;

  LEthHdr := PETHHdr(aData);
  if ntohs(LEthHdr.EtherType) = ETH_P_IP then
  begin
    LIPHdr := PIPHeader(aData + ETH_HEADER_LEN);
    if LIPHdr.Protocol <> IPPROTO_UDP then Exit;

    aPUDPHdr := PUDPHdr(AData + ETH_HEADER_LEN + SizeOf(TIPHeader));

    Result := True;
  end
  else if ntohs(LEthHdr.EtherType) = ETH_P_IPV6 then
  begin
    {TODO PCAP for test}
    if aSize < ETH_HEADER_LEN + SizeOf(TIPv6Header) then Exit;

    LIPv6Hdr := PIPv6Header(aData + ETH_HEADER_LEN);

  end;
end;



end.
