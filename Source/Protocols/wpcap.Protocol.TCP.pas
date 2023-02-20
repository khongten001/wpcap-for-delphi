unit wpcap.Protocol.TCP;

interface

uses wpcap.Conts,wpcap.Types,WinSock,System.Types;

type

  TCPHdr = packed record
    SrcPort   : Word;     // TCP source port
    DstPort   : Word;     // TCP destination port
    SeqNum    : DWORD;    // TCP sequence number
    AckNum    : DWORD;    // TCP acknowledgment number
    DataOff   : Byte;     // TCP data offset (number of 32-bit words in header)
    Flags     : Byte;     // TCP flags (SYN, ACK, FIN, etc.)
    WindowSize: Word;     // TCP window size
    Checksum  : Word;     // TCP checksum
    UrgPtr    : Word;     // TCP urgent pointer
  end;
  PTCPHdr = ^TCPHdr;




  /// <summary>
  /// Extracts the TCP header from a packet and returns it through aPHeader.
  /// </summary>
  /// <param name="aData">Pointer to the start of the packet.</param>
  /// <param name="aSize">Size of the packet.</param>
  /// <param name="aPHeader">Pointer to the TCP header.</param>
  /// <param name="aIsIPV6">The the type of header IP</param>  
  /// <returns>True if the TCP header was successfully extracted, False otherwise.</returns>
  function GetHeaderTCP(const aData: PByte; aSize: Integer; var aPTCPHdr: PTCPHdr;var aIsIPV6: boolean): Boolean;

  /// <summary>
  /// Returns a pointer to the payload of the provided TCP data.
  /// </summary>
  /// <param name="AData">The TCP data to extract the payload from.</param>
  /// <param name="aIsIPV6">The the type of header IP</param>
  /// <returns>A pointer to the beginning of the TCP payload.</returns>
  function GetTCPPayLoad(const AData: PByte;aIsIPV6: boolean): PByte;  

implementation

uses wpcap.level.Eth,wpcap.Level.Ip;

function GetTCPPayLoad(const AData: PByte; aIsIPv6: Boolean): PByte;
var TCPHeader : PTCPhdr;
    Offset    : Integer;
begin
  Offset    := TWpcapIPHeader.HeaderSize(aIsIPv6);
  TCPHeader := PTCPhdr(AData + SizeOf(TEthHdr) + Offset);
  Result    := AData + TWpcapEthHeader.HeaderSize  + Offset + ( TCPHeader.DataOff * 4);
end;


function GetHeaderTCP(const aData: PByte; aSize: Integer; var aPTCPHdr: PTCPHdr;var aIsIPV6: boolean): Boolean;
begin
  Result := False;
  aIsIPV6:= False;
  // Check if the data size is sufficient for the Ethernet, IP, and TCP headers
  if (aSize < TWpcapEthHeader.HeaderSize + TWpcapIPHeader.HeaderSize(False) + SizeOf(TCPHdr)) then Exit;
  
    // Parse the Ethernet header
  case TWpcapEthHeader.IpClassType(aData,aSize) of
    imtIpv4 : 
      begin
        // Parse the IPv4 header
        if TWpcapIPHeader.HeaderIPv4(aData,aSize).Protocol <> IPPROTO_TCP then Exit;

        // Parse the UDP header
        aPTCPHdr := PTCPHdr(aData + TWpcapEthHeader.HeaderSize + TWpcapIPHeader.HeaderSize(False));
        Result   := True;     
      end;
   imtIpv6:
      begin
        // Parse the IPv6 header
        if aSize < TWpcapEthHeader.HeaderSize + TWpcapIPHeader.HeaderSize(True) then Exit;

        if TWpcapIPHeader.HeaderIPv6(aData,aSize).NextHeader <> IPPROTO_TCP then Exit;
        aIsIPV6  := True;
        // Parse the TCP header
        aPTCPHdr := PTCPHdr(aData + TWpcapEthHeader.HeaderSize + TWpcapIPHeader.HeaderSize(True));
        Result   := True;
      end;      
  end;
end;


end.
