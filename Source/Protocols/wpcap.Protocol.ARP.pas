unit wpcap.Protocol.ARP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,wpcap.StrUtils,
  System.Variants, wpcap.BufferUtils,WinSock,WinSock2,Wpcap.IpUtils,idGlobal;

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
    HardwareType: Word;
    ProtocolType: Word;
    HardwareSize: Byte;
    ProtocolSize: Byte;
    OpCode      : Word;
  end;
  PTARPHeader = ^TARPHeader;
  

  
  /// <summary>
  /// The ICMP protocol implementation class.
  /// </summary>
  TWPcapProtocolARP = Class(TWPcapProtocolBase)
  private

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
    class function HeaderToString(const aPacketData: PByte;aPacketSize: Integer; AListDetail: TListHeaderString): Boolean; override;      
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
  
class function TWPcapProtocolARP.HeaderToString(const aPacketData: PByte; aPacketSize: Integer;AListDetail: TListHeaderString): Boolean;
var LHeaderARP     : PTARPHeader;
    LSenderIP      : string;
    LTargetIP      : string;
    LTmpBytesSender: TIdBytes;
    LTmpBytesTarget: TIdBytes;    
    LCurrentPos    : Integer;
begin
  Result := False;

  if not Header(aPacketData,aPacketSize,LHeaderARP) then exit;

  AListDetail.Add(AddHeaderInfo(0,Format('%s (%s)',[ProtoName,AcronymName]),NULL,PByte(LHeaderARP),HeaderLength(0)));    
  AListDetail.Add(AddHeaderInfo(1, 'Hardware type:', wpcapntohs(LHeaderARP.HardwareType), @LHeaderARP.HardwareType, SizeOf(LHeaderARP.HardwareType) ));
  AListDetail.Add(AddHeaderInfo(1, 'Protocol type:',Format('%s [%d]',[TWpcapEthHeader.GetEthAcronymName(wpcapntohs(LHeaderARP.ProtocolType)),wpcapntohs(LHeaderARP.ProtocolType)]), @LHeaderARP.ProtocolType, SizeOf(LHeaderARP.ProtocolType) ));
  AListDetail.Add(AddHeaderInfo(1, 'Hardware len:',  (LHeaderARP.HardwareSize), @LHeaderARP.HardwareSize, SizeOf(LHeaderARP.HardwareSize) ));
  AListDetail.Add(AddHeaderInfo(1, 'Protocol len:',  (LHeaderARP.ProtocolSize), @LHeaderARP.ProtocolSize, SizeOf(LHeaderARP.ProtocolSize) ));
  AListDetail.Add(AddHeaderInfo(1, 'Operation:',  wpcapntohs(LHeaderARP.OpCode), @LHeaderARP.OpCode, SizeOf(LHeaderARP.OpCode) ));

  
  LCurrentPos := HeaderEthSize + HeaderLength(0);

  SetLength(LTmpBytesSender,LHeaderARP.HardwareSize);
  SetLength(LTmpBytesTarget,LHeaderARP.HardwareSize);

  {Sender}
  Move((aPacketData + LCurrentPos)^,LTmpBytesSender[0],LHeaderARP.HardwareSize);
  Inc(LCurrentPos,Length(LTmpBytesSender));
  
  {Target}
  Move((aPacketData+LCurrentPos+LHeaderARP.ProtocolSize)^,LTmpBytesTarget[0],LHeaderARP.HardwareSize);
                                 
  AListDetail.Add(AddHeaderInfo(1, 'Sender MAC:', MACAddressToString(LTmpBytesSender), PByte(LTmpBytesSender), LHeaderARP.HardwareSize));
  AListDetail.Add(AddHeaderInfo(1, 'Target MAC:', MACAddressToString(LTmpBytesTarget), PByte(LTmpBytesTarget), LHeaderARP.HardwareSize));

  SetLength(LTmpBytesSender,LHeaderARP.ProtocolSize);
  SetLength(LTmpBytesTarget,LHeaderARP.ProtocolSize);  

  {Sender}
  Move((aPacketData + LCurrentPos)^,LTmpBytesSender[0],LHeaderARP.ProtocolSize);
  Inc(LCurrentPos,LHeaderARP.ProtocolSize);

  {Target}
  Move((aPacketData+ LCurrentPos+LHeaderARP.HardwareSize)^,LTmpBytesTarget[0],LHeaderARP.ProtocolSize);
  
  case wpcapntohs(LHeaderARP.ProtocolType) of
    ETH_P_IP    :
      begin
        AListDetail.Add(AddHeaderInfo(1, 'Sender IP:', BytesToIPv4Str(LTmpBytesSender), PByte(LTmpBytesSender), SizeOf(LTmpBytesSender)));
        AListDetail.Add(AddHeaderInfo(1, 'Target IP:', BytesToIPv4Str(LTmpBytesTarget), PByte(LTmpBytesTarget), SizeOf(LTmpBytesTarget)));          
      end;
    ETH_P_ARP   :
      begin
        AListDetail.Add(AddHeaderInfo(1, 'Sender IP:', BytesToIPv4Str(LTmpBytesSender), PByte(LTmpBytesSender), SizeOf(LTmpBytesSender)));
        AListDetail.Add(AddHeaderInfo(1, 'Target IP:', BytesToIPv4Str(LTmpBytesTarget), PByte(LTmpBytesTarget), SizeOf(LTmpBytesTarget)));           
      end;
    ETH_P_IPV6  : 
      begin       
        // convert sender IP address to string
        LSenderIP := IPv6AddressToString(LTmpBytesSender);
        AListDetail.Add(AddHeaderInfo(1, 'Sender IP:', LSenderIP, PByte(LTmpBytesSender), SizeOf(LTmpBytesSender)));

        // convert target IP address to string
        LTargetIP := IPv6AddressToString(LTmpBytesTarget);
        AListDetail.Add(AddHeaderInfo(1, 'Target IP:', LTargetIP, PByte(LTmpBytesTarget), SizeOf(LTmpBytesTarget)));      
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
  aSizeEthEth := HeaderEthSize;

  // Check if the data size is sufficient for the Ethernet, IP, and UDP headers
  if (aSize < aSizeEthEth + HeaderLength(0)) then Exit;  

  aARPHeader := PTARPHeader(aData + aSizeEthEth);

  Result := True;
end;

end.
                                                 
