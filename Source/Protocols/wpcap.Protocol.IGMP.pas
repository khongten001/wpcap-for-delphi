unit wpcap.Protocol.IGMP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,System.Classes,
  System.Variants, wpcap.BufferUtils,WinSock,WinSock2,wpcap.IpUtils;

type

  {  https://www.rfc-editor.org/rfc/rfc3376
  
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |  Type = 0x11  | Max Resp Code |           Checksum            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                         Group Address                         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                       Source Address [1]                      |
      +-                                                             -+
      |                       Source Address [2]                      |
      +-                              .                              -+
      .                               .                               .
      .                               .                               .
      +-                                                             -+
      |                       Source Address [N]                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  }

  TIGMPHeader = record
     VerType        : Byte;
     Unused         : Byte;
     CheckSum       : Word; 
     Reserved       : Word; 
     NGroupRec      : Word    
  end;  
  PTIGMPHeader = ^TIGMPHeader;
  
  TIGMPGroupRecord = record
    RecType        : Byte;
    DataLen        : Byte;
    NumSrc         : Word; 
    Ipaddr         : LongWord;
  end;
  PTIGMPGroupRecord = ^TIGMPGroupRecord;  
  
  
  /// <summary>
  /// The IGMP protocol implementation class.
  /// </summary>
  TWPcapProtocolIGMP = Class(TWPcapProtocolBase)
  private
    class function TypeToString(const aType: Byte): String; static;
    class function RecordTypeToString(const aType: Byte): String; static;
  public
    /// <summary>
    /// Returns the default IGMP 0 - No port.
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the IGMP protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the IGMP protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    ///  Returns the length of the IGMP header.
    /// </summary>
    class function HeaderLength(aFlag:Byte): word; override;

    /// <summary>
    ///  Returns a pointer to the IGMP header.
    /// </summary>
    class function Header(const aData: PByte; aSize: Integer;var aIGMPHeader: PTIGMPHeader): Boolean; static;    
    /// <summary>
    /// Returns the acronym name of the IGMP protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; static;
    class function HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean; override;      
  end;


implementation

uses wpcap.Level.IP;


{ TWPcapProtocolMDNS }
class function TWPcapProtocolIGMP.DefaultPort: Word;
begin
  Result := 0;
end;

class function TWPcapProtocolIGMP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_IGMP
end;

class function TWPcapProtocolIGMP.ProtoName: String;
begin
  Result := 'Internet Group Management Protocol';
end;

class function TWPcapProtocolIGMP.AcronymName: String;
begin
  Result := 'IGMP';
end;

class function TWPcapProtocolIGMP.IsValid(const aPacket: PByte;aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var aIPClass : TIpClaseType;  
begin
  result := True;
  aIPClass:= IpClassType(aPacket,aPacketSize); 
  if aIPClass = imtIpv6 then
  begin
      if result then
      begin
        aAcronymName     := Format('%sv6',[AcronymName]);
        aIdProtoDetected := IDDetectProto;
      end;      
  end;
end;
  
class function TWPcapProtocolIGMP.HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer;AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;
var LHeader        : PTIGMPHeader;
    LGroupRec      : PTIGMPGroupRecord;
    LSizeEthIP     : Integer;
    I              : Integer;
    X              : Integer;
    LCurrentPos    : Integer;
    LLongWordValue : LongWord;
begin
  Result := False;
  FisFilterMode := aisFilterMode;

  if not Header(aPacketData,aPacketSize,LHeader) then exit;
  AListDetail.Add(AddHeaderInfo(aStartLevel,AcronymName, Format('%s (%s)',[ProtoName,AcronymName]),NULL,PByte(LHeader),HeaderLength(0))); 
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Type',[AcronymName]), 'Type:',TypeToString(LHeader.VerType),@LHeader.VerType,sizeOf(LHeader.VerType), LHeader.VerType ));             
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.CheckSum',[AcronymName]), 'CheckSum:',wpcapntohs( LHeader.CheckSum),@LHeader.CheckSum,sizeOf(LHeader.CheckSum) ));                 
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Reserved',[AcronymName]), 'Reserved:',wpcapntohs( LHeader.Reserved),@LHeader.Reserved,sizeOf(LHeader.Reserved) ));       
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.NGroupRecords',[AcronymName]), 'Num Group Records:',wpcapntohs( LHeader.NGroupRec),@LHeader.NGroupRec,sizeOf(LHeader.NGroupRec) )); 

  LSizeEthIP  := TWpcapIPHeader.EthAndIPHeaderSize(aPacketData,aPacketSize);
  LCurrentPos := LSizeEthIP+SizeOf(TIGMPHeader);

  if LCurrentPos+SizeOf(TIGMPGroupRecord) > aPacketSize then exit;
  
  for I := 0 to wpcapntohs( LHeader.NGroupRec)-1 do
  begin
    LGroupRec := PTIGMPGroupRecord(aPacketData + LCurrentPos );
    if LCurrentPos >aPacketSize  then break;
    
    AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.GroupRecord',[AcronymName]), 'Group record:',null,@LGroupRec,SizeOf(LGroupRec)));
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.GroupRecord.Type',[AcronymName]), 'Type:',RecordTypeToString(LGroupRec.RecType),@LGroupRec.RecType,sizeOf(LGroupRec.RecType), LGroupRec.RecType ));            
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.GroupRecord.AudLen',[AcronymName]), 'Aux Data Len:',LGroupRec.DataLen,@LGroupRec.DataLen,sizeOf(LGroupRec.DataLen) ));    
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.GroupRecord.NSrc',[AcronymName]), 'Num src:',wpcapntohs(LGroupRec.NumSrc),@LGroupRec.NumSrc,sizeOf(LGroupRec.NumSrc) ));   
    AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.GroupRecord.MulticastAddr',[AcronymName]), 'Multicast addess:',intToIPV4(LGroupRec.Ipaddr),@LGroupRec.Ipaddr,sizeOf(LGroupRec.Ipaddr) ));  
    Inc(LCurrentPos,SizeOf(TIGMPGroupRecord));

    if LCurrentPos > aPacketSize then break;
    
    
    
    for X := 0 to wpcapntohs(LGroupRec.NumSrc) -1 do
    begin
      LLongWordValue := PLongWord(aPacketData+LCurrentPos)^ ;
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.GroupRecord.SrcAddr',[AcronymName]), 'Source Address:',intToIPV4(LLongWordValue),@LLongWordValue,sizeOf(LLongWordValue) ));
      Inc(LCurrentPos,SizeOf(LLongWordValue));
    end;
    
    INC(LCurrentPos,LGroupRec.DataLen);  
    {Padding ??}  
  end;  
  Result := True;       
end;

class function TWPcapProtocolIGMP.HeaderLength(aFlag: Byte): word;
begin
  Result := SizeOf(TIGMPHeader) + (aFlag *SizeOf(TIGMPGroupRecord));
end;

class function TWPcapProtocolIGMP.Header(const aData: PByte; aSize: Integer; var aIGMPHeader: PTIGMPHeader): Boolean;
var aSizeEthIP : Word;
begin
  Result     := False;
  aSizeEthIP := TWpcapIPHeader.EthAndIPHeaderSize(AData,aSize);

  // Check if the data size is sufficient for the Ethernet, IP, and UDP headers
  if (aSize < aSizeEthIP + HeaderLength(0)) then Exit;  


  // Parse the Ethernet header
  case TWpcapIPHeader.IpClassType(aData,aSize) of
    imtIpv4 : 
      begin
        // Parse the IPv4 header
        if TWpcapIPHeader.HeaderIPv4(aData,aSize).Protocol <> IPPROTO_IGMP then Exit;

        // Parse the UDP header
        aIGMPHeader := PTIGMPHeader(aData + aSizeEthIP);
        Result      := True;     
      end;
   imtIpv6:
      begin

        if Not (TWpcapIPHeader.HeaderIPv6(aData,aSize).NextHeader in [IPPROTO_IGMP]) then Exit;
        // Parse the UDP header
        aIGMPHeader := PTIGMPHeader(aData + aSizeEthIP);
        Result      := True;
      end;      
  end;  
end;

class function TWPcapProtocolIGMP.TypeToString(const aType:Byte):String;
begin
  case aType of
    17: Result := 'Membership Query';
    18: Result := 'Version 1 Membership Report  ';
    22: Result := 'Version 2 Membership Report ';            
    23: Result := 'Version 2 Leave Group';                
    34: Result := 'Version 3 Membership Report';

  else Result := 'Unknown';  
  end;
end;

class function TWPcapProtocolIGMP.RecordTypeToString(const aType:Byte):String;
begin
  case aType of
    1: Result := 'MODE_IS_INCLUDE';
    2: Result := 'MODE_IS_EXCLUDE';
    3: Result := 'CHANGE_TO_INCLUDE_MODE';
    4: Result := 'CHANGE_TO_EXCLUDE_MODE';
    5: Result := 'ALLOW_NEW_SOURCES';
    6: Result := 'BLOCK_OLD_SOURCES';
  else Result := 'Unknown';  
  end;
end;

end.
                                                 
