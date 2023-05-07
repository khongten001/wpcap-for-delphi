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

unit wpcap.Protocol.TCP;

interface

uses
  wpcap.Conts, wpcap.Types, wpcap.BufferUtils, System.Types, wpcap.Protocol.Base,
  System.Math, System.Variants, System.SysUtils, wpcap.StrUtils, winsock,
  wpcap.Packet, System.DateUtils;

type
  //https://datatracker.ietf.org/doc/html/rfc793#page-15

{    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

}


  TCPHdr = packed record
    SrcPort   : Uint16;    // TCP source port
    DstPort   : Uint16;    // TCP destination port
    SeqNum    : Uint32;    // TCP sequence number
    AckNum    : Uint32;    // TCP acknowledgment number
    DataOff   : Uint8;     // TCP data offset (number of 32-bit words in header)
    Flags     : Uint8;     // TCP flags (SYN, ACK, FIN, etc.)
    WindowSize: Uint16;    // TCP window size
    Checksum  : Uint16;    // TCP checksum
    UrgPtr    : Uint16;    // TCP urgent pointer
  end;
  PTCPHdr = ^TCPHdr;


  /// <summary>
  /// Base class for all protocols that use the TCP stands for Transmission Control Protocol. (TCP).
  /// This class extends the TWPcapProtocolBase class with TCP-specific functions.
  /// </summary>
  TWPcapProtocolBaseTCP = Class(TWPcapProtocolBase)
  private

  const
    TCP_OPTION_EOL            = 0;  //(End of Option List, Kind = 0): Indicates the end of the options list.
    TCP_OPTION_NOP            = 1;  //(No-Operation, Kind = 1): Used for padding and alignment.
    TCP_OPTION_MSS            = 2;  // (Maximum Segment Size, Kind = 2): Used to specify the maximum segment size that can be received by a host.
    TCP_OPTION_WSCALE         = 3;  // (Window Scale, Kind = 3): Used to specify a scale factor to increase the maximum window size.
    TCP_OPTION_SACKOK         = 4;  // (Selective Acknowledgment Permitted, Kind = 4): Indicates that the sender is willing to receive selective acknowledgment (SACK) options.
    TCP_OPTION_SACK           = 5;  // (Selective Acknowledgment, Kind = 5): Used to acknowledge non-contiguous blocks of data.
    TCP_OPTION_ECHO           = 6;  // (Echo, Kind = 6): Used to carry a timestamp from the sender to the receiver.
    TCP_OPTION_ECHOREPLY      = 7;  // (Echo Reply, Kind = 7): Used to carry a timestamp from the receiver back to the sender.
    TCP_OPTION_TIMESTAMP      = 8;  // (Timestamps, Kind = 8): Used to carry two timestamps: one from the sender to the receiver and one from the receiver back to the sender.

    {TCP FLAGS}
    TCP_FLAG_FIN              = $01;
    TCP_FLAG_SYN              = $02;
    TCP_FLAG_RST              = $04;
    TCP_FLAG_ACK              = $10;

    ///<summary>
    /// Returns a string representing a TCP flags value.
    ///</summary>
    /// <param name="aFlags">The TCP flags value.</param>
    /// <returns>The representation of the TCP flags value as a string.</returns>
    class function GetTCPFlags(aFlags: Uint8): string; static;

    ///<summary>
    /// Returns a string representing a TCP kind value.
    ///</summary>
    /// <param name="aKind">The TCP kind value.</param>
    /// <returns>The representation of the TCP kind value as a string.</returns>
    class function TCPKindToString(const aKind: Uint8): string;


  protected
    ///<summary>
    /// Updates TCP information.
    ///</summary>
    /// <param name="aSrcAddr">The source IP address.</param>
    /// <param name="aDstAddr">The destination IP address.</param>
    /// <param name="aSrcPort">The source port number.</param>
    /// <param name="aDstPort">The destination port number.</param>
    /// <param name="aTCPFlags">The TCP flags value.</param>
    /// <param name="aSeqNum">The packet sequence number.</param>
    /// <param name="aAckNum">The packet acknowledgement number.</param>
    /// <param name="aDatePacket">The date of the packet.</param>
    /// <param name="aAdditionalInfo">Additional packet information.</param>
    class procedure UpdateFlowInfo(const aSrcAddr, aDstAddr: string; aSrcPort, aDstPort: Uint16; aTCPFlags: Uint8; aSeqNum, aAckNum: Uint32;aAdditionalInfo: PTAdditionalInfo); override;
    ///<summary>
    /// Returns the offset value in bytes based on a given data offset.
    ///</summary>
    /// <param name="aDataOffset">The data offset value to convert.</param>
    /// <returns>The offset value in bytes.</returns>  
    class function GetDataOFFSetBytes(const aDataOFFset: Byte): integer; 

    /// <summary>
    /// Checks whether the length of the payload is valid for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function PayLoadLengthIsValid(const aTCPPtr: PTCPHdr;const aPacketData:PByte;aPacketSize:Word): Boolean; virtual;  

    class function GetFlowTimeOut : Byte;override;  
  public
    class function IsValidByPort(aTestPort, aDstPort: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean;overload;  

    /// <summary>
    /// Returns the acronym name of the POP3 protocol.
    /// </summary>    
    class function AcronymName: String; override;

    /// <summary>
    /// Returns the default 0 for TCP
    /// </summary>    
    class function DefaultPort: Word; override;

    /// <summary>
    /// Returns the header length for TCP prococol.
    /// </summary>        
    class function HeaderLength(aFlag:Byte): word; override;

    /// <summary>
    /// Returns the ID number of the TCP protocol.
    /// </summary>    
    class function IDDetectProto: byte; override;
    
    /// <summary>
    /// Returns the length of the TCP payload.
    /// </summary>
    class function TCPPayLoadLength(const aTCPPtr: PTCPHdr;const aPacketData:PByte;aPacketSize:Word): Word; static;

    /// <summary>
    /// Checks whether the packet is valid for the protocol.
    /// This function is marked as virtual, which means that it can be overridden by subclasses.
    /// </summary>
    class function IsValid(const aPacket:PByte;aPacketSize:Integer;var aAcronymName: String;var aIdProtoDetected: Byte): Boolean; virtual;

    /// <summary>
    /// Returns the source port number for the TCP packet.
    /// </summary>
    class function SrcPort(const aTCPPtr: PTCPHdr): Word; static;

    /// <summary>
    /// Returns the destination port number for the TCP packet.
    /// </summary>
    class function DstPort(const aTCPPtr: PTCPHdr): Word; static;   
    
    /// <summary>
    /// Extracts the TCP header from a packet and returns it through aPHeader.
    /// </summary>
    /// <param name="aData">Pointer to the start of the packet.</param>
    /// <param name="aSize">Size of the packet.</param>
    /// <param name="aPHeader">Pointer to the TCP header.</param>
    /// <returns>True if the TCP header was successfully extracted, False otherwise.</returns>
    class function HeaderTCP(const aData: PByte; aSize: Integer; var aPTCPHdr: PTCPHdr): Boolean;static;

    /// <summary>
    /// Returns a pointer to the payload of the provided TCP data.
    /// </summary>
    /// <param name="AData">The TCP data to extract the payload from.</param>
    /// <param name="aSize">Size of packet</param>
    /// <returns>A pointer to the beginning of the TCP payload.</returns>
    class function GetTCPPayLoad(const AData: PByte;aSize: word): PByte;static;  

    ///  <summary>
    ///    Analyzes a TCP protocol packet to determine its acronym name and protocol identifier.
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
    class function AnalyzeTCPProtocol(const aData:Pbyte;aSize:Integer;var aArcronymName:String;var aIdProtoDetected:Byte):boolean;static;  
    class function GetPayLoad(const aPacketData: PByte;aPacketSize: Integer; var aSize,aSizeTotal: Integer): PByte; override;
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer;AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalInfo: PTAdditionalInfo): Boolean;override;
  end;      

implementation

uses wpcap.Level.Ip,wpcap.protocol;

{ TWPcapProtocolBaseTCP }

class function TWPcapProtocolBaseTCP.GetPayLoad(const aPacketData: PByte;aPacketSize: Integer; var aSize,aSizeTotal: Integer): PByte;
var LPTCPHdr : PTCPHdr;
begin
  Result := nil;
  aSize  := 0;
  if not HeaderTCP(aPacketData,aPacketSize,LPTCPHdr) then exit;
  Result := GetTCPPayLoad(aPacketData,aPacketSize);
  aSize  := TCPPayLoadLength(LPTCPHdr,aPacketData,aPacketSize);
  if aSizeTotal <= 0 then
    aSizeTotal := aSize;
end;

class procedure TWPcapProtocolBaseTCP.UpdateFlowInfo(const aSrcAddr, aDstAddr: string; aSrcPort, aDstPort: Uint16;aTCPFlags:Uint8; aSeqNum, aAckNum: Uint32;aAdditionalInfo: PTAdditionalInfo);
var LKey           : string; 
    LFlowInfo      : TFlowInfo;
    LFlowFound     : Boolean;
    LDeltaMin      : Int64;
    LSeqAckInfoAdd : TSeqAckInfo;

    { This function is designed to identify TCP retransmissions in a network capture. 
      However, it may not identify all retransmissions and may also generate false positives due to various 
      reasons such as asymmetric network traffic or limitations in the detection algorithm.

      TODO review and improve the function.}    
    Procedure CheckisRetrasmission;
    var LSeqAckInfo : TSeqAckInfo;
    begin
      LDeltaMin := Abs(MinutesBetween(aAdditionalInfo.PacketDate,LFlowInfo.PacketDate)); 
      
      {TODO CHECK WINDOWS SLIDE} 
      if  ( LDeltaMin < GetFlowTimeOut) and LFlowInfo.SeqAckList.TryGetValue(Format('%d-%d',[aSeqNum,aAckNum]),LSeqAckInfo) then
      begin
        if (LFlowInfo.SrcIP = aSrcAddr )and (LSeqAckInfo.PayLoadSize <= 0) then exit;

        if (aAdditionalInfo.PayloadSize <= 0 ) then  Exit;
                
        aAdditionalInfo.FrameNumber     := LSeqAckInfo.FrameNumber;
        aAdditionalInfo.isRetrasmission := true;
        aAdditionalInfo.Info            := Format('%s [Retrasmission by list of framenumber [%d]]',[aAdditionalInfo.Info,LSeqAckInfo.FrameNumber]);
      end
      else if aAdditionalInfo.TCPTimeStamp > -1 then
      begin 
        if (aAdditionalInfo.PayloadSize <= 0 ) then  Exit;     
        if LFlowInfo.TCPTimeStamp = -1 then Exit;
         
        // Check TCP Timestamps to identify retransmissions
        if (aAdditionalInfo.TCPTimeStamp <= LFlowInfo.TCPTimeStamp ) and ( aSeqNum < LFlowInfo.prevSeqNum) and ( LDeltaMin < GetFlowTimeOut) then  
        begin 
          aAdditionalInfo.Info := Format('%s [Retrasmission by Seq and TCP options]',[aAdditionalInfo.Info]);
          aAdditionalInfo.isRetrasmission := True;       {Some false retrasmission}
        end;
      end; 

      {TODO Create a SACK_LIST and check in SeqAckList than identy framenubmer ?? but how ??}

      if aAdditionalInfo.isRetrasmission then
      begin
        aAdditionalInfo.SequenceNumber       := 0;
        aAdditionalInfo.AcknowledgmentNumber := 0;             
      end;
    end;

    function FlagRSTorFINPresent:Boolean;
    begin
      Result :=  ( ( aTCPFlags and TCP_FLAG_RST > 0 ) or //RST
                   ( aTCPFlags and TCP_FLAG_FIN > 0 ) ) // 'FIN
    end;
begin
  if not Assigned(FlowInfoList) then Exit;
  
  LFlowFound  := GetInfoFlow(aSrcAddr,aDstAddr,aSrcPort,aDstPort,LKey,@LFlowInfo);

  // Check if session already exists in the dictionary
  if LFlowFound then
  begin  
    if ( aTCPFlags and TCP_FLAG_ACK > 0 ) then // Check if ACK flag is set
    begin
      if (aTCPFlags and TCP_FLAG_SYN > 0) then // Check if SYN flag is set
      begin
        CheckisRetrasmission;
        if not aAdditionalInfo.isRetrasmission  then        
        begin
          // This is the first packet of a new session, reset previous sequence and acknowledgement numbers
          LFlowInfo.SrcIP                      := aSrcAddr;
          LFlowInfo.DstIP                      := aDstAddr;
          LFlowInfo.FirstSeqNum                := aSeqNum;
          LFlowInfo.FirstAckNum                := aAckNum;
          LFlowInfo.prevSeqNum                 := aSeqNum;
          LFlowInfo.prevAckNum                 := aAckNum;
          LFlowInfo.FLowId                     := GetNewFlowID;
          LFlowInfo.PacketDate                 := aAdditionalInfo.PacketDate;
          if aAdditionalInfo.TCPTimeStamp > -1 then          
            LFlowInfo.TCPTimeStamp  := aAdditionalInfo.TCPTimeStamp;

          LFlowInfo.SeqAckList.Clear;      
          LSeqAckInfoAdd.FrameNumber := aAdditionalInfo.FrameNumber;
          LSeqAckInfoAdd.PayloadSize := aAdditionalInfo.PayLoadSize;
          LFlowInfo.SeqAckList.Add(Format('%d-%d',[aSeqNum,aAckNum]),LSeqAckInfoAdd);

          aAdditionalInfo.isRetrasmission      := False;
          aAdditionalInfo.SequenceNumber       := 1;
          aAdditionalInfo.AcknowledgmentNumber := 1;        
          aAdditionalInfo.FlowID               := LFlowInfo.FLowId; 
          FlowInfoList.Remove(LKey);
          FlowInfoList.AddOrSetValue(LKey, LFlowInfo);
        end;
            
        Exit;
      end
      else // Normal packet with ACK flag set
      begin   
		    {TODO CHECK WINDOWS SLIDE}
        CheckisRetrasmission;
        if not aAdditionalInfo.isRetrasmission then
        begin                 
          if ( LDeltaMin < GetFlowTimeOut) then   
          begin
            if aSrcAddr = LFlowInfo.SrcIP then
            begin
              aAdditionalInfo.SequenceNumber       := Max(0,aSeqNum - LFlowInfo.FirstSeqNum)+1;
              aAdditionalInfo.AcknowledgmentNumber := Max(0,aAckNum - LFlowInfo.FirstAckNum)+1;            
            end
            else
            begin
              aAdditionalInfo.SequenceNumber       := Max(0,aSeqNum - LFlowInfo.FirstAckNum)+1;
              aAdditionalInfo.AcknowledgmentNumber := Max(0,aAckNum - LFlowInfo.FirstSeqNum)+1;
            end;
          end
          else  
          begin  // New Flow for timeout
            aAdditionalInfo.SequenceNumber       := 1;
            aAdditionalInfo.AcknowledgmentNumber := 1;
            LFlowInfo.FLowId                         := GetNewFlowID;
          end;
        end;
        LFlowInfo.prevSeqNum  := aSeqNum;
        LFlowInfo.prevAckNum  := aAckNum;
      end;
    end
    else
    begin
      {Nothing}
      aAdditionalInfo.SequenceNumber       := 0;
      aAdditionalInfo.AcknowledgmentNumber := 0;
      aAdditionalInfo.isRetrasmission      := False;           
    end;    
    
    aAdditionalInfo.FlowID := LFlowInfo.FLowId;      
                                                                          
    if FlagRSTorFINPresent or ( LDeltaMin >= GetFlowTimeOut) then
    begin
      FreeAndNil(LFlowInfo.SeqAckList);    
      FlowInfoList.Remove(LKey);
      exit;
    end;
    LSeqAckInfoAdd.FrameNumber := aAdditionalInfo.FrameNumber;
    LSeqAckInfoAdd.PayloadSize := aAdditionalInfo.PayLoadSize;
    LFlowInfo.SeqAckList.TryAdd(Format('%d-%d',[aSeqNum,aAckNum]),LSeqAckInfoAdd);     
    // Update the dictionary entry if session are not finished
    LFlowInfo.PacketDate  := aAdditionalInfo.PacketDate;
    FlowInfoList.AddOrSetValue(LKey, LFlowInfo);
  end
  else
  begin
    // Add new session to the dictionary
    aAdditionalInfo.SequenceNumber       := 1;
    aAdditionalInfo.AcknowledgmentNumber := 1;          

    if FlagRSTorFINPresent then Exit;
    
    LFlowInfo.SrcIP            := aSrcAddr;
    LFlowInfo.DstIP            := aDstAddr;    
    LFlowInfo.FirstSeqNum      := aSeqNum;
    LFlowInfo.FirstAckNum      := aAckNum;  
    LFlowInfo.prevSeqNum       := aSeqNum;
    LFlowInfo.prevAckNum       := aAckNum;    
    LFlowInfo.PacketDate       := aAdditionalInfo.PacketDate;
    if aAdditionalInfo.TCPTimeStamp > -1 then              
      LFlowInfo.TCPTimeStamp     := aAdditionalInfo.TCPTimeStamp;    
    LFlowInfo.FLowId           := GetNewFlowID;
    LFlowInfo.SeqAckList       := TSeqAckList.Create;
    LSeqAckInfoAdd.FrameNumber := aAdditionalInfo.FrameNumber;
    LSeqAckInfoAdd.PayloadSize := aAdditionalInfo.PayLoadSize;
    LFlowInfo.SeqAckList.TryAdd(Format('%d-%d',[aSeqNum,aAckNum]),LSeqAckInfoAdd);      
    aAdditionalInfo.FlowID := LFlowInfo.FLowId;
    FlowInfoList.Add(LKey, LFlowInfo);
  end;
end;

class function TWPcapProtocolBaseTCP.DefaultPort: Word;
begin
  Result := 0; 
end;

class function TWPcapProtocolBaseTCP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_TCP;
end;

class function TWPcapProtocolBaseTCP.HeaderLength(aFlag:Byte): word;
begin
  Result := SizeOf(TCPHdr)
end;

class function TWPcapProtocolBaseTCP.AcronymName: String;
begin
  Result := 'TCP';
end;

class function TWPcapProtocolBaseTCP.AnalyzeTCPProtocol(const aData:Pbyte;aSize:Integer;var aArcronymName:String;var aIdProtoDetected:Byte):boolean;
var LTCPPPtr  : PTCPHdr;
    I        : Integer;
begin
  Result := False;
  if not HeaderTCP(aData,aSize,LTCPPPtr) then exit;
  
  aIdProtoDetected := DETECT_PROTO_TCP;

  for I := 0 to FListProtolsTCPDetected.Count-1 do
  begin
    FListProtolsTCPDetected[I].OnLog          := OnLog;
    FListProtolsTCPDetected[I].OnGetNewFlowID := OnGetNewFlowID;    
    
    if FListProtolsTCPDetected[I].IsValid(aData,aSize,aArcronymName,aIdProtoDetected) then
    begin
      Result := True;
      Exit;
    end;
  end;
end;


class function TWPcapProtocolBaseTCP.PayLoadLengthIsValid(const aTCPPtr: PTCPHdr;const aPacketData:PByte; aPacketSize:Word): Boolean;
var DataOffset: Integer;
begin
   // Get the data offset in bytes
   DataOffset := GetDataOFFSetBytes(aTCPPtr^.DataOff)*4;
   // Get the data offset in bytes
   Result     := aPacketSize - TWpcapIPHeader.EthAndIPHeaderSize(aPacketData,aPacketSize) > DataOffset;
end;

class function TWPcapProtocolBaseTCP.TCPPayLoadLength(const aTCPPtr: PTCPHdr;const aPacketData:PByte;aPacketSize:Word): Word;
var DataOffset: Integer;
begin
   // Get the data offset in bytes
   DataOffset := GetDataOFFSetBytes(aTCPPtr^.DataOff)*4;
   // Calculate the length of the payload
   Result := aPacketSize - TWpcapIPHeader.EthAndIPHeaderSize(aPacketData,aPacketSize)-DataOffset;
end;

class function TWPcapProtocolBaseTCP.IsValid(const aPacket:PByte;aPacketSize:Integer;var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var LTCPPtr: PTCPHdr;
begin
  Result := False;    
  if not HeaderTCP(aPacket,aPacketSize,LTCPPtr) then exit;   
  if not PayLoadLengthIsValid(LTCPPtr,aPacket,aPacketSize) then  Exit;

  Result := IsValidByDefaultPort(SrcPort(LTCPPtr),DstPort(LTCPPtr),aAcronymName,aIdProtoDetected)
end;

class function TWPcapProtocolBaseTCP.SrcPort(const aTCPPtr: PTCPHdr): Word;
begin
  Result := wpcapntohs(aTCPPtr.SrcPort);
end;

class function TWPcapProtocolBaseTCP.DstPort(const aTCPPtr: PTCPHdr): Word;
begin
  Result := wpcapntohs(aTCPPtr.DstPort);
end;

class function TWPcapProtocolBaseTCP.IsValidByPort(aTestPort,aDstPort: Integer;
  var aAcronymName: String; var aIdProtoDetected: Byte): Boolean;
begin
  Result := False;
  if aTestPort = 0 then Exit;
  
   Result := ( aDstPort = aTestPort );

   if not Result then exit;

   aAcronymName     := AcronymName;
   aIdProtoDetected := IDDetectProto;   
end;

class function TWPcapProtocolBaseTCP.GetTCPPayLoad(const AData: PByte; aSize: word): PByte;
var LTCPHeader : PTCPhdr;
    DataOffset : Uint16;   
begin
  HeaderTCP(AData,aSize,LTCPHeader);
  
  DataOffset := GetDataOFFSetBytes( LTCPHeader^.DataOff)*4+1;
  Result     := AData + TWpcapIPHeader.EthAndIPHeaderSize(AData,aSize) +  DataOffset-1; 
end;

class function TWPcapProtocolBaseTCP.GetDataOFFSetBytes(const aDataOFFset:Byte):integer;
begin 
  Result := aDataOFFset shr 4;
end;

class function TWPcapProtocolBaseTCP.HeaderTCP(const aData: PByte; aSize: Integer; var aPTCPHdr: PTCPHdr): Boolean;
var LSizeEthAndIP : Word;
    LHeaderV4     : PTIPHeader;
    LNewPacketLen : Integer;
    LNewPacketData: PByte;
    LHeaderV6     : PIpv6Header;      
begin
  Result        := False;
  LSizeEthAndIP := TWpcapIPHeader.EthAndIPHeaderSize(AData,aSize,False);
  // Check if the data size is sufficient for the Ethernet, IP, and TCP headers
  if (aSize < LSizeEthAndIP + SizeOf(TCPHdr)) then Exit;
  
    // Parse the Ethernet header
  case TWpcapIPHeader.IpClassType(aData,aSize) of
    imtIpv4 : 
      begin
        LHeaderV4 := TWpcapIPHeader.HeaderIPv4(aData,aSize);
        if not Assigned(LHeaderV4) then Exit;        
        if LHeaderV4.Protocol = IPPROTO_IPV6 then
        begin
	        LNewPacketData := TWpcapIPHeader.GetNextBufferHeader(aData,aSize,0,ETH_P_IPV6,LNewPacketLen,False);
          Try
            Result := HeaderTCP(LNewPacketData, LNewPacketLen,aPTCPHdr);
            Exit;
          Finally
            FreeMem(LNewPacketData);
          End;
        end;
        
        // Parse the IPv4 header
        if (LHeaderV4.Protocol <> IPPROTO_TCP) then exit;

        // Parse the UDP header
        aPTCPHdr := PTCPHdr(aData + LSizeEthAndIP);

        Result   := True;     
      end;
   imtIpv6:
      begin
        LHeaderV6 := TWpcapIPHeader.HeaderIPv6(aData,aSize);

        if LHeaderV6.NextHeader = IPPROTO_IP then
        begin
	        LNewPacketData := TWpcapIPHeader.GetNextBufferHeader(aData,aSize,0,ETH_P_IP,LNewPacketLen,False);
          Try
            Result := HeaderTCP(LNewPacketData, LNewPacketLen,aPTCPHdr);
            Exit;
          Finally
            FreeMem(LNewPacketData);
          End;
        end;        
        if LHeaderV6.NextHeader <> IPPROTO_TCP then Exit;      

        // Parse the TCP header
        aPTCPHdr := PTCPHdr(aData + LSizeEthAndIP);
        Result   := True;
      end;      
  end;
end;

class function TWPcapProtocolBaseTCP.TCPKindToString(const aKind: Uint8): string;
begin
  case aKind of
    TCP_OPTION_EOL            : Result := 'End of Options List';
    TCP_OPTION_NOP            : Result := 'No Operation';
    TCP_OPTION_MSS            : Result := 'Maximum Segment Size';
    TCP_OPTION_WSCALE         : Result := 'Window Scale';
    TCP_OPTION_SACKOK         : Result := 'Selective Acknowledgement Permitted';
    TCP_OPTION_SACK           : Result := 'Selective Acknowledgement';
    TCP_OPTION_ECHO           : Result := 'Echo';
    TCP_OPTION_ECHOREPLY      : Result := 'Echo Reply';
    TCP_OPTION_TIMESTAMP      : Result := 'Time Stamp';
    // Aggiungere altre costanti qui, se necessario
    else Result := 'Unknown';
  end;
end;

class function TWPcapProtocolBaseTCP.GetTCPFlags(aFlags: Uint8): string;
begin
  Result := String.Empty;
  if aFlags and $80 > 0 then Result := Result + 'CWR,';
  if aFlags and $40 > 0 then Result := Result + 'ECE,';
  if aFlags and $20 > 0 then Result := Result + 'URG,';
  if aFlags and TCP_FLAG_ACK > 0 then Result := Result + 'ACK,';
  if aFlags and $08 > 0 then Result := Result + 'PSH,';
  if aFlags and TCP_FLAG_RST > 0 then Result := Result + 'RST,';
  if aFlags and TCP_FLAG_SYN > 0 then Result := Result + 'SYN,';
  if aFlags and TCP_FLAG_FIN > 0 then Result := Result + 'FIN,';
  if Result <> '' then
    Result := Copy(Result, 1, Length(Result) - 1);
end;

class function TWPcapProtocolBaseTCP.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalInfo: PTAdditionalInfo): Boolean;
var LPTCPHdr             : PTCPHdr;
    LesBits              : Integer;
    LHeaderLen           : Integer;
    LOffset              : Integer;
    LBckOffSet           : Integer;
    LEthandIpSize        : Integer;
    LUint8Value          : Uint8;
    LOptionKind          : Uint8;  
    LSrcPort             : Uint16;  
    LDstPort             : Uint16;   
    LSeqNum              : Uint32;
    LAckNum              : Uint32;
    LIsRetransmission    : Boolean;
    LRelativeSeqNumber   : Integer;
    LSizePayLoad         : Integer;
    LOptionStr           : String;
    LFlagsStr            : String;
    LHeaderIPv4          : PTIPHeader;
    LInternalIP          : TInternalIP;
    LTCPTimeStamp        : Integer;
begin
  Result               := False;                        
  FIsFilterMode        := aisFilterMode;
  aAdditionalInfo.Info := String.Empty;
  if not HeaderTCP(aPacketData,aPacketSize,LPTCPHdr) then exit;

  LEthAndIpSize               := TWpcapIPHeader.EthAndIPHeaderSize(aPacketData,aPacketSize);
  LHeaderLen                  := GetDataOFFSetBytes(LPTCPHdr^.DataOff) *4;
  LSrcPort                    := wpcapntohs(LPTCPHdr.SrcPort);
  LDstPort                    := wpcapntohs(LPTCPHdr.DstPort);
  LAckNum                     := wpcapntohl(LPTCPHdr.AckNum);
  LSeqNum                     := wpcapntohl(LPTCPHdr.SeqNum);
  LSizePayLoad                := TCPPayLoadLength(LPTCPHdr,aPacketData,aPacketSize);  
  aAdditionalInfo.PayLoadSize := LSizePayLoad;
  
  AListDetail.Add(AddHeaderInfo(aStartLevel,AcronymName,'Transmission Control Protocol',Format('Src Port: %d, Dst %d: 80, Seq: %u, Ack: %u, Len: %s',[LSrcPort,LDstPort,
                                                                                        LSeqNum,LAckNum,SizeTostr(LPTCPHdr.DataOff shr 4)]),PByte(aPacketData+LEthAndIpSize),LHeaderLen));  
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.HeaderLen',[AcronymName]), 'Header length:',SizeToStr(LHeaderLen), PByte(@LPTCPHdr.DataOff),2));              
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Source',[AcronymName]), 'Source:',LSrcPort, PByte(@LPTCPHdr.SrcPort),SizeOf(LPTCPHdr.SrcPort)));    
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Destination',[AcronymName]), 'Destination:',LDstPort, PByte(@LPTCPHdr.DstPort),SizeOf(LPTCPHdr.DstPort)));         
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SequenceNumberRaw',[AcronymName]), 'Sequence number(RAW):',LSeqNum, PByte(@LPTCPHdr.SeqNum),SizeOf(LPTCPHdr.SeqNum)));      
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.AcknowledgmentNumberRaw',[AcronymName]), 'Acknowledgment number(RAW):',LAckNum, PByte(@LPTCPHdr.AckNum),SizeOf(LPTCPHdr.AckNum)));        
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.MsgLen',[AcronymName]), 'Data offset:',GetDataOFFSetBytes(LPTCPHdr^.DataOff), PByte(@LPTCPHdr.DataOff),2));          
  LesBits := (LPTCPHdr.DataOff and $0F) shl 2; 
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.ReservedBits',[AcronymName]), 'Reserved bits:',LesBits,PByte(LesBits),2));          
  LFlagsStr := GetTCPFlags(LPTCPHdr.Flags);
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Flags',[AcronymName]), 'Flags:',Format('%s %S [%s]',[ByteToBinaryString(GetByteFromWord(LPTCPHdr.Flags,0)),ByteToBinaryString(GetByteFromWord(LPTCPHdr.Flags,1)),LFlagsStr]), PByte(@LPTCPHdr.Flags),SizeOf(LPTCPHdr.Flags), LPTCPHdr.Flags ));   
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.WindowSize',[AcronymName]), 'Window size:',wpcapntohs(LPTCPHdr.WindowSize), PByte(@LPTCPHdr.WindowSize),SizeOf(LPTCPHdr.WindowSize)));        
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Checksum',[AcronymName]), 'Checksum:',wpcapntohs(LPTCPHdr.Checksum), PByte(@LPTCPHdr.Checksum),SizeOf(LPTCPHdr.Checksum)));        
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.UrgentPointer',[AcronymName]), 'Urgent pointer:',wpcapntohs(LPTCPHdr.UrgPtr), PByte(@LPTCPHdr.UrgPtr),SizeOf(LPTCPHdr.UrgPtr)));   
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.PayloadLen',[AcronymName]), 'Payload length:',SizeToStr(LSizePayLoad), PByte(@LPTCPHdr.UrgPtr),SizeOf(LPTCPHdr.UrgPtr)));     
    
  LOffset := SizeOf(TCPHdr)+LEthAndIpSize; 
  inc(LHeaderLen,LEthAndIpSize);

  if not LFlagsStr.IsEmpty then
    aAdditionalInfo.Info := Format( '%S Flags: [%s]',[aAdditionalInfo.Info,LFlagsStr]).Trim;
  LTCPTimeStamp := -1;  
  if LHeaderLen > LOffset then
  begin
    LBckOffSet := LOffset;
    ParserGenericBytesValue(aPacketData,aStartLevel+1,LHeaderLen,LHeaderLen - LOffset,Format('%s.Options',[AcronymName]), 'Options:',AListDetail,nil,True,LOffset); 
    LOffset := LBckOffSet;            

    while LHeaderLen > LOffset do
    begin
      LBckOffSet  := LOffset;
      ParserGenericBytesValue(aPacketData,aStartLevel+2,LHeaderLen,LHeaderLen - LOffset,Format('%s.Option',[AcronymName]), 'Option:',AListDetail,nil,True,LOffset);
      LOffset     := LBckOffSet;  
      LOptionKind := ParserUint8Value(aPacketData,aStartLevel+3,LHeaderLen,Format('%s.Option.Kind',[AcronymName]), 'Kind:',AListDetail,TCPKindToString,False,LOffset);
      LOptionStr  := TCPKindToString(LOptionKind);
      if not aAdditionalInfo.Info.Contains('Options:') then
        aAdditionalInfo.Info := Format( '%s Options: %s',[aAdditionalInfo.Info,LOptionStr]).Trim
      else if not aAdditionalInfo.Info.Contains('Options:') then
        aAdditionalInfo.Info := Format('%s,%s',[aAdditionalInfo.Info,LOptionStr]);

      if LOptionKind > TCP_OPTION_NOP then
      begin
        LUint8Value := ParserUint8Value(aPacketData,aStartLevel+3,LHeaderLen,Format('%s.Option.Len',[AcronymName]), 'Length:',AListDetail,SizeaUint8ToStr,False,LOffset);
        Dec(LUint8Value,2);

        if LUint8Value > 0 then
        begin
          case LOptionKind of
          
            TCP_OPTION_MSS       : 
              begin
                ParserUint16Value(aPacketData,aStartLevel+3,LHeaderLen,Format('%s.Option.MSS.value',[AcronymName]), 'MSS Value:',AListDetail,nil,True,LOffset);
                Dec(LUint8Value,2);
                if LUint8Value > 0 then
                  ParserGenericBytesValue(aPacketData,aStartLevel+3,LHeaderLen,LUint8Value,Format('%s.Option.MSS.Unknown',[AcronymName]), 'Unknown:',AListDetail,nil,True,LOffset);   
                LUint8Value := 0;                             
              end;
            
            TCP_OPTION_WSCALE    :
              begin
                ParserUint8Value(aPacketData,aStartLevel+3,LHeaderLen,Format('%s.Option.WScale.ShiftCount',[AcronymName]), 'Shift count:',AListDetail,nil,True,LOffset);
                Dec(LUint8Value,1);
                if LUint8Value > 0 then
                  ParserGenericBytesValue(aPacketData,aStartLevel+3,LHeaderLen,LUint8Value,Format('%s.Option.WScale.Unknown',[AcronymName]), 'Unknown:',AListDetail,nil,True,LOffset);  
                LUint8Value := 0;                              
              end;           

            TCP_OPTION_SACKOK    :;//nothing;  
            
            TCP_OPTION_SACK      :
              begin 
                ParserUint32Value(aPacketData,aStartLevel+3,LHeaderLen,Format('%s.Option.Sack.LeftEdge',[AcronymName]), 'Left edge:',AListDetail,nil,True,LOffset);  
                Dec(LUint8Value,4);
                ParserUint32Value(aPacketData,aStartLevel+3,LHeaderLen,Format('%s.Option.Sack.RightEdge',[AcronymName]), 'Right edge:',AListDetail,nil,True,LOffset);  
                Dec(LUint8Value,4);
                if LUint8Value > 0 then
                  ParserGenericBytesValue(aPacketData,aStartLevel+3,LHeaderLen,LUint8Value,Format('%s.Option.Sack.Unknown',[AcronymName]), 'Unknown:',AListDetail,nil,True,LOffset); 
                LUint8Value := 0;
                
              end;
              
            TCP_OPTION_ECHO      : DoLog('TWPcapProtocolBaseTCP.HeaderToString','TCP_OPTION_ECHO not implemented',TWLLWarning) {TODO};  
            TCP_OPTION_ECHOREPLY : DoLog('TWPcapProtocolBaseTCP.HeaderToString','TCP_OPTION_ECHOREPLY not implemented',TWLLWarning) {TODO};  
            
            TCP_OPTION_TIMESTAMP :
              begin
                LTCPTimeStamp := ParserUint32Value(aPacketData,aStartLevel+3,LHeaderLen,Format('%s.Option.TimeStamp.Value',[AcronymName]), 'TimeStamp value:',AListDetail,nil,True,LOffset);  
                Dec(LUint8Value,4);
                ParserUint32Value(aPacketData,aStartLevel+3,LHeaderLen,Format('%s.Option.TimeStamp.EchoReplay',[AcronymName]), 'TimeStamp echo replay:',AListDetail,nil,True,LOffset);                
                Dec(LUint8Value,4);
                if LUint8Value > 0 then
                  ParserGenericBytesValue(aPacketData,aStartLevel+3,LHeaderLen,LUint8Value,Format('%s.Option.TimeStamp.Unknown',[AcronymName]), 'Unknown:',AListDetail,nil,True,LOffset); 
                LUint8Value := 0;
              end;
          end;

          if LUint8Value > 0 then
            Inc(LOffset,LUint8Value-2);
        end;
      end;               
    end;
  end;

  if IsFilterMode then  
  begin
    aAdditionalInfo.TCPTimeStamp := LTCPTimeStamp;
    TWpcapIPHeader.InternalIP(aPacketData,aPacketSize,nil,@LInternalIP,False,False);
    UpdateFlowInfo(LInternalIP.Src,LInternalIP.Dst,LSrcPort,LDstPort,LPTCPHdr.Flags,LSeqNum,LAckNum,aAdditionalInfo);
    aAdditionalInfo.Info := Format( 'Seq: [%u] Ack [%u] %s',[aAdditionalInfo.SequenceNumber,aAdditionalInfo.AcknowledgmentNumber,aAdditionalInfo.Info]);
  end;

  if aAdditionalInfo.isRetrasmission then
    AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Retransmission',[AcronymName]), 'Retransmission','True',nil,0));      
  
  
  Result := True;       
end;

class function TWPcapProtocolBaseTCP.GetFlowTimeOut: Byte;
begin
  Result := 2;
end;

end.
