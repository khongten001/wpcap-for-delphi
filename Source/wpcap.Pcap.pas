unit wpcap.Pcap;

interface

uses
  wpcap.protocol, wpcap.Wrapper, wpcap.Types, wpcap.StrUtils, wpcap.Conts,WinApi.Windows,
  wpcap.IOUtils, System.SysUtils, Winsock, DateUtils,System.Generics.Collections,wpcap.Protocol.UDP;

type

  TPacketToDump = record 
    tv_sec    : LongInt;
    PacketLen : Integer;
    packet    : pbyte;
  end;
  PTPacketToDump = ^TPacketToDump;

  ///<summary>
  /// Type definition for a callback to be called when an offline packet is processed.
  ///</summary>
  ///<param name="aPktData">
  /// A pointer to the packet data.
  ///</param>
  ///<param name="aPktLen">
  /// The length of the packet data.
  ///</param>
  ///<param name="aPktDate">
  /// The date and time when the packet was captured.
  ///</param>
  ///<param name="aEthType">
  /// The Ethernet type of the packet.
  ///</param>
  ///<param name="atEthAcronym">
  /// The acronym of the Ethernet type.
  ///</param>
  ///<param name="aMacSrc">
  /// The MAC source address of the packet.
  ///</param>
  ///<param name="aMacDst">
  /// The MAC destination address of the packet.
  ///</param>
  ///<param name="LaPProto">
  /// The Layer 3 protocol of the packet.
  ///</param>
  ///<param name="aIPProtoMapping">
  /// The mapping of the Layer 3 protocol to a string representation.
  ///</param>
  ///<param name="aIpSrc">
  /// The source IP address of the packet.
  ///</param>
  ///<param name="aIpDst">
  /// The destination IP address of the packet.
  ///</param>
  ///<param name="aPortSrc">
  /// The source port of the packet.
  ///</param>
  ///<param name="aPortDst">
  /// The destination port of the packet.
  ///</param>
  ///<remarks>
  /// This type definition is used for a callback procedure that is called by the packet capture module when a packet is processed. 
  //  The callback procedure is responsible for processing the packet data in a way that is appropriate for the application. The packet information, such as the date and time, 
  //  Ethernet type, MAC addresses, Layer 3 protocol, IP addresses, and port numbers, is passed to the callback procedure as parameters.
  ///</remarks>

  TPCAPCallBackPacket        = procedure(  const aPktData:PByte;aPktLen:LongWord;aPktDate:TDateTime;//Packet info
                                                  aEthType:Word;const atEthAcronym,aMacSrc,aMacDst:String; // Eth info
                                                  LaPProto:Word;const aIPProtoMapping,aIpSrc,aIpDst:String;aPortSrc,aPortDst:Word;aIdProtoDetected:byte) of object;  //Ip info

  ///<summary>
  /// Type definition for a callback procedure to be called when an error occurs during packet processing.
  ///</summary>
  ///<param name="aFileName">
  /// The name of the file being processed when the error occurred.
  ///</param>
  ///<param name="aError">
  /// The error message.
  ///</param>
  ///<remarks>
  /// This type definition is used for a callback procedure that is called by the packet capture module when an error occurs during packet processing. 
  //  The callback procedure is responsible for handling the error in a way that is appropriate for the application. 
  //  The name of the file being processed and the error message are passed to the callback procedure as parameters.
  ///</remarks>                                                  
  TPCAPCallBackError         = procedure(const aFileName,aError:String) of object;

  ///<summary>
  /// Type definition for a callback procedure to be called to report progress during packet processing.
  ///</summary>
  ///<param name="aTotalSize">
  /// The total size of the file being processed.
  ///</param>
  ///<param name="aCurrentSize">
  /// The number of bytes processed so far.
  ///</param>
  ///<remarks>
  /// This type definition is used for a callback procedure that is called by the packet capture module to report progress during packet processing. 
  /// The callback procedure is responsible for displaying progress information to the user, such as a progress bar or a status message. 
  /// The total size of the file being processed and the number of bytes processed so far are passed to the callback procedure as parameters.
  ///</remarks>  
  TPCAPCallBackProgress      = procedure(aTotalSize,aCurrentSize:Int64) of object;
  
  ///<summary>
  /// Type definition for a callback procedure to be called when packet processing is complete.
  ///</summary>
  ///<param name="aFileName">
  /// The name of the file that was processed.
  ///</param>
  ///<remarks>
  /// This type definition is used for a callback procedure that is called by the packet capture module when packet processing is complete. 
  /// The callback procedure is responsible for any post-processing that may be required, such as closing files or displaying a message to the user. 
  /// The name of the file that was processed is passed to the callback procedure as a parameter.
  ///</remarks>  
  TPCAPCallBackEnd           = procedure(const aFileName:String) of object;

  
  TPCAPUtils = class
  strict private
    class var FPCAPCallBackPacket      : TPCAPCallBackPacket;
    class var FPCAPCallBackProgressRT  : TPCAPCallBackProgress;
    class var FAbort                   : Boolean;    
    class var FHandleRT                : THandle;        
    class var FPCapRT                  : Ppcap_t;            
  private
    class procedure PacketHandlerRealtime(user: PAnsiChar; aHeader: PTpcap_pkthdr;aPacketData: PByte); cdecl;
    class procedure AnalyzePacketForCallBack(const aPacketData: Pbyte;aHeader:PTpcap_pkthdr); static;
    class function CheckWPcapFilter(aHandlePcap: Ppcap_t; const aFileName,
      aFilter: string; aPCAPCallBackError: TPCAPCallBackError):Boolean; static;
  public
    ///<summary>
    /// Analyzes an packet capture file using a specified set of callbacks.
    ///</summary>
    ///<param name="aFileName">
    /// The name of the file to be analyzed.
    ///<param name="afilter">
    /// Optional filter in string format on PCAP file 
    ///</param>
    ///</param>
    ///<param name="aPCAPCallBackPacket">
    /// A callback procedure to be called for each packet in the capture file.
    ///</param>
    ///<param name="aPCAPCallBackError">
    /// A callback procedure to be called in case of errors during packet processing.
    ///</param>
    ///<param name="aPCAPCallBackEnd">
    /// A callback procedure to be called when packet processing is complete.
    ///</param>
    ///<param name="aPCAPCallBackProgress">
    /// A callback procedure to be called to report progress during packet processing.
    ///</param>
    ///<remarks>
    /// This procedure analyzes an packet capture file using a specified set of callbacks. The specified callbacks are responsible for processing packets, 
    /// handling errors, and reporting progress to the user. 
    /// The procedure reads the capture file packet by packet, calling the appropriate callback procedure for each packet. 
    /// The progress callback is optional and can be used to report progress to the user during long-running capture file analysis.
    ///</remarks>
    class procedure AnalyzePCAPOffline( const aFilename, aFilter: String;
                                        aPCAPCallBackPacket  : TPCAPCallBackPacket;
                                        aPCAPCallBackError   : TPCAPCallBackError;
                                        aPCAPCallBackEnd     : TPCAPCallBackEnd;
                                        aPCAPCallBackProgress: TPCAPCallBackProgress= nil); static;


    /// <summary>
    ///   Starts recording a PCAP file with the given filename and packet filter.
    /// </summary>
    /// <param name="aFilename">
    ///   The name of the file to record to.
    /// </param>
    /// <param name="aFilter">
    ///   The packet filter to apply to the captured packets, or an empty string to capture all packets.
    /// </param>
    /// <param name="aInterfaceName">
    ///   The name of interface where start recording.
    /// </param>
    /// <param name="aPCAPCallBackPacket">
    ///  A callback procedure to be called for each packet in the capture file.
    /// </param>
    /// <param name="aPCAPCallBackError">
    ///  A callback procedure to be called in case of errors during packet processing.
    /// </param>
    /// <param name="aPCAPCallBackProgress">
    ///  A callback procedure to be called to report progress during packet processing.
    /// </param>
    class procedure AnalyzePCAPRealtime(  const aFilename, aFilter,aInterfaceName: string;
                                    aPCAPCallBackPacket  : TPCAPCallBackPacket;
                                    aPCAPCallBackError   : TPCAPCallBackError;
                                    aPCAPCallBackProgress: TPCAPCallBackProgress = nil);static;                     

    class procedure StopAnalyze;static;
    ///  <summary>
    ///    Saves a list of packets to a pcap file.
    ///  </summary>
    ///  <param name="aPacketList">
    ///    The list of packets to save.
    ///  </param>
    ///  <param name="aFilename">
    ///    The name of the pcap file to save to.
    ///  </param>
    class procedure SavePacketListToPcapFile(aPacketList: TList<PTPacketToDump>; aFilename: String);static;
  end;
  
implementation

class procedure TPCAPUtils.AnalyzePacketForCallBack(const aPacketData : Pbyte;aHeader:PTpcap_pkthdr);
var LIPHdr           : PETHHdr;
    LEthType         : Word;
    LIPv6Hdr         : PIPv6Header;
    LLenAnalyze      : Int64;
    LTolSizePcap     : Int64;
    LIPProtoMapping  : String;
    LIPProto         : Word;
    LIpSrc           : String;
    LIpDst           : String;
    LPortSrc         : Word;
    LPortDst         : Word;    
    LPUDPHdr         : PUDPHdr;
    LIdProtoDetected : Byte;
begin
  LIPProtoMapping := String.Empty;
  LIPProto        := 0;
  LIpSrc          := String.Empty;
  LIpDst          := String.Empty;
  LPortSrc        := 0;
  LPortDst        := 0;            
  LIPHdr          := PETHHdr(aPacketData);
  LEthType        := ntohs(LIPHdr.EtherType);
                                    
  case LEthType of
    ETH_P_IP :
      begin
        LIPProto        := PIPHeader(aPacketData + ETH_HEADER_LEN).Protocol; 
        LIPProtoMapping := GetIPv4ProtocolName(LIPProto);
        LIpSrc          := intToIPV4(PIPHeader(aPacketData + ETH_HEADER_LEN).SrcIP.Addr );
        LIpDst          := intToIPV4(PIPHeader(aPacketData + ETH_HEADER_LEN).DestIP.Addr );

        //TODO other protocol
        AnalyzeUDPProtocol(aPacketData,aHeader.len,LIPProtoMapping,LIdProtoDetected);
      end;
    ETH_P_IPV6 : 
      begin
        {IPv6}                       
        LIPv6Hdr         := PIPv6Header(aPacketData + ETH_HEADER_LEN);
        LIPProto         := PIPHeader(aPacketData + ETH_HEADER_LEN).Protocol;                   
        LIPProtoMapping  := GetIPv6ProtocolName(LIPProto);                    
        LIpSrc           := IPv6AddressToString(LIPv6Hdr.SourceAddress);
        LIpDst           := IPv6AddressToString(LIPv6Hdr.DestinationAddress); 
      end;
  end;  

  if GetHeaderUDP(aPacketData,aHeader.len,LPUDPHdr) then
  begin
    LPortSrc := ntohs(LPUDPHdr.SrcPort);
    LPortDst := ntohs(LPUDPHdr.DstPort);
  end;
  
  
  FPCAPCallBackPacket(PByte(aPacketData),aHeader.len,UnixToDateTime(aHeader.ts.tv_sec,false),// Packet info
                             LEthType,GetEthAcronymName(LEthType),MACAddrToStr(LIPHdr.SrcAddr),MACAddrToStr(LIPHdr.DestAddr), //Eth info
                             LIPProto,LIPProtoMapping,LIpSrc,LIpDst,LPortSrc,LPortDst,LIdProtoDetected ); // IP info 

end;

class procedure TPCAPUtils.PacketHandlerRealtime(user: PAnsiChar; aHeader: PTpcap_pkthdr; aPacketData: PByte); cdecl;

begin
  if Assigned(FPCAPCallBackProgressRT) then
    FPCAPCallBackProgressRT(-1,aHeader^.len);

  AnalyzePacketForCalLBack(aPacketData,aHeader);
  
  if FAbort then
  begin
    if WaitForSingleObject(FHandleRT, 0) = WAIT_OBJECT_0 then
      pcap_breakloop(FPcapRT);                             
  end;
  
end;

class procedure TPCAPUtils.AnalyzePCAPRealtime(  const aFilename, aFilter,aInterfaceName: string;
                                aPCAPCallBackPacket  : TPCAPCallBackPacket;
                                aPCAPCallBackError   : TPCAPCallBackError;
                                aPCAPCallBackProgress: TPCAPCallBackProgress = nil
                             );
CONST TIME_OUT_READ = 1000;                             
var Lerrbuf      : array[0..PCAP_ERRBUF_SIZE-1] of AnsiChar;
    LPcapDumper  : ppcap_dumper_t;
begin
  FAbort := False;
  if not Assigned(aPCAPCallBackError) then
    raise Exception.Create('Callback event for error not assigned');

  if aFilename.Trim.IsEmpty then
  begin
    aPCAPCallBackError(aFileName,'filename is empty');
    Exit;    
  end;

  if not FileExists(aFilename) then
  begin
    aPCAPCallBackError(aFileName,'filename not exists');
    Exit;    
  end;
        
  if not Assigned(aPCAPCallBackPacket) then
  begin
    aPCAPCallBackError(aFileName,'Callback event for packet not assigned');
    Exit;
  end;

  if aInterfaceName.Trim.IsEmpty then
  begin
    aPCAPCallBackError(aFileName,'Interface name is empty');
    Exit;
  end;  

  FPCAPCallBackPacket      := aPCAPCallBackPacket;
  FPCAPCallBackProgressRT  := aPCAPCallBackProgress;
  
  // Open the network adapter for capturing
  FPcapRT := pcap_open_live(PAnsiChar(AnsiString(aInterfaceName)), MAX_PACKET_SIZE, 1, TIME_OUT_READ, Lerrbuf); //TODO MAGIC NUMBER
  if not Assigned(FPcapRT) then
  begin
    aPCAPCallBackError(aFileName,Format('Error opening network adapter: %s', [Lerrbuf]));
    Exit;
  end;
  Try          
    // Open the PCAP file for writing
    LPcapDumper := pcap_dump_open(FPcapRT, PAnsiChar(AnsiString(aFilename)));

    if LPcapDumper = nil then
    begin
      aPCAPCallBackError(aFileName,Format('Failed to open PCAP dump %s',[string(pcap_geterr(FPcapRT))]));
      Exit;
    end;  
    
    Try  
      FHandleRT := CreateEvent(nil, True, False, nil);
      Try
        // Set the packet filter if one was provided
        if not CheckWPcapFilter(FPcapRT,aFilename,aFilter,aPCAPCallBackError) then exit;

        // Start capturing packets and writing them to the output file
        pcap_loop(FPcapRT, -1, @PacketHandlerRealtime, nil);

      finally
        // Close the event handle.
        CloseHandle(FHandleRT);
      end;      
    Finally
       // Close the output file and the network adapter
      pcap_dump_close(LPcapDumper);
    End;        
  Finally
    pcap_close(FPcapRT);
  End;
end;

Class function TPCAPUtils.CheckWPcapFilter(aHandlePcap : Ppcap_t;const aFileName,aFilter: string;aPCAPCallBackError:TPCAPCallBackError) : Boolean;
var LFilterCode : BPF_program;  
    LNetMask    : bpf_u_int32;
begin
  Result := False;
  {Filter}
  if Not aFilter.Trim.IsEmpty then
  begin
    if pcap_compile(aHandlePcap, @LFilterCode, PAnsiChar(AnsiString(aFilter)), 1, LNetMask) <> 0 then
    begin
      aPCAPCallBackError(aFileName,string(pcap_geterr(aHandlePcap)));            
      Exit;
    end;
      
    if pcap_setfilter(aHandlePcap,@LFilterCode) <>0 then
    begin
      aPCAPCallBackError(aFileName,string(pcap_geterr(aHandlePcap)));
      Exit;
    end;
  end;
  Result := True;
end;

class procedure TPCAPUtils.SavePacketListToPcapFile(aPacketList: TList<PTPacketToDump>; aFilename: String);
var LPcap        : Ppcap_t;
    LPcapDumper  : ppcap_dumper_t ;
    LPacket      : PByte;
    LPacketHeader: Tpcap_pkthdr;
    I            : Integer;
begin
  LPcap := pcap_open_dead(DLT_EN10MB, MAX_PACKET_SIZE);

  if LPcap = nil then
    raise Exception.Create('Failed to open PCAP');

  Try
    // Open the PCAP file for writing
    LPcapDumper := pcap_dump_open(LPcap, PAnsiChar(AnsiString(aFilename)));

    if LPcapDumper = nil then
      raise Exception.CreateFmt('Failed to open PCAP dump %s',[string(pcap_geterr(LPcap))]);

    try
      // Write each packet in the list to the PCAP file
      for I := 0 to aPacketList.Count -1 do
      begin
        LPacket                  := aPacketList[I].Packet;
        // Get the packet header
        LPacketHeader.ts.tv_sec  := aPacketList[I].tv_sec;
        LPacketHeader.ts.tv_usec := aPacketList[I].tv_sec;
        LPacketHeader.caplen     := aPacketList[I].PacketLen;
        LPacketHeader.len        := aPacketList[I].PacketLen;

        // Write the packet header and data to the PCAP file
        pcap_dump(LPcapDumper, @LPacketHeader, LPacket);
      end;
    finally
      // Close the PCAP file
      pcap_dump_close(LPcapDumper);
    end;
  Finally
    pcap_close(LPcap);
  End;
end;

class procedure TPCAPUtils.AnalyzePCAPOffline( const aFilename,aFilter:String;
                              aPCAPCallBackPacket  : TPCAPCallBackPacket;
                              aPCAPCallBackError   : TPCAPCallBackError;
                              aPCAPCallBackEnd     : TPCAPCallBackEnd;
                              aPCAPCallBackProgress: TPCAPCallBackProgress = nil
                            );                            
var LHandlePcap      : Ppcap_t;
    LErrbuf          : array[0..PCAP_ERRBUF_SIZE-1] of AnsiChar;
    LHeader          : PTpcap_pkthdr;
    LPktData         : PByte;
    LResultPcapNext  : Integer;
    LLenAnalyze      : Int64;
    LTolSizePcap     : Int64;

    Procedure DoPcapProgress(aTotalSize,aCurrentSize:Int64);
    begin
      if Assigned(aPCAPCallBackProgress) then
        aPCAPCallBackProgress(aTotalSize,aCurrentSize);
    end;

begin
  FAbort := False;
  if not Assigned(aPCAPCallBackError) then
    raise Exception.Create('Callback event for error not assigned');

  if aFilename.Trim.IsEmpty then
  begin
    aPCAPCallBackError(aFileName,'filename is empty');
    Exit;    
  end;

  if not FileExists(aFilename) then
  begin
    aPCAPCallBackError(aFileName,'filename not exists');
    Exit;    
  end;
        
  if not Assigned(aPCAPCallBackPacket) then
  begin
    aPCAPCallBackError(aFileName,'Callback event for packet not assigned');
    Exit;
  end;

  if not Assigned(aPCAPCallBackEnd) then
  begin
    aPCAPCallBackError(aFileName,'Callback event for end analyze not assigned');
    Exit;
  end;  

  LTolSizePcap         := FileGetSize(aFileName);  
  FPCAPCallBackPacket  := aPCAPCallBackPacket;              
  LLenAnalyze          := 0;
  DoPcapProgress(LTolSizePcap,0);
  
  LHandlePcap := pcap_open_offline(PAnsiChar(AnsiString(aFileName)), LErrbuf);
  
  if LHandlePcap = nil then
  begin
    aPCAPCallBackError(aFileName,string(LErrbuf));
    Exit;
  end;
  
  try
    if not CheckWPcapFilter(LHandlePcap,aFilename,aFilter,aPCAPCallBackError) then exit;  
    // Loop over packets in PCAP file
    while True do
    begin
      // Read the next packet
      LResultPcapNext := pcap_next_ex(LHandlePcap, LHeader, @LPktData);
      case LResultPcapNext of
        1:  // packet read correctly           
          begin      
            AnalyzePacketForCalLBack(LPktData,LHeader);
            Inc(LLenAnalyze,LHeader^.Len);
            DoPcapProgress(LTolSizePcap,LLenAnalyze);

            if FAbort then break;
            
          end;
        0: 
          begin
            // No packets available at the moment
            Continue;
          end;
        -1: 
          begin
            // Error reading packet
            aPCAPCallBackError(aFileName,string(pcap_geterr(LHandlePcap)));            
            Break;
          end;
        -2:
          begin
            // No packets available, the pcap file instance has been closed
            DoPcapProgress(LTolSizePcap,LTolSizePcap);

            aPCAPCallBackEnd(aFileName);
            Break;
          end;
      end;
    end;
  finally
    // Close PCAP file
    pcap_close(LHandlePcap);
  end;
end;


class procedure TPCAPUtils.StopAnalyze;
begin
 FAbort := true;
end;

end.
