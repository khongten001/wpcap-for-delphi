unit wpcap.Offline;

interface

uses wpcap.protocol,wpcap.Wrapper,wpcap.Types,wpcap.StrUtils,wpcap.Conts,wpcap.IOUtils,System.SysUtils,Winsock,DateUtils;

type

  ///<summary>
  /// Type definition for a callback procedure to be called when an offline packet is processed.
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
  /// This type definition is used for a callback procedure that is called by the offline packet capture module when a packet is processed. 
  //  The callback procedure is responsible for processing the packet data in a way that is appropriate for the application. The packet information, such as the date and time, 
  //  Ethernet type, MAC addresses, Layer 3 protocol, IP addresses, and port numbers, is passed to the callback procedure as parameters.
  ///</remarks>

  TPCAPOfflineCallBackPacket        = procedure(  const aPktData:PByte;aPktLen:LongWord;aPktDate:TDateTime;//Packet info
                                                  aEthType:Word;const atEthAcronym,aMacSrc,aMacDst:String; // Eth info
                                                  LaPProto:Word;const aIPProtoMapping,aIpSrc,aIpDst:String;aPortSrc,aPortDst:Word  ) of object;  //Ip info

  ///<summary>
  /// Type definition for a callback procedure to be called when an error occurs during offline packet processing.
  ///</summary>
  ///<param name="aFileName">
  /// The name of the file being processed when the error occurred.
  ///</param>
  ///<param name="aError">
  /// The error message.
  ///</param>
  ///<remarks>
  /// This type definition is used for a callback procedure that is called by the offline packet capture module when an error occurs during packet processing. 
  //  The callback procedure is responsible for handling the error in a way that is appropriate for the application. 
  //  The name of the file being processed and the error message are passed to the callback procedure as parameters.
  ///</remarks>                                                  
  TPCAPOfflineCallBackError         = procedure(const aFileName,aError:String) of object;

  ///<summary>
  /// Type definition for a callback procedure to be called to report progress during offline packet processing.
  ///</summary>
  ///<param name="aTotalSize">
  /// The total size of the file being processed.
  ///</param>
  ///<param name="aCurrentSize">
  /// The number of bytes processed so far.
  ///</param>
  ///<remarks>
  /// This type definition is used for a callback procedure that is called by the offline packet capture module to report progress during packet processing. 
  /// The callback procedure is responsible for displaying progress information to the user, such as a progress bar or a status message. 
  /// The total size of the file being processed and the number of bytes processed so far are passed to the callback procedure as parameters.
  ///</remarks>  
  TPCAPOfflineCallBackProgress      = procedure(aTotalSize,aCurrentSize:Int64) of object;
  
  ///<summary>
  /// Type definition for a callback procedure to be called when offline packet processing is complete.
  ///</summary>
  ///<param name="aFileName">
  /// The name of the file that was processed.
  ///</param>
  ///<remarks>
  /// This type definition is used for a callback procedure that is called by the offline packet capture module when packet processing is complete. 
  /// The callback procedure is responsible for any post-processing that may be required, such as closing files or displaying a message to the user. 
  /// The name of the file that was processed is passed to the callback procedure as a parameter.
  ///</remarks>  
  TPCAPOfflineCallBackEnd           = procedure(const aFileName:String) of object;

  ///<summary>
  /// Analyzes an offline packet capture file using a specified set of callbacks.
  ///</summary>
  ///<param name="aFileName">
  /// The name of the file to be analyzed.
  ///<param name="afilter">
  /// Optional filter in string format on PCAP file 
  ///</param>
  ///</param>
  ///<param name="aPCAPOfflineCallBackPacket">
  /// A callback procedure to be called for each packet in the capture file.
  ///</param>
  ///<param name="aPCAPOfflineCallBackError">
  /// A callback procedure to be called in case of errors during packet processing.
  ///</param>
  ///<param name="aPCAPOfflineCallBackEnd">
  /// A callback procedure to be called when packet processing is complete.
  ///</param>
  ///<param name="aPCAPOfflineCallBackProgress">
  /// A callback procedure to be called to report progress during packet processing.
  ///</param>
  ///<remarks>
  /// This procedure analyzes an offline packet capture file using a specified set of callbacks. The specified callbacks are responsible for processing packets, 
  /// handling errors, and reporting progress to the user. 
  /// The procedure reads the capture file packet by packet, calling the appropriate callback procedure for each packet. 
  /// The progress callback is optional and can be used to report progress to the user during long-running capture file analysis.
  ///</remarks>
  procedure AnalyzePCAPOffline( const aFilename,afilter:String;
                                aPCAPOfflineCallBackPacket  : TPCAPOfflineCallBackPacket;
                                aPCAPOfflineCallBackError   : TPCAPOfflineCallBackError;
                                aPCAPOfflineCallBackEnd     : TPCAPOfflineCallBackEnd;
                                aPCAPOfflineCallBackProgress: TPCAPOfflineCallBackProgress = nil
                            );
  
implementation



procedure AnalyzePCAPOffline( const aFilename,aFilter:String;
                              aPCAPOfflineCallBackPacket  : TPCAPOfflineCallBackPacket;
                              aPCAPOfflineCallBackError   : TPCAPOfflineCallBackError;
                              aPCAPOfflineCallBackEnd     : TPCAPOfflineCallBackEnd;
                              aPCAPOfflineCallBackProgress: TPCAPOfflineCallBackProgress = nil
                            );
                            
var LHandlePcap      : Ppcap_t;
    LErrbuf          : array[0..PCAP_ERRBUF_SIZE-1] of AnsiChar;
    LHeader          : PTpcap_pkthdr;
    LPktData         : PByte;
    LResultPcapNext  : Integer;
    LIPHdr           : PETHHdr;
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
    LFilterCode      : PBPF_program;  
    LNetMask         : bpf_u_int32;

    Procedure DoPcapOfflineProgress(aTotalSize,aCurrentSize:Int64);
    begin
      if Assigned(aPCAPOfflineCallBackProgress) then
        aPCAPOfflineCallBackProgress(aTotalSize,aCurrentSize);
    end;

begin

  if not Assigned(aPCAPOfflineCallBackError) then
  begin
    raise Exception.Create('Callback event for error not assigned');
  end;  

  if aFilename.Trim.IsEmpty then
  begin
    aPCAPOfflineCallBackError(aFileName,'filename is empty');
    Exit;    
  end;

  if not FileExists(aFilename) then
  begin
    aPCAPOfflineCallBackError(aFileName,'filename not exists');
    Exit;    
  end;
        
  if not Assigned(aPCAPOfflineCallBackPacket) then
  begin
    aPCAPOfflineCallBackError(aFileName,'Callback event for packet not assigned');
    Exit;
  end;

  if not Assigned(aPCAPOfflineCallBackEnd) then
  begin
    aPCAPOfflineCallBackError(aFileName,'Callback event for end analyze not assigned');
    Exit;
  end;  

  LTolSizePcap := FileGetSize(aFileName);  
  LLenAnalyze  := 0;
  DoPcapOfflineProgress(LTolSizePcap,0);
  
  LHandlePcap := pcap_open_offline(PAnsiChar(AnsiString(aFileName)), LErrbuf);
  
  if LHandlePcap = nil then
  begin
    aPCAPOfflineCallBackError(aFileName,string(LErrbuf));
    Exit;
  end;

  try
    if Not afilter.Trim.IsEmpty then
    begin
      if pcap_compile(LHandlePcap, LFilterCode, PAnsiChar(AnsiString(afilter)), 1, LNetMask) <> 0 then
      begin
        aPCAPOfflineCallBackError(aFileName,string(pcap_geterr(LHandlePcap)));            
        Exit;
      end;
      
      if pcap_setfilter(LHandlePcap,LFilterCode) <>9 then
      begin
        aPCAPOfflineCallBackError(aFileName,string(pcap_geterr(LHandlePcap)));            
        Exit;
      end;
    end;
    
    // Loop over packets in PCAP file
    while True do
    begin
      // Read the next packet
      LResultPcapNext := pcap_next_ex(LHandlePcap, LHeader, @LPktData);
      case LResultPcapNext of
        1:  // packet read correctly           
          begin           
            LIPProtoMapping := String.Empty;
            LIPProto        := 0;
            LIpSrc          := String.Empty;
            LIpDst          := String.Empty;
            LPortSrc        := 0;
            LPortDst        := 0;            
            Inc(LLenAnalyze,LHeader.len);
            DoPcapOfflineProgress(LTolSizePcap,LLenAnalyze);

            LIPHdr   := PETHHdr(LPktData);
            LEthType := ntohs(LIPHdr.EtherType);
                                    
            {Common packet info}
            case LEthType of
              ETH_P_IP :
                begin
                  LIPProto        := PIPHeader(LPktData + ETH_HEADER_LEN).Protocol; 
                  LIPProtoMapping := GetIPv4ProtocolName(LIPProto);
                  LIpSrc          := intToIPV4(PIPHeader(LPktData + ETH_HEADER_LEN).SrcIP.Addr );
                  LIpDst          := intToIPV4(PIPHeader(LPktData + ETH_HEADER_LEN).DestIP.Addr );

                  //TODO other protocol
                  case PIPHeader(LPktData + ETH_HEADER_LEN).Protocol of
                    IPPROTO_UDP:
                      begin 
                        if IsL2TPPacketData(LPktData,LHeader.len) then
                          LIPProtoMapping := 'L2PT';
                      end;

                      
                  end;                  
                end;
              ETH_P_IPV6 : 
                begin
                  {IPv6}                       
                  LIPv6Hdr         := PIPv6Header(LPktData + ETH_HEADER_LEN);
                  LIPProto         := PIPHeader(LPktData + ETH_HEADER_LEN).Protocol;                   
                  LIPProtoMapping  := GetIPv6ProtocolName(LIPProto);                    
                  LIpSrc           := IPv6AddressToString(LIPv6Hdr.SourceAddress);
                  LIpDst           := IPv6AddressToString(LIPv6Hdr.DestinationAddress); 
                end;
            end;

            aPCAPOfflineCallBackPacket(LPktData,LHeader.len,UnixToDateTime(LHeader.ts.tv_sec,false),// Packet info
                                       LEthType,GetEthAcronymName(LEthType),MACAddrToStr(LIPHdr.SrcAddr),MACAddrToStr(LIPHdr.DestAddr), //Eth info
                                       LIPProto,LIPProtoMapping,LIpSrc,LIpDst,LPortSrc,LPortDst ) // IP info           
          end;
        0: 
          begin
            // No packets available at the moment
            Continue;
          end;
        -1: 
          begin
            // Error reading packet
            aPCAPOfflineCallBackError(aFileName,string(pcap_geterr(LHandlePcap)));            
            Break;
          end;
        -2:
          begin
            // No packets available, the pcap file instance has been closed
            DoPcapOfflineProgress(LTolSizePcap,LTolSizePcap);

            aPCAPOfflineCallBackEnd(aFileName);            
            Break;
          end;
      end;
    end;
  finally
    // Close PCAP file
    pcap_close(LHandlePcap);
  end;
end;

end.
