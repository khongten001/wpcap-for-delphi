unit wpcap.Offline;

interface

uses wpcap.protocol,wpcap.Wrapper,wpcap.Types,wpcap.StrUtils,wpcap.Conts,wpcap.IOUtils,System.SysUtils,Winsock,DateUtils;

type
  TPCAPOfflineCallBackPacket        = procedure(  const aPktData:PByte;aPktLen:LongWord;aPktDate:TDateTime;//Packet info
                                                  aEthType:Word;const atEthAcronym,aMacSrc,aMacDst:String; // Eth info
                                                  LaPProto:Word;const aIPProtoMapping,aIpSrc,aIpDst:String;aPortSrc,aPortDst:Word  ) of object;  //Ip info
                                                  
  TPCAPOfflineCallBackError         = procedure(const aFileName,aError:String) of object;
  TPCAPOfflineCallBackProgress      = procedure(aTotalSize,aCurrentSize:Int64) of object;
  TPCAPOfflineCallBackEnd           = procedure(const aFileName:String) of object;


  procedure AnalyzePCAPOffline( const aFilename:String;
                                aPCAPOfflineCallBackPacket  : TPCAPOfflineCallBackPacket;
                                aPCAPOfflineCallBackError   : TPCAPOfflineCallBackError;
                                aPCAPOfflineCallBackEnd     : TPCAPOfflineCallBackEnd;
                                aPCAPOfflineCallBackProgress: TPCAPOfflineCallBackProgress = nil
                            );
  
implementation



procedure AnalyzePCAPOffline( const aFilename:String;
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
