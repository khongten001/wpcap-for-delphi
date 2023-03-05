unit wpcap.Pcap;

interface

uses
  wpcap.Wrapper, wpcap.Types, wpcap.StrUtils, wpcap.Conts,wpcap.IANA.DbPort,
  WinApi.Windows, wpcap.Packet, wpcap.IOUtils, System.SysUtils,System.DateUtils, 
  Winsock,wpcap.Level.Eth,wpcap.BufferUtils,Forms,System.Math,System.Types ,
  System.Generics.Collections,System.Variants,wpcap.GEOLite2,wpcap.IPUtils;

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
  ///<param name="aInternalPacket">
  /// Internal rappresentazion of packet in TInternalPacket structure
  ///</param>
  ///<remarks>
  /// This type definition is used for a callback procedure that is called by the packet capture module when a packet is processed. 
  //  The callback procedure is responsible for processing the packet data in a way that is appropriate for the application. The packet information, such as the date and time, 
  //  Ethernet type, MAC addresses, Layer 3 protocol, IP addresses, and port numbers, is passed to the callback procedure as parameters.
  ///</remarks>

  TPCAPCallBackPacket        = procedure(const aInternalPacket : PTInternalPacket) of object; 

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
    class var FAbort                   : Boolean; 
    class var FPCapRT                  : Ppcap_t;      
    class var FTimeStopRecording       : TDateTime;      
    class var FIANADictionary          : TDictionary<String,TIANARow>;   
    /// <summary>
    /// This is a class procedure that handles a packet in real time. 
    /// It takes three parameters: a pointer to the user, a pointer to the packet header, and a pointer to the packet data.
    /// </summary>
    /// <param name="user">A pointer to the user.</param>
    /// <param name="aHeader">A pointer to the packet header.</param>
    /// <param name="aPacketData">A pointer to the packet data.</param>
    /// <remarks>
    /// This function uses cdecl calling convention.
    /// </remarks>

  private


    /// <summary>
    /// This is a static class procedure that analyzes a packet. It takes two parameters: a pointer to the packet data and a pointer to the packet header.
    /// </summary>
    /// <param name="aPacketData">A pointer to the packet data.</param>
    /// <param name="aHeader">A pointer to the packet header.</param>
    class procedure AnalyzePacketCallBack(const aPacketData: PByte; aHeader: PTpcap_pkthdr;aGeoLiteDB : TWpcapGEOLITE); static;

    /// <summary>
    /// This is a static class function that checks a wpcap filter. It takes four parameters: a handle to the pcap file, the name of the file, the filter to check, and a callback function to handle errors.
    /// </summary>
    /// <param name="aHandlePcap">A handle to the pcap file.</param>
    /// <param name="aFileName">The name of the pcap file.</param>
    /// <param name="aFilter">The filter to check.</param>
    /// <param name="aPCAPCallBackError">A callback function to handle errors.</param>
    /// <returns>True if the filter is valid; otherwise, False.</returns>
    class function CheckWPcapFilter(aHandlePcap: Ppcap_t; const aFileName, aFilter,aIP: string; aPCAPCallBackError: TPCAPCallBackError): Boolean; static;
    
    /// <summary>
    /// This static class procedure initializes an IANA dictionary.
    /// </summary>
    class procedure InitIANADictionary; static;
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
                                        aGeoLiteDB           : TWpcapGEOLITE;    
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
    /// <param name="aPromisc">
    ///   Use promisc in interface
    /// </param>
    /// <param name="aSevePcapDump">
    ///   save DB and PCAP dump 
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
    /// <param name="aTimeOut">
    ///  Timeout in millisecond for data collection
    /// </param>
    /// <param name="aMaxSizePakcet">
    ///  Max size in byte for capture packet 
    /// </param>
    /// <param name="aTimeRecoStop">
    ///  Time recording stopping 0 disable 
    /// </param>
    procedure AnalyzePCAPRealtime(  const aFilename, aFilter,aInterfaceName,aIP: string;
                                          aPromisc,aSevePcapDump:Boolean;
                                          aPCAPCallBackPacket  : TPCAPCallBackPacket;
                                          aPCAPCallBackError   : TPCAPCallBackError;
                                          aPCAPCallBackProgress: TPCAPCallBackProgress = nil;
                                          aTimeOutMs:Integer=1000;
                                          aMaxSizePakcet:Integer = MAX_PACKET_SIZE;
                                          aTimeRecoStop : TTime = 0); 

    class var FPCAPCallBackProgressRT  : TPCAPCallBackProgress;
    /// <summary>
    /// This is a static class procedure that stops the analysis process.
    /// </summary>
    class procedure StopAnalyze; static;
    
    ///  <summary>
    ///    Saves a list of packets to a pcap file.
    ///  </summary>
    ///  <param name="aPacketList">
    ///    The list of packets to save.
    ///  </param>
    ///  <param name="aFilename">
    ///    The name of the pcap file to save to.
    ///  </param>
    ///
    class procedure SavePacketListToPcapFile(aPacketList: TList<PTPacketToDump>; aFilename: String);static;

    {Property}
    class Property Abort             : Boolean     Read FAbort;
    class Property PCapRT            : Ppcap_t     Read FPCapRT;
    class Property TimeStopRecording : TDateTime   Read FTimeStopRecording;    
  end;
  
  function  PacketHandlerRealtime ( aUser: PAnsiChar;const aHeader: PTpcap_pkthdr;const aPacketData: Pbyte): Integer; cdecl;  
  
implementation

class procedure TPCAPUtils.AnalyzePacketCallBack(const aPacketData : Pbyte;aHeader:PTpcap_pkthdr;aGeoLiteDB : TWpcapGEOLITE);
var LInternalPacket  : PTInternalPacket;  
begin
  if not Assigned(aPacketData) then Exit;
  
  New(LInternalPacket); 
  Try
    LInternalPacket.PacketDate := UnixToDateTime(aHeader.ts.tv_sec,false);    
    TWpcapEthHeader.InternalPacket(aPacketData,aHeader.len,FIANADictionary,LInternalPacket);  

    LInternalPacket.IP.SrcGeoIP.ASNumber        := String.Empty;
    LInternalPacket.IP.SrcGeoIP.ASOrganization  := String.Empty;
    LInternalPacket.IP.SrcGeoIP.Location        := String.Empty;            
    LInternalPacket.IP.SrcGeoIP.Latitude        := 0;
    LInternalPacket.IP.SrcGeoIP.Longitude       := 0;

    LInternalPacket.IP.DestGeoIP.ASNumber       := String.Empty;
    LInternalPacket.IP.DestGeoIP.ASOrganization := String.Empty;
    LInternalPacket.IP.DestGeoIP.Location       := String.Empty;            
    LInternalPacket.IP.DestGeoIP.Latitude       := 0;
    LInternalPacket.IP.DestGeoIP.Longitude      := 0;
    
    if Assigned(aGeoLiteDB) and aGeoLiteDB.Connection.Connected then
    begin
      if ( LInternalPacket.Eth.EtherType = ETH_P_IP ) or
         ( LInternalPacket.Eth.EtherType = ETH_P_IPV6 ) 
      then
      begin
        if IsValidPublicIP(LInternalPacket.IP.Src) then        
          aGeoLiteDB.GetGeoIPByIp(LInternalPacket.IP.Src,@LInternalPacket.IP.SrcGeoIP);
        if IsValidPublicIP(LInternalPacket.IP.Dst) then        
          aGeoLiteDB.GetGeoIPByIp(LInternalPacket.IP.Dst,@LInternalPacket.IP.DestGeoIP);
      end;
    end;
        
    FPCAPCallBackPacket(LInternalPacket);
  Finally
    Dispose(LInternalPacket);
  end;                        
end;

function  PacketHandlerRealtime ( aUser: PAnsiChar;const aHeader: PTpcap_pkthdr;const aPacketData: Pbyte): Integer; 
var PacketBuffer: array[0..MAX_PACKET_SIZE-1] of Byte;
    LPacketLen  : Word;
    aNewHeader  : PTpcap_pkthdr;
begin
  MyProcessMessages;

  if Assigned(aPacketData) then
  begin
    LPacketLen  := wpcapntohs(aHeader^.len);
    if Assigned( TPCAPUtils(aUser).FPCAPCallBackProgressRT) then
      TPCAPUtils(aUser).FPCAPCallBackProgressRT(-1,LPacketLen);
    new(aNewHeader);
    aNewHeader.ts := aHeader.ts;
    aNewHeader.caplen := (aHeader.caplen);
    aNewHeader.len := LPacketLen ;

    Move(aPacketData^, PacketBuffer[0], LPacketLen);
    TPCAPUtils(aUser).AnalyzePacketCallBack(@PacketBuffer[0],aNewHeader,nil);
    dispose(aNewHeader);
  end;
  
  if ( TPCAPUtils(aUser).Abort) or 
      ( ( TPCAPUtils(aUser).TimeStopRecording>0 ) and (Now> TPCAPUtils(aUser).TimeStopRecording) ) 
  then
    pcap_breakloop(TPCAPUtils(aUser).PcapRT);                             

  Result := 0;
end;

procedure TPCAPUtils.AnalyzePCAPRealtime( const aFilename, aFilter,aInterfaceName,aIP: string;
                                                aPromisc,aSevePcapDump:Boolean;
                                                aPCAPCallBackPacket  : TPCAPCallBackPacket;
                                                aPCAPCallBackError   : TPCAPCallBackError;
                                                aPCAPCallBackProgress: TPCAPCallBackProgress = nil;
                                                aTimeOutMs:Integer=1000;
                                                aMaxSizePakcet:Integer = MAX_PACKET_SIZE;
                                                aTimeRecoStop : TTime = 0 
                                             );
var Lerrbuf      : array[0..PCAP_ERRBUF_SIZE-1] of AnsiChar;
    LPcapDumper  : ppcap_dumper_t;
    LLoopResult  : Integer;
    
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

  FTimeStopRecording := 0;
  if aTimeRecoStop > 0 then
  begin
    FTimeStopRecording := now;
    ReplaceTime(FTimeStopRecording,aTimeRecoStop);    
    if CompareTime(aTimeRecoStop,now) <> GreaterThanValue then
      FTimeStopRecording := IncDay(FTimeStopRecording,1)
  end;
  
  FPCAPCallBackPacket      := aPCAPCallBackPacket;
  FPCAPCallBackProgressRT  := aPCAPCallBackProgress;
  
  // Open the network adapter for capturing
  FPcapRT := pcap_open_live(PAnsiChar(AnsiString(aInterfaceName)), aMaxSizePakcet, ifthen(aPromisc,1,0), aTimeOutMs, Lerrbuf);
  if not Assigned(FPcapRT) then
  begin
    aPCAPCallBackError(aFileName,Format('Error opening network adapter: %s', [Lerrbuf]));
    Exit;
  end;
  Try          
    // Open the PCAP file for writing
    if aSevePcapDump then    
    begin
      LPcapDumper := pcap_dump_open(FPcapRT, PAnsiChar(AnsiString(ChangeFileExt(aFilename,'.pcap'))));

      if LPcapDumper = nil then
      begin
        aPCAPCallBackError(aFileName,Format('Failed to open PCAP dump %s',[string(pcap_geterr(FPcapRT))]));
        Exit;
      end;      
    end;

    Try  
      // Set the packet filter if one was provided
      if not CheckWPcapFilter(FPcapRT,aFilename,aFilter,aIP,aPCAPCallBackError) then exit;

      // Start capturing packets and writing them to the output file


      LLoopResult := pcap_loop(FPcapRT, -1, @PacketHandlerRealtime, @self);
      case LLoopResult  of
        0  :; //Cnt end
        -1 : aPCAPCallBackError(aFileName,Format('pcap_loop ended because of an error %s',[string(pcap_geterr(FPcapRT))])); 
        -2 : //Normal
      else
         aPCAPCallBackError(aFileName,Format('pcap_loop ended unknow return code [%d] error %s',[LLoopResult,string(pcap_geterr(FPcapRT))]));   
      end;

      

    Finally
      // Close the output file and the network adapter
      if aSevePcapDump then     
        pcap_dump_close(LPcapDumper);
    End;        
  Finally
    pcap_close(FPcapRT);
  End;
end;

Class function TPCAPUtils.CheckWPcapFilter(aHandlePcap : Ppcap_t;const aFileName,aFilter,aIP: string;aPCAPCallBackError:TPCAPCallBackError) : Boolean;
var LFilterCode : BPF_program;  
begin
  Result := False;
  {Filter}
 // if Not aFilter.Trim.IsEmpty then
  begin
    if pcap_compile(aHandlePcap, @LFilterCode, PAnsiChar(AnsiString(aFilter)), 1, inet_addr(PAnsiChar(AnsiString(aIP)))) <> 0 then
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

class Procedure TPCAPUtils.InitIANADictionary;
var aRow : TIANARow;
begin
  FIANADictionary := TDictionary<String,TIANARow>.Create;
  for aRow in PROTOCOL_IANA_PORTS do
    FIANADictionary.Add(Format('%d_%d',[aRow.PortNumber,aRow.IPPROTP]), aRow);
end;

class procedure TPCAPUtils.AnalyzePCAPOffline( const aFilename,aFilter:String;
                              aGeoLiteDB           : TWpcapGEOLITE;
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
    if not CheckWPcapFilter(LHandlePcap,aFilename,aFilter,String.Empty,aPCAPCallBackError) then exit;  
    // Loop over packets in PCAP file
    Try
      InitIANADictionary;
      while True do
      begin
        // Read the next packet
        LResultPcapNext := pcap_next_ex(LHandlePcap, LHeader, @LPktData);
        case LResultPcapNext of
          1:  // packet read correctly           
            begin      
              AnalyzePacketCallBack(LPktData,LHeader,aGeoLiteDB);
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
      FreeAndNil(FIANADictionary);
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
