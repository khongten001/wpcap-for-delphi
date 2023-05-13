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

unit wpcap.Pcap;

interface

uses
  wpcap.Wrapper, wpcap.Types, wpcap.StrUtils, wpcap.Conts, wpcap.IANA.DbPort,System.Diagnostics,
  System.Threading, WinApi.Windows, wpcap.Packet, wpcap.IOUtils, System.SysUtils,
  System.DateUtils, System.Classes, Winsock, wpcap.Level.Eth, wpcap.BufferUtils,
  Forms, System.Math, System.Types, System.Generics.Collections, System.Variants,
  wpcap.GEOLite2, wpcap.IPUtils,wpcap.Filter,System.SyncObjs;

  ///<summary>
  /// Callback function that handles incoming packets in real-time mode
  ///</summary>
  ///<param name="aUser">Pointer to user-defined data, not used in this function</param>
  ///<param name="aHeader">Pointer to the packet header</param>
  ///<param name="aPacketData">Pointer to the packet data</param>
  ///<returns>Zero on success, a negative value on error</returns>
  function PacketHandlerRealtime(aUser: PAnsiChar; const aHeader: PTpcap_pkthdr; const aPacketData: PByte): Integer; cdecl;
  
  /// <summary>
  /// This is a function that analyzes a packet. It takes two parameters: a pointer to the packet data and a pointer to the packet header.
  /// </summary>
  /// <param name="aPacketData">A pointer to the packet data.</param>
  /// <param name="aHeader">A pointer to the packet header.</param>
  /// <param name="aGeoLiteDB">Link for MaxMind geoIp database.</param>  
  /// <param name="aListLabelByLevel">Internal list for label filter.</param>  
  /// <param name="aLogFunctoin">Function log.</param>
  function AnalyzePacketCallBack(const aPacketData: PByte;aFrameNumber:Integer; aHeader: PTpcap_pkthdr;aGeoLiteDB : TWpcapGEOLITE; aListLabelByLevel : TListLabelByLevel;aLogFunctoin:TWpcapLog;aFlowInfoList:TFlowInfoList;aGetNewFlowIDFnc: TWpcapGetNewFlowID): PTInternalPacket;

type
  ///<summary>
  /// Structure that represents a packet to be dumped to a file
  ///</summary>
  TPacketToDump = record
    tv_sec    : LongInt;
    PacketLen : Integer;
    packet    : PByte;
  end;
  PTPacketToDump = ^TPacketToDump;

  ///<summary>
  /// Thread class for capturing network packets using the PCAP library
  ///</summary>
  TThreadPcap = class(TThread)
  private         
    FAbort                   : Boolean; 
    FOnPCAPCallBackPacket    : TPCAPCallBackPacket;     // event for process packet analyzed
    FOnPCAPCallBackError     : TPCAPCallBackError;      // event for PCAP analysis error
    FOnPCAPCallBackProgress  : TPCAPCallBackProgress;   // event for PCAP analysis progress
    FOnPCAPCallBeforeBackEnd : TPCAPCallBeforeBackEnd;  // event fire bofere end analysis 
    FonWpcapEthMacFound      : TWpcapEthMacFound;       // event for MAC found
    FonWpcapIpFound          : TWpcapIPFound;           // event for IP found
    FOnWpcapProtocolDetected : TWpcapProtocolDetected;  // event for protocol detected      
    FOnLog                   : TWpcapLog;               // event for logging      
    FFlowInfoList            : TFlowInfoList;
    FCurrentFlowID           : Integer;    
  protected
    FFilename               : string;
    FFilter                 : string;  
    FByteAnalyzed           : Int64;    
    FOwner                  : TObject;
    Procedure DoCreate;
    ///<summary>
    /// Invokes an error event with the given error message
    ///</summary>
    ///<param name="aFileName">File name of the error</param>
    ///<param name="aErrorMessage">Error message to send</param>
    procedure DoError(const aFileName, aErrorMessage: string); virtual;
    
     /// <summary>
     /// Log a message with the given function name, description, and log level.
     /// </summary>         
    procedure DoLog(const aFunctionName, aDescription: String;aLevel: TWpcapLvlLog);   
  public
    destructor Destroy; override;    
    ///<summary>
    /// Stops the thread from capturing packets
    ///</summary>
    procedure Stop;
    
    procedure GetNewFlowID(var aNewFlowID:Integer);
    ///<summary>
    /// Invokes a progress event with the given packet size information
    ///</summary>
    ///<param name="aTotalSize">Total number of bytes to be processed</param>
    ///<param name="aCurrentSize">Number of bytes processed so far</param>
    procedure DoProgress(aTotalSize, aCurrentSize: Int64); virtual;

    ///<summary>
    /// Invokes a packet event with the given internal packet information
    ///</summary>
    ///<param name="aInternalPacket">Internal packet information</param>
    procedure DoPacket(const aInternalPacket: PTInternalPacket); virtual;

    ///<summary>
    /// Executes a callback function in the context of the main thread to notify a listener that an Mac address has been found
    ///</summary>
    ///<param name="aInternalPacket">Pointer to a structure that contains information about the packet</param>
    ///<param name="aSkypPacket">Specifies whether the packet should be skipped</param>    
    procedure DoEthMacFound(aInternalPacket: PTInternalPacket;var aSkypPacket:Boolean;var aAnonymize : Boolean;var aNewMacSrc:TWpcapMacAddress;var aNewMacDst:TWpcapMacAddress);                          

    ///<summary>
    /// Executes a callback function in the context of the main thread to notify a listener that an IP address has been found
    ///</summary>
    ///<param name="aInternalPacket">Pointer to a structure that contains information about the packet</param>
    ///<param name="aSkypPacket">Specifies whether the packet should be skipped</param>
    procedure DoIpFound(const aInternalPacket: PTInternalPacket;var aSkypPacket: Boolean);

    ///<summary>
    /// Executes a callback function in the context of the main thread to notify a listener that an protocol has been detected
    ///</summary>
    ///<param name="aInternalPacket">Pointer to a structure that contains information about the packet</param>
    ///<param name="aSkypPacket">Specifies whether the packet should be skipped</param>    
    procedure DoProtocolFound(const aInternalPacket: PTInternalPacket;var aSkypPacket: Boolean);    
    
    ///<summary>
    /// Flag that determines if the thread should be aborted
    ///</summary>
    ///<returns>True if should be aborted; otherwise, False</returns>
    Property Aborted                  : Boolean                 read FAbort;

    ///<summary>
    /// Event triggered when there is a callback error
    ///</summary>
    property OnPCAPCallBackError      : TPCAPCallBackError      read FOnPCAPCallBackError     write FOnPCAPCallBackError;

    ///<summary>
    /// Event triggered during the PCAP analisys
    ///</summary>
    property OnPCAPCallBackProgress   : TPCAPCallBackProgress   read FOnPCAPCallBackProgress  write FOnPCAPCallBackProgress;

    ///<summary>
    /// Event triggered when packet is ready
    ///</summary>
    property OnPCAPCallBackPacket     : TPCAPCallBackPacket     read FOnPCAPCallBackPacket    write FOnPCAPCallBackPacket;    

    ///<summary>
    /// Event triggered before call callBackEnd event
    ///</summary>
    property OnPCAPCallBeforeBackEnd  : TPCAPCallBeforeBackEnd  read FOnPCAPCallBeforeBackEnd   write FOnPCAPCallBeforeBackEnd;     

    /// <summary>
    /// Occurs when a Wpcap Ethernet MAC is found.
    /// </summary>
    property OnWpcapEthMacFound       : TWpcapEthMacFound       read FonWpcapEthMacFound        write FonWpcapEthMacFound;

    /// <summary>
    /// Occurs when a Wpcap IP address is found.
    /// </summary>
    property OnWpcapIpFound           : TWpcapIPFound           read FonWpcapIpFound            write FonWpcapIpFound;

    /// <summary>
    /// Occurs when a Wpcap protocol is detected.
    /// </summary>
    property OnWpcapProtocolDetected  : TWpcapProtocolDetected  read FOnWpcapProtocolDetected    write FOnWpcapProtocolDetected;

    /// <summary>
    /// Gets or sets the TWpcapLog event for logging.
    /// </summary>        
    property OnLog                    : TWpcapLog               read FOnLog                       write FOnLog;       

    property FlowInfoList             : TFlowInfoList           read FFlowInfoList              write FFlowInfoList;           
  end;

  ///<summary>
  /// Thread class for capturing real-time network packets using the PCAP library
  ///</summary>          
  TPCAPCaptureRT = class(TThreadPcap)
  private
    FInterfaceName          : string;
    FIP                     : string;
    FPromisc                : Boolean;
    FSavePcapDump           : Boolean;
    FTimeoutMs              : Integer;
    FMaxSizePacket          : Integer;
    FFrameNumber            : Integer;
    FCountFile              : Integer;
    FMaxMBPcapFile          : Integer;
    FStartPcapFile          : TDateTime;
    FMaxMinPcapFile         : Integer;    
    FTimeRecoStop           : TTime;  
    FTimeRecCheck           : TDatetime;
    FPcapDumper             : ppcap_dumper_t;
    FPCapRT                 : Ppcap_t;    
    FDataLink               : Integer;   
    FListLabelByLevel       : TListLabelByLevel;

  protected
    ///<summary>
    /// Overrides the Execute method from the parent class to start capturing real-time packets
    ///</summary>
    procedure Execute; override;

  public
    ///<summary>
    /// Creates an instance of the TPCAPCaptureRT class with the specified parameters
    ///</summary>
    ///<param name="aOwner">Owner object</param>
    ///<param name="aFilename">Name of the capture file</param>
    ///<param name="aFilter">Capture filter</param>
    ///<param name="aInterfaceName">Name of the interface to capture on</param> 
    ///<param name="aIP">IP address to capture on</param> 
    ///<param name="aPromisc">Promiscuous mode flag</param>
    ///<param name="aSavePcapDump">Save PCAP dump flag</param>
    ///<param name="aTimeoutMs">Capture timeout in milliseconds</param>
    ///<param name="aMaxSizePacket">Maximum size of packets to capture</param>
    ///<param name="aMaxMBPcapFile">Maximum size of PCAP file </param>
    ///<param name="aMaxMinPcapFile">Maximum time interval in PCAP file</param>   
    ///<param name="aMaxMBPcapFile">Maximum size of PCAP file </param>
    ///<param name="aMaxMinPcapFile">Maximum time interval in PCAP file</param>   
    ///<param name="aTimeRecoStop">Time to stop capturing packets</param>  
    constructor Create(const aOwner: TObject; const aFilename, aFilter, aInterfaceName, aIP: string; aPromisc, aSavePcapDump: Boolean; 
                      aTimeoutMs: Integer = 1000; 
                      aMaxSizePacket: Integer = MAX_PACKET_SIZE; 
                      aMaxMBPcapFile: Integer = 50;
                      aMaxMinPcapFile: Integer = 5;                      
                      aTimeRecoStop: TTime = 0);  
    
    ///<summary>
    /// Destroys the instance of the TPCAPCaptureRT class and cleans up resources
    ///</summary>
    destructor Destroy; override;

    procedure IncFrameNumber;
    procedure CheckNewDumpFile;
    {Property}
    Property PCapRT           : Ppcap_t           read FPCapRT; 
    property DataLink         : Integer           read FDataLink;
    property ListLabelByLevel : TListLabelByLevel read FListLabelByLevel;
    property FrameNumber      : Integer           read FFrameNumber       write FFrameNumber;
    Property SavePcapDump     : Boolean           read FSavePcapDump;
    property PcapDumper       : ppcap_dumper_t    read FPcapDumper;
  end;

  ///<summary>
  /// Thread class for loading a PCAP capture file and decoding its packets
  ///</summary>
  TPCAPLoadFile = class(TThreadPcap)
  private
    FGeoLiteDB    : TWpcapGEOLITE;
  protected
    ///<summary>
    /// Overrides the Execute method from the parent class to load and decode packets from the capture file
    ///</summary>
    procedure Execute; override;
  public
    ///<summary>
    /// Creates an instance of the TPCAPLoadFile class with the specified parameters
    ///</summary>
    ///<param name="aOwner">Owner object</param>
    ///<param name="aFilename">Name of the capture file to load</param>
    ///<param name="aFilter">Capture filter</param>
    ///<param name="aGeoLiteDB">GeoLite database to use for IP geolocation</param>
    constructor Create(const aOwner: TObject; const aFilename, aFilter: string; const aGeoLiteDB: TWpcapGEOLITE);
  end;

 
  TPCAPUtils = class
  strict private
    var FAbort                   : Boolean; 
    var FThreadCaptureRT         : TPCAPCaptureRT;    
    var FThreadLoadFile          : TPCAPLoadFile;        
    var FOnPCAPCallBeforeBackEnd : TPCAPCallBeforeBackEnd;  // event fire bofere end analysis 
    var FOnPCAPCallBackPacket    : TPCAPCallBackPacket;     // event for process packet analyzed
    var FOnPCAPCallBackError     : TPCAPCallBackError;      // event for PCAP analysis error
    var FOnPCAPCallBackProgress  : TPCAPCallBackProgress;   // event for PCAP analysis progress
    var FonWpcapEthMacFound      : TWpcapEthMacFound;       // event for MAC found
    var FonWpcapIpFound          : TWpcapIPFound;           // event for IP found
    var FOnWpcapProtocolDetected : TWpcapProtocolDetected;  // event for protocol detected      
    var FonLog                   : TWpcapLog;               // event for logging              
  private
    ///<summary>
    /// Event handler for when the real-time capture terminates
    ///</summary>
    ///<param name="sender">Object that triggered the event</param>
    procedure DoOnTerminateRT(sender:TObject);

    ///<summary>
    /// Event handler for when the offline capture terminates
    ///</summary>
    ///<param name="sender">Object that triggered the event</param>
    procedure DoOnTerminateOffline(sender:TObject);

    ///<summary>
    /// Sets the value of an abort flag
    ///</summary>
    ///<param name="aValue">Value to set for the flag</param>
    procedure SetAbort(const aValue:Boolean);
    
    /// <summary>
    /// Log a message with the given function name, description, and log level.
    /// </summary>             
    procedure DoLog(const aFunctionName, aDescription: String;aLevel: TWpcapLvlLog);
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
    procedure AnalyzePCAPOffline( const aFilename, aFilter: String;
                                        aGeoLiteDB : TWpcapGEOLITE); 

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
                                          aTimeOutMs:Integer=1000;
                                          aMaxSizePakcet:Integer = MAX_PACKET_SIZE;
                                          aMaxMBPcapFile: Integer = 50;
                                          aMaxMinPcapFile: Integer = 5;
                                          aTimeRecoStop : TTime = 0); 
    
    ///  <summary>
    ///    Saves a list of packets to a pcap file.
    ///  </summary>
    ///  <param name="aPacketList">
    ///    The list of packets to save.
    ///  </param>
    ///  <param name="aFilename">
    ///    The name of the pcap file to save to.
    ///  </param>
    procedure SavePacketListToPcapFile(aPacketList: TList<PTPacketToDump>; aFilename: String);
    
    property Aborted                  : Boolean                    read FAbort                     write SetAbort;
    property ThreadCaptureRT          : TPCAPCaptureRT             read FThreadCaptureRT;
    
    {Event}
    ///<summary>
    /// Event triggered when there is a callback error
    ///</summary>
    property OnPCAPCallBackError      : TPCAPCallBackError      read FOnPCAPCallBackError     write FOnPCAPCallBackError;

    ///<summary>
    /// Event triggered during the PCAP analisys
    ///</summary>
    property OnPCAPCallBackProgress   : TPCAPCallBackProgress   read FOnPCAPCallBackProgress  write FOnPCAPCallBackProgress;

    ///<summary>
    /// Event triggered when packet is ready
    ///</summary>
    property OnPCAPCallBackPacket     : TPCAPCallBackPacket     read FOnPCAPCallBackPacket    write FOnPCAPCallBackPacket;    

    ///<summary>
    /// Event triggered before call callBackEnd event
    ///</summary>
    property OnPCAPCallBeforeBackEnd  : TPCAPCallBeforeBackEnd  read FOnPCAPCallBeforeBackEnd   write FOnPCAPCallBeforeBackEnd;  

    /// <summary>
    /// Occurs when a Wpcap Ethernet MAC is found.
    /// </summary>
    property OnWpcapEthMacFound       : TWpcapEthMacFound       read FonWpcapEthMacFound        write FonWpcapEthMacFound;

    /// <summary>
    /// Occurs when a Wpcap IP address is found.
    /// </summary>
    property OnWpcapIpFound           : TWpcapIPFound           read FonWpcapIpFound            write FonWpcapIpFound;

    /// <summary>
    /// Occurs when a Wpcap protocol is detected.
    /// </summary>
    property OnWpcapProtocolDetected  : TWpcapProtocolDetected  read FOnWpcapProtocolDetected    write FOnWpcapProtocolDetected;

    /// <summary>
    /// Gets or sets the TWpcapLog event for logging.
    /// </summary>        
    property OnLog                    : TWpcapLog               read FOnLog                       write FOnLog;        
  end;


implementation

function PacketHandlerRealtime ( aUser: PAnsiChar;const aHeader: PTpcap_pkthdr;const aPacketData: Pbyte): Integer; 
var PacketBuffer     : TBytes;
    LPacketLen       : Word;
    aNewHeader       : PTpcap_pkthdr;
    LTInternalPacket : PTInternalPacket;
    LSkypPacket      : Boolean;
    LAnonymize       : Boolean;
    LNewMacSrc       : TWpcapMacAddress;
    LNewMacDst       : TWpcapMacAddress;  
    RTThread         : TPCAPCaptureRT;
begin
  if Assigned(aPacketData) then
  begin
    RTThread   := TPCAPCaptureRT(aUser);
    LPacketLen := aHeader^.caplen;

    new(aNewHeader);
    Try
      aNewHeader.ts     := aHeader.ts;
      aNewHeader.caplen := (aHeader.caplen);

      SetLength(PacketBuffer,LPacketLen);
      Move(aPacketData^, PacketBuffer[0], LPacketLen);
      
      if RemovePendingBytesFromPacketData(PacketBuffer,LPacketLen) then
        SetLength(PacketBuffer,LPacketLen);
        
      RTThread.DoProgress(-1,LPacketLen);
               
      aNewHeader.len := aHeader.len;
      RTThread.IncFrameNumber;
      LTInternalPacket := AnalyzePacketCallBack(@PacketBuffer[0],
                              RTThread.FrameNumber,
                              aNewHeader,nil,
                              RTThread.ListLabelByLevel,
                              RTThread.OnLog,
                              RTThread.FlowInfoList,
                              RTThread.GetNewFlowID);
      
      if Assigned(LTInternalPacket) then
      begin
        Try
          LSkypPacket := false;
          LAnonymize  := True;
          RTThread.DoEthMacFound(LTInternalPacket,LSkypPacket,LAnonymize,LNewMacSrc,LNewMacDst);

          if not LSkypPacket then
          begin
            RTThread.DoIpFound(LTInternalPacket,LSkypPacket);

            if not LSkypPacket then
              RTThread.DoProtocolFound(LTInternalPacket,LSkypPacket);
             
            if not LSkypPacket then       
            begin      
              RTThread.DoPacket(LTInternalPacket);
              if RTThread.SavePcapDump then              
              begin
                if LTInternalPacket.PacketSize > 0 then               
                  pcap_dump(RTThread.PcapDumper, aNewHeader, LTInternalPacket.PacketData);              
                RTThread.CheckNewDumpFile                
              end;
            end;
          end;          
        finally
          Dispose(LTInternalPacket)
        end; 
      end;              
    Finally
      dispose(aNewHeader);
    End;
  end;
  
  if ( TPCAPCaptureRT(aUser).Aborted) or 
      ( ( TPCAPCaptureRT(aUser).FTimeRecCheck>0 ) and (Now> TPCAPCaptureRT(aUser).FTimeRecCheck) ) 
  then
    pcap_breakloop(TPCAPCaptureRT(aUser).PCapRT);                             

  Result := 0;
end;

function AnalyzePacketCallBack(const aPacketData : Pbyte;aFrameNumber:Integer;aHeader:PTpcap_pkthdr;aGeoLiteDB : TWpcapGEOLITE; aListLabelByLevel : TListLabelByLevel;aLogFunctoin:TWpcapLog;aFlowInfoList:TFlowInfoList;aGetNewFlowIDFnc: TWpcapGetNewFlowID) : PTInternalPacket;
var LLen                    : Integer;
    LListDetail             : TListHeaderString;
    LLikLayersSize          : Integer;
    LEthParser              : TWpcapEthHeader;
    LAdditionalParameters   : TAdditionalParameters;
begin
  Result := nil;
  if not Assigned(aPacketData) then Exit;
  LEthParser :=  TWpcapEthHeader.Create;
  Try
    LEthParser.FlowInfoList   := aFlowInfoList; 
    LEthParser.OnLog          := aLogFunctoin;
    LEthParser.OnGetNewFlowID := aGetNewFlowIDFnc;
    
    New(Result); 
    Result.PacketDate            := UnixToDateTime(aHeader.ts.tv_sec,false);    
    Result.AdditionalInfo.Index  := aFrameNumber;
    
    LLen                         := aHeader.len;
    LLikLayersSize               := 0;

    LEthParser.InternalPacket(aPacketData,LLen,FIANADictionary,Result,LLikLayersSize); 
  
    Result.RAW_Text := BufferToASCII(aPacketData,LLen);
    LListDetail     := TListHeaderString.Create;

    Try

      LAdditionalParameters.TCP.Retrasmission         := False;
      LAdditionalParameters.TCP.RetrasmissionFn       := -1;        
      LAdditionalParameters.TCP.AcknowledgmentNumber  := 0;    
      LAdditionalParameters.TCP.TimeStamp             := 0;                
      LAdditionalParameters.SequenceNumber            := 0;
      LAdditionalParameters.PayLoadSize               := 0;    
      LAdditionalParameters.FlowID                    := 0;                        
      LAdditionalParameters.Info                      := String.Empty;
      LAdditionalParameters.EnrichmentPresent         := False;
      LAdditionalParameters.ContentExt                := String.Empty;      
      LAdditionalParameters.CompressType              := -1;
      LAdditionalParameters.FrameNumber               := aFrameNumber;
      LAdditionalParameters.PacketDate                := Result.PacketDate;
     
      if LEthParser.HeaderToString(Result.PacketData,Result.PacketSize,0,LListDetail,True,@LAdditionalParameters) then 
      begin         
        Result.AdditionalInfo.SequenceNumber    := LAdditionalParameters.SequenceNumber;
        Result.AdditionalInfo.TCP               := LAdditionalParameters.TCP;
        Result.AdditionalInfo.Info              := LAdditionalParameters.Info;
        Result.AdditionalInfo.FlowID            := LAdditionalParameters.FlowID;
        Result.AdditionalInfo.EnrichmentPresent := LAdditionalParameters.EnrichmentPresent;
        Result.AdditionalInfo.CompressType      := LAdditionalParameters.CompressType;                                
        Result.AdditionalInfo.ContentExt        := LAdditionalParameters.ContentExt;                                        
        Result.XML_Detail                       := HeaderStringListToXML(LListDetail,aListLabelByLevel)
      end
      else
        Result.XML_Detail := String.empty;
    Finally
      FreeAndNil(LListDetail);
    End;

    if LLikLayersSize > 0 then
    begin
      {Free Memory}
      FreeMem(Result.PacketData,LLikLayersSize);
      Result.PacketData  := aPacketData;
      Result.PacketSize  := LLen;
    end;    

    Result.IsMalformed                 := LEthParser.IsMalformed;
    Result.IP.SrcGeoIP.ASNumber        := String.Empty;
    Result.IP.SrcGeoIP.ASOrganization  := String.Empty;
    Result.IP.SrcGeoIP.Location        := String.Empty;            
    Result.IP.SrcGeoIP.Latitude        := 0;
    Result.IP.SrcGeoIP.Longitude       := 0;

    Result.IP.DestGeoIP.ASNumber       := String.Empty;
    Result.IP.DestGeoIP.ASOrganization := String.Empty;
    Result.IP.DestGeoIP.Location       := String.Empty;            
    Result.IP.DestGeoIP.Latitude       := 0;
    Result.IP.DestGeoIP.Longitude      := 0;
    
    if Assigned(aGeoLiteDB) and aGeoLiteDB.Connection.Connected then
    begin
      if ( Result.Eth.EtherType = ETH_P_IP ) or
         ( Result.Eth.EtherType = ETH_P_IPV6 ) 
      then
      begin
        if IsValidPublicIP(Result.IP.Src) then        
          aGeoLiteDB.GetGeoIPByIp(Result.IP.Src,@Result.IP.SrcGeoIP);
        if IsValidPublicIP(Result.IP.Dst) then        
          aGeoLiteDB.GetGeoIPByIp(Result.IP.Dst,@Result.IP.DestGeoIP);
      end;
    end;
  Finally
    FreeAndNil(LEthParser);
  End;
end;

procedure TPCAPUtils.SetAbort(const aValue: Boolean);
begin
  FAbort := aValue;
  if Assigned(FThreadCaptureRT) and aValue then
    FThreadCaptureRT.Stop;
  if Assigned(FThreadLoadFile) and aValue then
    FThreadLoadFile.Stop;    
end;

procedure TPCAPUtils.DoLog(const aFunctionName,aDescription: String; aLevel: TWpcapLvlLog);
begin
  if Assigned(FOnLog) then
    FOnLog(aFunctionName,aDescription,aLevel)

end;

procedure TPCAPUtils.AnalyzePCAPRealtime( const aFilename, aFilter,aInterfaceName,aIP: string;
                                                aPromisc,aSevePcapDump:Boolean;
                                                aTimeOutMs:Integer=1000;
                                                aMaxSizePakcet:Integer = MAX_PACKET_SIZE;
                                                aMaxMBPcapFile: Integer = 50;
                                                aMaxMinPcapFile: Integer = 5;
                                                aTimeRecoStop : TTime = 0 
                                             );
begin
  if not Assigned(FOnPCAPCallBackError) then
  begin
    DoLog('TPCAPUtils.AnalyzePCAPRealtime','Callback event for error not assigned',TWLLError);

    raise Exception.Create('Callback event for error not assigned');
  end;

  if aFilename.Trim.IsEmpty then
  begin
    FOnPCAPCallBackError(aFilename,'filename is empty');
    Exit;    
  end;

  if not FileExists(aFilename) then
  begin
    FOnPCAPCallBackError(aFilename,'filename not exists');
    Exit;    
  end;
        
  if not Assigned(FOnPCAPCallBackPacket) then
  begin
    FOnPCAPCallBackError(aFilename,'Callback event for packet not assigned');
    Exit;
  end;

  if not Assigned(FOnPCAPCallBeforeBackEnd) then
  begin
    FOnPCAPCallBackError(aFileName,'Callback event for end analyze not assigned');
    Exit;
  end;  

  if aInterfaceName.Trim.IsEmpty then
  begin
    FOnPCAPCallBackError(aFilename,'Interface name is empty');
    Exit;
  end;  

  FThreadCaptureRT                          := TPCAPCaptureRT.Create(self,aFilename,aFilter,aInterfaceName,aIP,aPromisc,aSevePcapDump,
                                                  aTimeOutMs,aMaxSizePakcet,aMaxMBPcapFile,aMaxMinPcapFile,aTimeRecoStop);
  FThreadCaptureRT.OnPCAPCallBackError      := FOnPCAPCallBackError; 
  FThreadCaptureRT.OnPCAPCallBackProgress   := FOnPCAPCallBackProgress;
  FThreadCaptureRT.OnPCAPCallBackPacket     := FOnPCAPCallBackPacket; 
  FThreadCaptureRT.OnPCAPCallBeforeBackEnd  := FOnPCAPCallBeforeBackEnd; 
  FThreadCaptureRT.OnWpcapEthMacFound       := FOnWpcapEthMacFound;
  FThreadCaptureRT.OnWpcapIpFound           := FOnWpcapIpFound; 
  FThreadCaptureRT.OnWpcapProtocolDetected  := FOnWpcapProtocolDetected;     
  FThreadCaptureRT.OnLog                    := FOnLog;
  FThreadCaptureRT.OnTerminate              := DoOnTerminateRT;
  FThreadCaptureRT.FreeOnTerminate          := True;
  FThreadCaptureRT.Start;     
end;

procedure TPCAPUtils.DoOnTerminateRT(sender: Tobject);
begin
  FThreadCaptureRT := nil;
end;

procedure TPCAPUtils.AnalyzePCAPOffline( const aFilename,aFilter:String;aGeoLiteDB : TWpcapGEOLITE);                            
begin
  if not Assigned(FOnPCAPCallBackError) then
  begin
    DoLog('TPCAPUtils.AnalyzePCAPOffline','Callback event for error not assigned',TWLLError);
    raise Exception.Create('Callback event for error not assigned');
  end;

  if aFilename.Trim.IsEmpty then
  begin
    FOnPCAPCallBackError(aFileName,'filename is empty');
    Exit;    
  end;

  if not FileExists(aFilename) then
  begin
    FOnPCAPCallBackError(aFileName,'filename not exists');
    Exit;    
  end;
        
  if not Assigned(FOnPCAPCallBackPacket) then
  begin
    FOnPCAPCallBackError(aFileName,'Callback event for packet not assigned');
    Exit;
  end;

  if not Assigned(FOnPCAPCallBeforeBackEnd) then
  begin
    FOnPCAPCallBackError(aFileName,'Callback event for end analyze not assigned');
    Exit;
  end;  

  FThreadLoadFile                         := TPCAPLoadFile.Create(self,aFilename, aFilter,aGeoLiteDB);
  FThreadLoadFile.OnPCAPCallBackError     := FOnPCAPCallBackError; 
  FThreadLoadFile.OnPCAPCallBackProgress  := FOnPCAPCallBackProgress;
  FThreadLoadFile.OnPCAPCallBackPacket    := FOnPCAPCallBackPacket; 
  FThreadLoadFile.OnPCAPCallBeforeBackEnd := FOnPCAPCallBeforeBackEnd;   
  FThreadLoadFile.OnWpcapEthMacFound      := FOnWpcapEthMacFound;
  FThreadLoadFile.OnWpcapIpFound          := FOnWpcapIpFound; 
  FThreadLoadFile.OnWpcapProtocolDetected := FOnWpcapProtocolDetected;  
  FThreadLoadFile.OnLog                   := FOnLog;  
  FThreadLoadFile.OnTerminate             := DoOnTerminateOffline;
  FThreadLoadFile.FreeOnTerminate         := True;
  FThreadLoadFile.Start;      
end;

procedure TPCAPUtils.DoOnTerminateOffline(sender:Tobject);   
begin
  FThreadLoadFile := nil;
end;

procedure TPCAPUtils.SavePacketListToPcapFile(aPacketList: TList<PTPacketToDump>; aFilename: String);
var LPcap        : Ppcap_t;
    LPcapDumper  : ppcap_dumper_t ;
    LPacket      : PByte;
    LPacketHeader: Tpcap_pkthdr;
    I            : Integer;
begin
  LPcap := pcap_open_dead(DLT_EN10MB, MAX_PACKET_SIZE);

  if LPcap = nil then
  begin
    DoLog('TPCAPUtils.SavePacketListToPcapFile','Failed to open PCAP [LPcap not assinged]',TWLLError);
    raise Exception.Create('Failed to open PCAP');
  end;

  Try
    // Open the PCAP file for writing
    LPcapDumper := pcap_dump_open(LPcap, PAnsiChar(AnsiString(aFilename)));

    if LPcapDumper = nil then
    begin
      DoLog('TPCAPUtils.SavePacketListToPcapFile',Format('Failed to dumper object for file [%s] - error [%s]',[aFilename,string(pcap_geterr(LPcap))]),TWLLError);
      raise Exception.CreateFmt('Failed to open PCAP dump %s',[string(pcap_geterr(LPcap))]);
    end;

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

{ TThreaPcap }
procedure TThreadPcap.DoError(const aFileName, aErrorMessage: string);
begin
  DoLog('TThreadPcap.DoError',Format('File [%s] - error [%s]',[aFilename,aErrorMessage]),TWLLError);
  TThread.Synchronize(nil,
    procedure
    begin         
        OnPCAPCallBackError(aFileName,aErrorMessage);
    end);  
end;

procedure TThreadPcap.DoLog(const aFunctionName, aDescription: String;aLevel: TWpcapLvlLog);
begin
  if Assigned(FOnLog) then
    FOnLog(aFunctionName,aDescription,aLevel);
end;

procedure TThreadPcap.DoProgress(aTotalSize,aCurrentSize:Int64);
begin
  Inc(FByteAnalyzed,aCurrentSize);
  TThread.Synchronize(nil,
    procedure
    begin    
      if Assigned(OnPCAPCallBackProgress) then
        OnPCAPCallBackProgress(aTotalSize,aCurrentSize);
    end);        
end;

procedure TThreadPcap.Stop;
begin
  Fabort := True;
end;

procedure TThreadPcap.DoIpFound(const aInternalPacket : PTInternalPacket;var aSkypPacket:Boolean);
var LSkyp : Boolean;
begin
  if Assigned(FonWpcapIpFound) then
  begin
    LSkyp := aSkypPacket;
    TThread.Synchronize(nil,
      procedure
      begin                    
        FonWpcapIpFound(aInternalPacket.IP.Src,aInternalPacket.Ip.Dst,LSkyp);
      end);
    aSkypPacket := LSkyp;      
  end;  
end;

procedure TThreadPcap.DoProtocolFound(const aInternalPacket : PTInternalPacket;var aSkypPacket:Boolean);
var LSkyp : Boolean;
begin
  if Assigned(FOnWpcapProtocolDetected) then
  begin
    LSkyp := aSkypPacket;  
    TThread.Synchronize(nil,
      procedure
      begin                    
        FOnWpcapProtocolDetected(aInternalPacket.IP.ProtoAcronym,LSkyp);
      end);
    aSkypPacket := LSkyp;        
  end;  
end;

procedure TThreadPcap.DoEthMacFound(aInternalPacket : PTInternalPacket;var aSkypPacket:Boolean;var aAnonymize : Boolean;var aNewMacSrc:TWpcapMacAddress;var aNewMacDst:TWpcapMacAddress);
var LSkyp       : Boolean;
    LAnonymize  : Boolean;
    LNewMacSrc  : TWpcapMacAddress;
    LNewMacDst  : TWpcapMacAddress;    
    
begin
  if Assigned(FonWpcapEthMacFound) then
  begin
    LSkyp      := aSkypPacket;  
    LAnonymize := aAnonymize;  
    LNewMacSrc := aNewMacSrc;
    LNewMacDst := aNewMacDst;
    TThread.Synchronize(nil,
      procedure
      begin                    
        FonWpcapEthMacFound(aInternalPacket.Eth.SrcAddr,aInternalPacket.Eth.SrcAddr,LSkyp,LAnonymize,LNewMacSrc,LNewMacDst);
      end);
      
    aSkypPacket := LSkyp;        
    aAnonymize  := LAnonymize;
    aNewMacSrc  := LNewMacSrc;
    aNewMacDst  := LNewMacDst;

    if not LSkyp and LAnonymize then
    begin
      aInternalPacket.Eth.SrcAddr                  := MACAddrToStr(LNewMacSrc);
      aInternalPacket.Eth.DestAddr                 := MACAddrToStr(LNewMacDst);
      PETHHdr(aInternalPacket.PacketData).DestAddr := LNewMacSrc;
      PETHHdr(aInternalPacket.PacketData).DestAddr := LNewMacDst;
    end;
  end;
end;

procedure TThreadPcap.DoPacket(const aInternalPacket : PTInternalPacket);
begin
  TThread.Synchronize(nil,
    procedure
    begin                    
      OnPCAPCallBackPacket(aInternalPacket);
    end);
end;

procedure TThreadPcap.DoCreate;
begin
  FFlowInfoList  := TFlowInfoList.Create;
  FByteAnalyzed  := 0;
end;

destructor TThreadPcap.Destroy;
var LInfo : TFlowInfo;
begin
  for LInfo in FFlowInfoList.Values do
    FreeAndNil(LInfo.SeqAckList);
  FreeAndNil(FFlowInfoList);
  inherited;
end;

{TPCAPCaptureRT}
constructor TPCAPCaptureRT.Create(const aOwner: TObject; const aFilename, aFilter, aInterfaceName, aIP: string; aPromisc, aSavePcapDump: Boolean; 
                                  aTimeoutMs: Integer = 1000; 
                                  aMaxSizePacket: Integer = MAX_PACKET_SIZE; 
                                  aMaxMBPcapFile: Integer = 50;
                                  aMaxMinPcapFile: Integer = 5;                      
                                  aTimeRecoStop: TTime = 0);  
begin
  inherited Create(True);
  FFilename         := aFilename;
  FOwner            := aOwner;
  FFilter           := aFilter;
  FInterfaceName    := aInterfaceName;
  FIP               := aIP;
  FPromisc          := aPromisc;
  FSavePcapDump     := aSavePcapDump;
  FTimeoutMs        := aTimeoutMs;
  FMaxSizePacket    := aMaxSizePacket;
  FMaxMBPcapFile    := aMaxMBPcapFile;
  FMaxMinPcapFile   := aMaxMinPcapFile;
  FTimeRecoStop     := aTimeRecoStop;
  FAbort            := False;
  FListLabelByLevel := TListLabelByLevel.Create;
  DoCreate;
end;

destructor TPCAPCaptureRT.Destroy;
begin
  FreeAndNil(FListLabelByLevel);
  inherited;
end;

Procedure TPCAPCaptureRT.CheckNewDumpFile;
begin
  // Open the PCAP file for writing
  if FSavePcapDump then    
  begin

    if Assigned(FPcapDumper) then
    begin
      if ( FByteAnalyzed >= ( FMaxMBPcapFile * 1024 * 1024)) or
         ( MinutesBetween(Now,FStartPcapFile) >= FMaxMinPcapFile) then
      begin
        FByteAnalyzed  := 0;
        FStartPcapFile := Now;
        pcap_dump_close(FPcapDumper);
        FPcapDumper := nil;
      end;
    end;
    
    if FPcapDumper = nil then
    begin
      FPcapDumper := pcap_dump_open(FPcapRT, PAnsiChar( AnsiString( ChangeFileExt( FFilename, Format('_%d.pcap',[FCountFile]) ) ) ) );
      Inc(FCountFile);
      if FPcapDumper = nil then
      begin
        DoError(FFilename,Format('Failed to open PCAP dump %s',[string(pcap_geterr(FPcapRT))]));
        Exit;
      end;      
    end;
  end;
end;

procedure TPCAPCaptureRT.Execute;
var Lerrbuf      : array[0..PCAP_ERRBUF_SIZE-1] of AnsiChar;

    LLoopResult  : Integer;
begin
  inherited;
  FPcapDumper   := nil;
  FTimeRecCheck := 0;
  FFrameNumber  := 0;
  if FTimeRecoStop > 0 then
  begin
    FTimeRecCheck := now;
    ReplaceTime(FTimeRecCheck,FTimeRecoStop);    
    if CompareTime(FTimeRecoStop,now) <> GreaterThanValue then
      FTimeRecCheck := IncDay(FTimeRecCheck,1)
  end;

  FlowInfoList.Clear;
  FCountFile     := 1;
  FStartPcapFile := Now;
  
  // Open the network adapter for capturing
  FPcapRT := pcap_open_live(PAnsiChar(AnsiString(FInterfaceName)), FMaxSizePacket, ifthen(FPromisc,1,0), FTimeOutMs, Lerrbuf);
  if not Assigned(FPcapRT) then
  begin
    DoError(FFilename,Format('Error opening network adapter: %s', [Lerrbuf]));
    Exit;
  end;
  
  Try          
    CheckNewDumpFile;

    Try        
      //5mb todo by parameter???
      if  pcap_set_buffer_size(FPcapRT,5*1024*1024) = -1 then
      begin
        DoError(FFilename,Format('Failed to set buffer size %s',[string(pcap_geterr(FPcapRT))]));
        exit;      
      end;

      // Set the packet filter if one was provided
      if not CheckWPcapFilter(FPcapRT,FFilename,FFilter,FIP,DoError) then exit;

      if pcap_set_datalink(FPCapRT,DLT_EN10MB) = -1 then
      begin
        DoError(FFilename,Format('Failed to set datalink [%d] error [%s]',[FDataLink,string(pcap_geterr(FPcapRT))]));
        exit;      
      end;

      FDataLink  := pcap_datalink(FPCapRT);

      if FDataLink <> DLT_EN10MB then
      begin
        DoError(FFilename,Format('Device doesn''t provide Ethernet headers - not supported , DataLink [%d]',[FDataLink]));
        exit;      
      end;   
      
      // Start capturing packets and writing them to the output file
      LLoopResult := pcap_loop(FPcapRT, -1, @PacketHandlerRealtime, Pbyte(Self));
      case LLoopResult  of
        0 :; //Cnt end
       -1 : DoError(FFilename,Format('pcap_loop ended because of an error %s',[string(pcap_geterr(FPcapRT))])); 
       -2 : //Normal
      else
         DoError(FFilename,Format('pcap_loop ended unknow return code [%d] error %s',[LLoopResult,string(pcap_geterr(FPcapRT))]));
      end;
    Finally
      // Close the output file and the network adapter
      if FSavePcapDump and Assigned(FPcapDumper) then     
        pcap_dump_close(FPcapDumper);
    End;        
  Finally
    pcap_close(FPcapRT);
  End;
end;

procedure TPCAPCaptureRT.IncFrameNumber;
begin
  inc(FFrameNumber);
end;

{ TPCAPLoadFile }
constructor TPCAPLoadFile.Create(const aOwner: TObject; const aFilename, aFilter: string; const aGeoLiteDB: TWpcapGEOLITE);
begin
  inherited Create(True);
  FFilename      := aFilename;
  FOwner         := aOwner;
  FFilter        := aFilter;
  FGeoLiteDB     := aGeoLiteDB;
  DoCreate;  
end;

procedure TPCAPLoadFile.Execute;
var LHandlePcap      : Ppcap_t;
    LErrbuf          : array[0..PCAP_ERRBUF_SIZE-1] of AnsiChar;
    LHeader          : PTpcap_pkthdr;
    LPktData         : PByte;
    LResultPcapNext  : Integer;
    LLenAnalyze      : Int64;
    LTolSizePcap     : Int64;
    LTInternalPacket : PTInternalPacket;
    LListLabelByLevel: TListLabelByLevel;
    LIndex           : Integer;
    LSkypPacket      : boolean;
    LAnonymize       : Boolean;
    LNewMacSrc       : TWpcapMacAddress;
    LNewMacDst       : TWpcapMacAddress;    
    LStopwatch       : TStopwatch;
    LMsElp           : Int64;
begin
  FAbort               := False;
  LTolSizePcap         := FileGetSize(FFileName);  
  LLenAnalyze          := 0;
  LIndex               := 0;
  DoProgress(LTolSizePcap,0);
 
  LHandlePcap := pcap_open_offline(PAnsiChar(AnsiString(FFileName)), LErrbuf);
  FlowInfoList.Clear;  
  if LHandlePcap = nil then
  begin
    DoError(FFileName,string(LErrbuf));
    Exit;
  end;

  Try
    LStopwatch := TStopwatch.Create;
    Try
      try
        if not CheckWPcapFilter(LHandlePcap,FFileName,FFilter,String.Empty,FOnPCAPCallBackError) then exit;

        LListLabelByLevel := TListLabelByLevel.Create;
        try
          while True do
          begin      
             if Terminated then exit;
            // Read the next packet
            LResultPcapNext := pcap_next_ex(LHandlePcap, LHeader, @LPktData);
            case LResultPcapNext of
              1:  // packet read correctly
                begin     
                  try
                    LStopwatch := LStopwatch.StartNew;
                    Inc(LIndex);    
                    DoLog('TPCAPLoadFile.Execute',Format('Analyze frame number [%d]',[LIndex]),TWLLInfo);                                  
                    Inc(LLenAnalyze,LHeader^.Len);
                    {Does using parallel to parse pcap make the management of TCP retransmissions and sequence numbers complicated?}

                    LTInternalPacket  := AnalyzePacketCallBack(LPktData,LIndex,LHeader,FGeoLiteDB,LListLabelByLevel,FOnLog,FlowInfoList,GetNewFlowID);
                    if Assigned(LTInternalPacket) then
                    begin
                      Try
                        LSkypPacket := false;
                        DoEthMacFound(LTInternalPacket,LSkypPacket,LAnonymize,LNewMacSrc,LNewMacDst);  

                        if not LSkypPacket then
                          DoIpFound(LTInternalPacket,LSkypPacket);

                        if not LSkypPacket then
                          DoProtocolFound(LTInternalPacket,LSkypPacket);
                          
                        DoPacket(LTInternalPacket);
                      finally
                        Dispose(LTInternalPacket)
                      end; 
                    end;   
                        
                    DoProgress(LTolSizePcap,LLenAnalyze);
                  Except on E :Exception do
                    begin
                      DoError(FFileName,Format('Exception %s Index packet %d',[e.message,LIndex]));
                      Break;
                    end;
                  End;
                
                  if FAbort then Break;
                
                  LMsElp := LStopwatch.ElapsedMilliseconds;
                  if LMsElp > 5 then    
                    DoLog('TPCAPLoadFile.Execute',Format('Analyze frame number [%d] execute in [%d ms]',[LIndex,LMsElp]),TWLLTiming);                                                  
                end;
              0: // No packets available at the moment
                  Continue;
             -1: // Error reading packet 
                begin                  
                  DoError(FFileName,string(pcap_geterr(LHandlePcap)));
                  Break;
                end;
             -2: // No packets available, the pcap file instance has been closed
                begin                  
                  DoProgress(LTolSizePcap,LTolSizePcap);
                  TThread.Synchronize(nil,
                    procedure
                    begin                                 
                      FOnPCAPCallBeforeBackEnd(FFileName,LListLabelByLevel);
                    end);
                  Break;
                end;
            end;
          end;    
        finally
          FreeAndNil(LListLabelByLevel);
        end;
      finally        
        pcap_close(LHandlePcap);  // Close PCAP file
      end;
    Finally
      LStopwatch.Stop
    End;
  Except on E :Exception do
    DoError(FFileName,Format('Genesic exception %s',[e.message]));
  End;
end;

procedure TThreadPcap.GetNewFlowID(var aNewFlowID: Integer);
begin
  Inc(FCurrentFlowID);
  aNewFlowID := FCurrentFlowID;
end;

end.
