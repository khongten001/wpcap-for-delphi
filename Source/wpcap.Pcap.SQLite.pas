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

unit wpcap.Pcap.SQLite;

interface

uses wpcap.Pcap,System.SysUtils,wpcap.DB.SQLite.Packet,wpcap.Packet,wpcap.GEOLite2,Wpcap.Types;

type
  TPCAP2SQLite = class
  private
    FWPcapDBSqLite    : TWPcapDBSqLitePacket;   
    FPCAPCallBackEnd  : TPCAPCallBackEnd;
    FPCAPCallBackError: TPCAPCallBackError;
    FPcapUtils        : TPCAPUtils;
    procedure DoPCAPCallBackPacket(const aInternalPacket : PTInternalPacket);
    procedure DoPCAPCallBeforeBackEnd(const aFileName:String;aListLabelByLevel:TListLabelByLevel);
    procedure DoPCAPCallBackError(const aFileName, aError: String);
    procedure SetAbort(const Value: Boolean);
   public
    destructor Destroy; override;
    ///<summary>
    /// Converts an offline packet capture file to an SQLite database using a specified set of callbacks.
    ///</summary>
    ///<param name="aFileName">
    /// The name of the file to be converted.
    ///</param>
    ///<param name="aFilenameDB">
    /// The name of the SQLite database file to be created.
    ///</param>
    ///<param name="afilter">
    /// Optional filter in string format on PCAP file 
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
    /// This procedure converts an offline packet capture file to an SQLite database using a specified set of callbacks. 
    /// The specified callbacks are responsible for processing packets, handling errors, and reporting progress to the user. 
    /// The procedure reads the capture file packet by packet, inserting the packets into the specified SQLite database. 
    //  The progress callback is optional and can be used to report progress to the user during long-running capture file analysis.
    ///</remarks>   
    procedure PCAP2SQLite(const aFilename,aFilenameDB,aFilter:String;
                              aGeoLiteDB           : TWpcapGEOLITE;
                              aPCAPCallBackError   : TPCAPCallBackError;
                              aPCAPCallBackEnd     : TPCAPCallBackEnd;
                              aPCAPCallBackProgress: TPCAPCallBackProgress = nil);
    property Abort : Boolean write SetAbort;
  end;

implementation

{ TPCAP2SQLite }

procedure TPCAP2SQLite.DoPCAPCallBackPacket(const aInternalPacket : PTInternalPacket);
begin
  FWPcapDBSqLite.InsertPacket(aInternalPacket);
end;

procedure TPCAP2SQLite.DoPCAPCallBackError(const aFileName,aError:String);
begin
  FWPcapDBSqLite.RollbackAndClose(True);    
  FPCAPCallBackError(aFileName,aError)
end;

procedure TPCAP2SQLite.DoPCAPCallBeforeBackEnd(const aFileName:String;aListLabelByLevel:TListLabelByLevel);
begin
  FWPcapDBSqLite.FlushArrayInsert;
  FWPcapDBSqLite.InsertLabelByLevel(aListLabelByLevel);
  FWPcapDBSqLite.CommitAndClose;
  FPCAPCallBackEnd(aFileName)
end;

procedure TPCAP2SQLite.PCAP2SQLite( const aFilename, aFilenameDB,aFilter: String;
                                          aGeoLiteDB           : TWpcapGEOLITE;
                                          aPCAPCallBackError   : TPCAPCallBackError;
                                          aPCAPCallBackEnd     : TPCAPCallBackEnd;
                                          aPCAPCallBackProgress: TPCAPCallBackProgress);
                                          
begin
  if not Assigned(aPCAPCallBackError) then
  begin
    raise Exception.Create('Callback event for error not assigned');
  end;  

  if aFilenameDB.Trim.IsEmpty then
  begin
    aPCAPCallBackError(aFilenameDB,'filename database is empty');
    Exit;    
  end;

  if FileExists(aFilenameDB) then
  begin
    aPCAPCallBackError(aFilenameDB,'filename already exists');
    Exit;    
  end;
  {Backup event}
  FPCAPCallBackError := aPCAPCallBackError;
  FPCAPCallBackEnd   := aPCAPCallBackEnd;

  if Assigned(FWPcapDBSqLite) then
    FreeAndNil(FWPcapDBSqLite);
  {Create database}
  FWPcapDBSqLite := TWPcapDBSqLitePacket.Create;
  Try
    FWPcapDBSqLite.CreateDatabase(aFilenameDB);
    FWPcapDBSqLite.ResetCounterIntsert;
    Try
      FWPcapDBSqLite.Connection.StartTransaction;
      
      if Not Assigned(FPcapUtils) then      
        FPcapUtils := TPCAPUtils.Create;
      Try
        FPcapUtils.OnPCAPCallBackError      := DoPCAPCallBackError;
        FPcapUtils.OnPCAPCallBackProgress   := aPCAPCallBackProgress;
        FPcapUtils.OnPCAPCallBackPacket     := DoPCAPCallBackPacket;
        FPcapUtils.OnPCAPCallBeforeBackEnd  := DoPCAPCallBeforeBackEnd;                    
        FPcapUtils.AnalyzePCAPOffline(aFileName,afilter,aGeoLiteDB);          
      finally
        
      End;
    except on E: Exception do
      DoPCAPCallBackError(aFilenameDB,Format('Exception analyze PCAP %s',[E.Message]));
    end;    
  except on E: Exception do
    DoPCAPCallBackError(aFilenameDB,Format('Exception create database %s',[E.Message]));
  end;    
   
end;

destructor TPCAP2SQLite.Destroy;
begin
  if Assigned(FPcapUtils) then
    FreeAndNil(FPcapUtils);
  if Assigned(FWPcapDBSqLite) then
    FreeAndNil(FWPcapDBSqLite);
  inherited;
end;

procedure TPCAP2SQLite.SetAbort(const Value: Boolean);
begin
  if Assigned(FPcapUtils) then
    FPcapUtils.Abort := True;  
end;

end.
