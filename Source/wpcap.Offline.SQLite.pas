unit wpcap.Offline.SQLite;

interface

uses wpcap.Offline,System.SysUtils,wpcap.DB.SQLite;

type
  TPCAP2SQLite = class
  Strict private
    class var FPCAPOfflineCallBackEnd  : TPCAPOfflineCallBackEnd;
    class var FPCAPOfflineCallBackError: TPCAPOfflineCallBackError;
    class var FDBSqLite                : TDBSqLite;
  private
    class procedure DoPCAPOfflineCallBackPacket(const aPktData: PByte;
      aPktLen: LongWord; aPktDate: TDateTime; aEthType: Word;
      const atEthAcronym, aMacSrc, aMacDst: String; aIPProto: Word;
      const aIPProtoMapping, aIpSrc, aIpDst: String; aPortSrc, aPortDst: Word);
    class procedure DoPCAPOfflineCallBackEnd(const aFileName:String);
    class procedure DoPCAPOfflineCallBackError(const aFileName, aError: String); 
   public
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
    /// This procedure converts an offline packet capture file to an SQLite database using a specified set of callbacks. 
    /// The specified callbacks are responsible for processing packets, handling errors, and reporting progress to the user. 
    /// The procedure reads the capture file packet by packet, inserting the packets into the specified SQLite database. 
    //  The progress callback is optional and can be used to report progress to the user during long-running capture file analysis.
    ///</remarks>   
    class procedure PCAP2SQLite(const aFilename,aFilenameDB,aFilter:String;                              
                              aPCAPOfflineCallBackError   : TPCAPOfflineCallBackError;
                              aPCAPOfflineCallBackEnd     : TPCAPOfflineCallBackEnd;
                              aPCAPOfflineCallBackProgress: TPCAPOfflineCallBackProgress = nil); static;
  end;

implementation

{ TPCAP2SQLite }

class procedure TPCAP2SQLite.DoPCAPOfflineCallBackPacket(  const aPktData:PByte;aPktLen:LongWord;aPktDate:TDateTime;//Packet info
                                                aEthType:Word;const atEthAcronym,aMacSrc,aMacDst:String; // Eth info
                                                aIPProto:Word;const aIPProtoMapping,aIpSrc,aIpDst:String;aPortSrc,aPortDst:Word);
begin
  FDBSqLite.InsertPacket(aPktData,aPktLen,aPktDate,aEthType,atEthAcronym, aMacSrc, aMacDst,aIPProto,aIPProtoMapping, aIpSrc, aIpDst,aPortSrc, aPortDst);
end;

class procedure TPCAP2SQLite.DoPCAPOfflineCallBackError(const aFileName,aError:String);
begin
  FDBSqLite.RollbackAndClose(True);    
  FPCAPOfflineCallBackError(aFileName,aError)
end;

class procedure TPCAP2SQLite.DoPCAPOfflineCallBackEnd(const aFileName:String);
begin
  FDBSqLite.CommitAndClose;
  FPCAPOfflineCallBackEnd(aFileName)
end;

class procedure TPCAP2SQLite.PCAP2SQLite( const aFilename, aFilenameDB,aFilter: String;
                                          aPCAPOfflineCallBackError: TPCAPOfflineCallBackError;
                                          aPCAPOfflineCallBackEnd: TPCAPOfflineCallBackEnd;
                                          aPCAPOfflineCallBackProgress: TPCAPOfflineCallBackProgress);
begin
  if not Assigned(aPCAPOfflineCallBackError) then
  begin
    raise Exception.Create('Callback event for error not assigned');
  end;  

  if aFilenameDB.Trim.IsEmpty then
  begin
    aPCAPOfflineCallBackError(aFilenameDB,'filename database is empty');
    Exit;    
  end;

  if FileExists(aFilenameDB) then
  begin
    aPCAPOfflineCallBackError(aFilenameDB,'filename already exists');
    Exit;    
  end;
  {Backup event}
  FPCAPOfflineCallBackError := aPCAPOfflineCallBackError;
  FPCAPOfflineCallBackEnd   := aPCAPOfflineCallBackEnd;

  {Create database}
  FDBSqLite := TDBSqLite.Create;
  Try
    Try
      FDBSqLite.CreateDatabase(aFilenameDB);
      Try
        AnalyzePCAPOffline(aFileName,afilter,DoPCAPOfflineCallBackPacket,DoPCAPOfflineCallBackError,DoPCAPOfflineCallBackEnd,aPCAPOfflineCallBackProgress);          
      except on E: Exception do
        DoPCAPOfflineCallBackError(aFilenameDB,Format('Exception analyze PCAP %s',[E.Message]));
      end;    
    except on E: Exception do
      DoPCAPOfflineCallBackError(aFilenameDB,Format('Exception create database %s',[E.Message]));
    end;    
  finally
    FreeAndNil(FDBSqLite);
  end;    
end;

end.
