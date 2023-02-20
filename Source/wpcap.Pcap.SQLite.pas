unit wpcap.Pcap.SQLite;

interface

uses wpcap.Pcap,System.SysUtils,wpcap.DB.SQLite,wpcap.Packet;

type
  TPCAP2SQLite = class
  Strict private
    class var FPCAPCallBackEnd  : TPCAPCallBackEnd;
    class var FPCAPCallBackError: TPCAPCallBackError;
    class var FWPcapDBSqLite    : TWPcapDBSqLite;
  private
    class procedure DoPCAPCallBackPacket(const aInternalPacket : PTInternalPacket);
    class procedure DoPCAPCallBackEnd(const aFileName:String);
    class procedure DoPCAPCallBackError(const aFileName, aError: String); 
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
    class procedure PCAP2SQLite(const aFilename,aFilenameDB,aFilter:String;                              
                              aPCAPCallBackError   : TPCAPCallBackError;
                              aPCAPCallBackEnd     : TPCAPCallBackEnd;
                              aPCAPCallBackProgress: TPCAPCallBackProgress = nil); static;
  end;

implementation

{ TPCAP2SQLite }

class procedure TPCAP2SQLite.DoPCAPCallBackPacket(const aInternalPacket : PTInternalPacket);
begin
  FWPcapDBSqLite.InsertPacket(aInternalPacket);
end;

class procedure TPCAP2SQLite.DoPCAPCallBackError(const aFileName,aError:String);
begin
  FWPcapDBSqLite.RollbackAndClose(True);    
  FPCAPCallBackError(aFileName,aError)
end;

class procedure TPCAP2SQLite.DoPCAPCallBackEnd(const aFileName:String);
begin
  FWPcapDBSqLite.CommitAndClose;
  FPCAPCallBackEnd(aFileName)
end;

class procedure TPCAP2SQLite.PCAP2SQLite( const aFilename, aFilenameDB,aFilter: String;
                                          aPCAPCallBackError: TPCAPCallBackError;
                                          aPCAPCallBackEnd: TPCAPCallBackEnd;
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

  {Create database}
  FWPcapDBSqLite := TWPcapDBSqLite.Create;
  Try
    Try
      FWPcapDBSqLite.CreateDatabase(aFilenameDB);
      Try
        TPCAPUtils.AnalyzePCAPOffline(aFileName,afilter,DoPCAPCallBackPacket,DoPCAPCallBackError,DoPCAPCallBackEnd,aPCAPCallBackProgress);          
      except on E: Exception do
        DoPCAPCallBackError(aFilenameDB,Format('Exception analyze PCAP %s',[E.Message]));
      end;    
    except on E: Exception do
      DoPCAPCallBackError(aFilenameDB,Format('Exception create database %s',[E.Message]));
    end;    
  finally
    FreeAndNil(FWPcapDBSqLite);
  end;    
end;

end.
