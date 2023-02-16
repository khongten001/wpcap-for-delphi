unit wpcap.Offline.SQLite;

interface

uses wpcap.Offline,System.SysUtils,FireDAC.Stan.ExprFuncs, FireDAC.Phys.SQLiteWrapper.Stat,
  FireDAC.Phys.SQLiteDef, FireDAC.Stan.Intf, FireDAC.Stan.Option,System.Classes,
  FireDAC.Stan.Error, FireDAC.UI.Intf, FireDAC.Phys.Intf, FireDAC.Stan.Def,
  FireDAC.Stan.Pool, FireDAC.Stan.Async, FireDAC.Phys, FireDAC.VCLUI.Wait,
  FireDAC.Stan.Param, FireDAC.DatS, FireDAC.DApt.Intf, FireDAC.DApt,FireDAC.Comp.Script,
  FireDAC.Comp.Client, Data.DB, FireDAC.Comp.DataSet, FireDAC.Phys.SQLite;

type
  TPCAP2SQLite = class
  Strict private
    class var FDriverLink              : TFDPhysSQLiteDriverLink;
    class var FConnection              : TFDConnection;      
    class var FQuery                   : TFdQuery;    
    class var FPCAPOfflineCallBackEnd  : TPCAPOfflineCallBackEnd;
  private
    CONST SQL_TABLE = 'CREATE TABLE PACKETS (                                         '+sLineBreak+
                      '  NPACKET INTEGER PRIMARY KEY AUTOINCREMENT,                   '+sLineBreak+
                      '  PACKET_LEN INTEGER,                                          '+sLineBreak+
                      '  PACKET_DATE TEXT,                                            '+sLineBreak+
                      '  ETH_TYPE INTEGER,                                            '+sLineBreak+
                      '  ETH_ACRONYM TEXT,                                            '+sLineBreak+
                      '  MAC_SRC TEXT,                                                '+sLineBreak+
                      '  MAC_DST TEXT,                                                '+sLineBreak+
                      '  IPPROTO INTEGER,                                             '+sLineBreak+
                      '  PROTOCOL TEXT,                                               '+sLineBreak+
                      '  IP_SRC TEXT,                                                 '+sLineBreak+
                      '  IP_DST TEXT,                                                 '+sLineBreak+
                      '  PORT_SRC INTEGER,                                            '+sLineBreak+
                      '  PORT_DST NUMERIC,                                            '+sLineBreak+
                      '  PACKET_DATA BLOB                                             '+sLineBreak+
                      ');                                                             ';
           SQL_INDEX = 'CREATE UNIQUE INDEX PACKETS_NPACKET_IDX ON PACKETS (NPACKET);  ';
           SQL_INSERT = 'INSERT INTO PACKETS (PACKET_LEN, PACKET_DATE, ETH_TYPE, ETH_ACRONYM, MAC_SRC, MAC_DST, IPPROTO, PROTOCOL, IP_SRC, IP_DST, PORT_SRC, PORT_DST, PACKET_DATA) '+slineBreak+
                        'VALUES(:pLen,:pDate,:pEthType,:pEthAcr,:pMacSrc,:pMacDst,:pIpProto,:pProto,:pIpSrc,:pIpDst,:pPortSrc,:pPortDst,:pPacket)';

    class procedure DoPCAPOfflineCallBackPacket(const aPktData: PByte;
      aPktLen: LongWord; aPktDate: TDateTime; aEthType: Word;
      const atEthAcronym, aMacSrc, aMacDst: String; LaPProto: Word;
      const aIPProtoMapping, aIpSrc, aIpDst: String; aPortSrc, aPortDst: Word);
    class procedure DoPCAPOfflineCallBackEnd(const aFileName:String);
   public
    class procedure PCAP2SQLite(const aFilename,aFilenameDB:String;                              
                              aPCAPOfflineCallBackError   : TPCAPOfflineCallBackError;
                              aPCAPOfflineCallBackEnd     : TPCAPOfflineCallBackEnd;
                              aPCAPOfflineCallBackProgress: TPCAPOfflineCallBackProgress = nil); static;
  end;

implementation

{ TPCAP2SQLite }

class procedure TPCAP2SQLite.DoPCAPOfflineCallBackPacket(  const aPktData:PByte;aPktLen:LongWord;aPktDate:TDateTime;//Packet info
                                                aEthType:Word;const atEthAcronym,aMacSrc,aMacDst:String; // Eth info
                                                LaPProto:Word;const aIPProtoMapping,aIpSrc,aIpDst:String;aPortSrc,aPortDst:Word);
var LMemoryStream : TMemoryStream;                                                
begin 
  //       'VALUES(:pLen,:pDate,:pEthType,:pEthAcr,:pMacSrc,:pMacDst,:pIpProto,:pProto,:pIpSrc,:pIpDst,:pPortSrc,:pPortDst,:pPacket)';
  FQuery.ParamByName('pLen').AsInteger     := aPktLen;
  FQuery.ParamByName('pDate').AsString     := DateTimeToStr(aPktDate);
  FQuery.ParamByName('pEthType').AsInteger := aEthType;
  FQuery.ParamByName('pEthAcr').AsString   := atEthAcronym;
  FQuery.ParamByName('pMacSrc').AsString   := aMacSrc;
  FQuery.ParamByName('pMacDst').AsString   := aMacDst;
  FQuery.ParamByName('pIpProto').AsInteger := LaPProto;
  FQuery.ParamByName('pProto').AsString    := aIPProtoMapping;
  FQuery.ParamByName('pIpSrc').AsString    := aIpSrc;  
  FQuery.ParamByName('pIpDst').AsString    := aIpDst;  
  FQuery.ParamByName('pPortSrc').AsInteger := aPortSrc;  
  FQuery.ParamByName('pPortDst').AsInteger := aPortDst;  
  FQuery.ParamByName('pPacket').DataType   := ftOraBlob;
  LMemoryStream := TMemoryStream.Create; 
  Try
    LMemoryStream.Write(aPktData,aPktLen);
    FQuery.ParamByName('pPacket').LoadFromStream(LMemoryStream,ftOraBlob);
    FQuery.ExecSQL;
  Finally
    FreeAndNil(LMemoryStream);
  End;  
end;

class procedure TPCAP2SQLite.DoPCAPOfflineCallBackEnd(const aFileName:String);
begin
  FConnection.Commit;
  FConnection.Connected := False;
  FPCAPOfflineCallBackEnd(aFileName)
end;

class procedure TPCAP2SQLite.PCAP2SQLite( const aFilename, aFilenameDB: String;
                                          aPCAPOfflineCallBackError: TPCAPOfflineCallBackError;
                                          aPCAPOfflineCallBackEnd: TPCAPOfflineCallBackEnd;
                                          aPCAPOfflineCallBackProgress: TPCAPOfflineCallBackProgress);
var LTable       : TFdScript;
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
  FPCAPOfflineCallBackEnd := aPCAPOfflineCallBackEnd;
  {Create database}
  FDriverLink := TFDPhysSQLiteDriverLink.Create( nil );
  Try
    FConnection := TFDConnection.Create( nil );
    try
      FConnection.Params.Values['DriverID'] := 'SQLite';
      FConnection.Params.Values['Database'] := aFilenameDB;
      Try
        FConnection.Connected := True;
        {Create schema}      
        LTable := TFdScript.Create( nil );
        try                                 
          Try
            LTable.Connection := FConnection;
            with LTable.SQLScripts do begin
              Clear;
              with Add do begin
                Name := 'root';
                SQL.Add('@first');  // explicitly call 'first' script
                SQL.Add('@second'); // explicitly call 'second' script
              end;
              with Add do begin
                Name := 'first';
                SQL.Add(SQL_TABLE);
              end;
              with Add do begin
                Name := 'second';
                SQL.Add(SQL_INDEX);
              end;
            end;      
           LTable.ValidateAll;
           LTable.ExecuteAll;
           
           FQuery := TFDQuery.Create(nil);
           Try
             FQuery.Connection := FConnection;
             FQuery.SQL.Text   := SQL_INSERT;
             FConnection.StartTransaction;
             
             AnalyzePCAPOffline(aFileName,DoPCAPOfflineCallBackPacket,aPCAPOfflineCallBackError,DoPCAPOfflineCallBackEnd,aPCAPOfflineCallBackProgress);          
           finally             
             
             FreeAndNil(FQuery);
           end;
           
           FConnection.Connected := False;
          except on E: Exception do    
            begin
              FConnection.Connected := False;
              DeleteFile(aFilenameDB);
              aPCAPOfflineCallBackError(aFilenameDB,Format('Exception create table %s',[E.Message]));
            end;
          end;          
        finally
          LTable.Free;
        end;
      except on E: Exception do
        begin
          FConnection.Connected := False;
          DeleteFile(aFilenameDB);
          aPCAPOfflineCallBackError(aFilenameDB,Format('Exception create database %s',[E.Message]));
        end;
      end;    
    finally
      FreeAndNil(FConnection);
    end;  
  finally
    FreeAndNil(FDriverLink)
  end;    
end;

end.
