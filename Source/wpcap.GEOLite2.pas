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

unit wpcap.GEOLite2;

interface

uses
  wpcap.Types, System.Generics.Collections, FireDAC.Phys, FireDAC.Phys.SQLite,
  FireDAC.Comp.Client, FireDac.Stan.Param, wpcap.DB.SQLite, winApi.Windows,wpcap.IpUtils,
  System.Classes, FireDAC.Stan.Option, FireDAC.Stan.Intf, System.SysUtils,IdGlobal, System.NetEncoding,
  wpcap.BufferUtils, wpcap.Packet, Data.DB, System.Threading,IdGlobalProtocols;

type
  TGeoLiteDBType = (gbtASNv4,gbtASNv6,gbtLocationv4,gbtLocationv6);
  
  TOnImportTerminate= Procedure (const aAborted:Boolean)of object;
  TOnProgressImport = procedure (aKink : TGeoLiteDBType;aProgress:Integer;aMax:Integer;var aAbort:Boolean) of object;
  /// <summary>
  /// TWpcapGEOLITE class, inheriting from TWPcapDBSqLite, provides additional functionality for handling geolocation data using a SQLite database.
  /// </summary>
  TWpcapGEOLITE = Class(TWPcapDBSqLite) 
  Strict private
    /// <summary>
    /// Private field FQueryCache stores a dictionary of cached results from queries to the database.
    /// </summary>  
    var FQueryCache         : TDictionary<string, TRecordGeoIP>; 
    var FFDGetASNByIP       : TFDQuery;
    var FFDGetLocationByIP  : TFDQuery;    
    var FImportAborted      : Boolean;
    var FOnProgressImport   : TOnProgressImport;
    var FOnImportCompleate : TOnImportTerminate;
    
  protected
    /// <summary>
    /// Overrides the GetSQLScriptDatabaseSchema method to provide the SQL script for creating the database schema for the geolocation data.
    /// </summary>
    function GetSQLScriptDatabaseSchema: String;override;
    /// <summary>
    /// Overrides the InitConnection method to initialize the database connection and create the necessary tables if they do not exist.
    /// </summary>    
    procedure InitConnection;override;    
  private
    procedure DoOnProgressImport(aKink: TGeoLiteDBType; aProgress,aMax: Integer;var aAbort:Boolean);
  public
    destructor Destroy; override;
    /// <summary>
    /// Public method LoadGeoLiteCSV loads geolocation data from the specified CSV files into the database.
    /// </summary>  
    procedure LoadGeoLiteCSVAsync(const aFileNameASNv4, aFileNameASNv6,aFileLocationV4, aFileLocationV6, aFileOutput: String);
    
    /// <summary>
    /// Public method GetGeoIPByIp queries the database for geolocation data for the specified IP address and returns it in the specified structure.
    /// </summary>    
    procedure GetGeoIPByIp(const aIP: String; aGeoStructure: PTRecordGeoIP);
    property OnProgressImport : TOnProgressImport   read FOnProgressImport  write FOnProgressImport;
    property OnImportCompleate: TOnImportTerminate  read FOnImportCompleate write FOnImportCompleate;       
  End;


type
  TImportThreadGeoLite = class(TThread)
  private
    var FConnection       : TFDConnection;
    var FFDInsertQuery    : TFDQuery;
    var FFileNameASNv4    : string;
    var FFileNameASNv6    : string;
    var FFileLocationV4   : string;
    var FFileLocationV6   : string;
    var FFileOutput       : string;
    var FImportAborted    : Boolean;
    var FOnProgressImport : TOnProgressImport;
    var FOnImportCompleate: TOnImportTerminate;    
    var FLastPercProg     : Integer;
    var FFormatSettings   : TFormatSettings;
  protected
    procedure Execute; override;
  private
     /// <summary>
    /// Private method ParseASNBlocksRow parses a single row of data from the ASN blocks file and inserts it into the database.
    /// </summary>
    procedure ParseASNBlocksRow(const aRow: string);
    /// <summary>
    /// Private method GetSubnetBounds returns the lower and upper bounds of the subnet for the specified IP address.
    /// </summary>
    function GetSubnetBounds(const AIPAddress: string): TArray<Uint32>;
    /// <summary>
    /// Private method CIDRToSubnetMask returns the subnet mask for the specified CIDR prefix length.
    /// </summary>
    function CIDRToSubnetMask(const ACIDR: Integer): UInt32;  
    procedure LoadGeoLiteCSV(const aFileNameASNv4,aFileNameASNv6,aFileLocationV4,aFileLocationV6,aFileOutput:String);
    procedure ParseLocationBlocksRow(const aRow: string);
    function GetSubnetBoundsIPv6(const AIPAddress: string): TArray<UInt64>;
    procedure ParseASNBlocksRowIPv6(const aRow: string);
    procedure ParseLocationBlocksRowIpv6(const aRow: string);
  public
    constructor Create(const FileNameASNv4, FileNameASNv6, FileLocationV4, FileLocationV6, FileOutput: string;AConnectionParams:TFDConnectionDefParams);
    destructor Destroy; override;
    property OnProgressImport : TOnProgressImport   read FOnProgressImport  write FOnProgressImport;
    property OnImportCompleate: TOnImportTerminate  read FOnImportCompleate write FOnImportCompleate;   

  end;


implementation

function TWpcapGEOLITE.GetSQLScriptDatabaseSchema: String;
{$REGION 'SQL Scrit'}
    CONST SQL_TABLE = 'CREATE TABLE ASN (                          '+sLineBreak+
                      '  ID_ASN INTEGER PRIMARY KEY AUTOINCREMENT, '+sLineBreak+
                      '  IP_START INTEGER,                         '+sLineBreak+
                      '  IP_END INTEGER,                           '+sLineBreak+                      
                      '  ASN_NUMBER TEXT,                          '+sLineBreak+
                      '  ORGANIZATION TEXT,                        '+sLineBreak+
                      '  IS_IPV6 NUMBER                            '+sLineBreak+
                      ');                                          ';
                      
//           SQL_INDEX_1 = 'CREATE UNIQUE INDEX ASN_IP_START_IDX ON ASN (IP_START);  ';
  //         SQL_INDEX_2 = 'CREATE UNIQUE INDEX ASN_IP_END_IDX ON ASN (IP_END);  ';  
           SQL_INDEX   = 'CREATE UNIQUE INDEX ASN_UQ_IDX ON ASN (IP_START,IP_END,IS_IPV6);  ';

           SQL_LOCATION = ' CREATE TABLE LOCATION (                                '+sLineBreak+
                          '   ID INTEGER PRIMARY KEY AUTOINCREMENT,                '+sLineBreak+
                          '   IP_START INTEGER,                                    '+sLineBreak+
                          '   IP_END INTEGER,                                      '+sLineBreak+    
                          '   GEONAME_ID INTEGER DEFAULT NULL,                     '+sLineBreak+
                          '   REGISTERED_COUNTRY_GEONAME_ID INTEGER DEFAULT NULL,  '+sLineBreak+
                          '   REPRESENTED_COUNTRY_GEONAME_ID INTEGER DEFAULT NULL, '+sLineBreak+
                          '   IS_ANONYMOUS_PROXY INTEGER DEFAULT NULL,             '+sLineBreak+
                          '   IS_SATELLITE_PROVIDER INTEGER DEFAULT NULL,          '+sLineBreak+
                          '   POSTAL_CODE TEXT DEFAULT NULL,                       '+sLineBreak+
                          '   LATITUDE FLOAT DEFAULT NULL,                         '+sLineBreak+
                          '   LONGITUDE FLOAT DEFAULT NULL,                        '+sLineBreak+
                          '   IS_IPV6 NUMBER ,                                      '+sLineBreak+                          
                          '   ACCURACY_RADIUS INTEGER DEFAULT NULL                 '+sLineBreak+
                        ');                                                     ';
    //       SQL_INDEX_3 = 'CREATE UNIQUE INDEX LOCATION_IP_START_IDX ON LOCATION (IP_START);  ';
    //       SQL_INDEX_4 = 'CREATE UNIQUE INDEX LOCATION_IP_END_IDX ON LOCATION (IP_END);  ';  
           SQL_INDEX_5 = 'CREATE UNIQUE INDEX LOCATION_UQ_IDX ON ASN (IP_START,IP_END,IS_IPV6);  ';           
{$ENDREGION}
begin

  Result := SQL_TABLE    +sLineBreak+
            SQL_INDEX    +sLineBreak+
            //SQL_INDEX_1  +sLineBreak+
       //     SQL_INDEX_2  +sLineBreak+
            SQL_LOCATION +sLineBreak+
     //       SQL_INDEX_3  +sLineBreak+
    //        SQL_INDEX_4  +sLineBreak+
            SQL_INDEX_5;
end;

Procedure TWpcapGEOLITE.DoOnProgressImport(aKink : TGeoLiteDBType;aProgress:Integer;aMax:Integer;var aAbort:Boolean);
begin
  if Assigned(FOnProgressImport) then
    FOnProgressImport(aKink,aProgress,aMax,aAbort);
end;

Procedure TWpcapGEOLITE.GetGeoIPByIp(const aIP:String;aGeoStructure:PTRecordGeoIP);
CONST MAX_CACHE_SIZE = 3000;
var aGeoCache : TRecordGeoIP;
begin
  if aIP.Trim.IsEmpty then Exit;

  if not Assigned(FQueryCache) then
    FQueryCache := TDictionary<string, TRecordGeoIP>.Create;


  if FQueryCache.TryGetValue(aIP,aGeoCache) then
  begin
    aGeoStructure.ASNumber       := aGeoCache.ASNumber;
    aGeoStructure.ASOrganization := aGeoCache.ASOrganization;
    aGeoStructure.Latitude       := aGeoCache.Latitude;
    aGeoStructure.Longitude      := aGeoCache.Longitude;    
    Exit;
  end;
      
  if not FFDGetASNByIP.Prepared then
    FFDGetASNByIP.Prepare;
  FFDGetASNByIP.Close;
  if aIP.Contains('.') then
  begin
    FFDGetASNByIP.ParamByName('pIP').AsInteger     := IPv4ToUInt32(aIP);  
    FFDGetASNByIP.ParamByName('pIpType').AsInteger := 0;
  end
  else
  begin
    FFDGetASNByIP.ParamByName('pIP').Value          := IPv6ToUInt64(aIP);  
    FFDGetASNByIP.ParamByName('pIpType').AsInteger  := 1;  
  end;
  
  FFDGetASNByIP.Open;  
  if FFDGetASNByIP.RecordCount > 0 then
  begin
    aGeoStructure.ASNumber       := FFDGetASNByIP.FieldByName('ASN_NUMBER').AsString; 
    aGeoStructure.ASOrganization := FFDGetASNByIP.FieldByName('ORGANIZATION').AsString;
    aGeoCache.ASNumber           := FFDGetASNByIP.FieldByName('ASN_NUMBER').AsString; 
    aGeoCache.ASOrganization     := FFDGetASNByIP.FieldByName('ORGANIZATION').AsString;
  end
  else
  begin
    aGeoCache.ASNumber       := String.Empty;
    aGeoCache.ASOrganization := String.Empty;
  end;

  if not FFDGetLocationByIP.Prepared then
    FFDGetLocationByIP.Prepare;

  FFDGetLocationByIP.Close;
  if aIP.Contains('.') then
  begin
    FFDGetLocationByIP.ParamByName('pIP').AsInteger     := IPv4ToUInt32(aIP);  
    FFDGetLocationByIP.ParamByName('pIpType').AsInteger := 0;
  end
  else
  begin
    FFDGetLocationByIP.ParamByName('pIP').Value          := IPv6ToUInt64(aIP);  
    FFDGetLocationByIP.ParamByName('pIpType').AsInteger  := 1;  
  end;
  
  FFDGetLocationByIP.Open;

  if FFDGetLocationByIP.RecordCount > 0 then
  begin
    aGeoStructure.Latitude   := FFDGetLocationByIP.FieldByName('LATITUDE').AsFloat; 
    aGeoStructure.Longitude  := FFDGetLocationByIP.FieldByName('LONGITUDE').AsFloat;
    aGeoCache.Latitude       := aGeoStructure.Latitude;
    aGeoCache.Longitude      := aGeoStructure.Longitude;
    FQueryCache.TryAdd(aIP,aGeoCache);
  end
  else
  begin
    aGeoCache.Location  := String.Empty;
    aGeoCache.Latitude  := 0;
    aGeoCache.Longitude := 0;
    FQueryCache.TryAdd(aIP,aGeoCache);
  end;      

 { if FQueryCache.Count > MAX_CACHE_SIZE then
    FQueryCache.Remove();
  }
  FFDGetASNByIP.Close;
end;


procedure TWpcapGEOLITE.InitConnection;
begin
  inherited;
  FFDGetASNByIP                                         := TFDQuery.Create(nil);
  FFDGetASNByIP.SQL.Text                                := 'SELECT * FROM ASN WHERE :pIP BETWEEN IP_START AND IP_END AND IS_IPV6 = :pIpType';
  FFDGetASNByIP.ParamByName('pIP').DataType             := ftInteger;
  FFDGetASNByIP.ParamByName('pIpType').DataType         := ftInteger;
  FFDGetASNByIP.FetchOptions.Mode                       := fmAll;
  FFDGetASNByIP.FetchOptions.RowsetSize                 := 1;    
  FFDGetASNByIP.FetchOptions.LiveWindowFastFirst        := True;
  FFDGetASNByIP.CachedUpdates                           := True; 
  FFDGetASNByIP.Connection                              := FConnection;
  
  FFDGetLocationByIP                                    := TFDQuery.Create(nil);
  FFDGetLocationByIP.SQL.Text                           := 'SELECT * FROM LOCATION WHERE :pIP BETWEEN IP_START AND IP_END AND IS_IPV6 = :pIpType';
  FFDGetLocationByIP.ParamByName('pIP').DataType        := ftInteger;
  FFDGetLocationByIP.ParamByName('pIpType').DataType    := ftInteger;
  
  FFDGetLocationByIP.FetchOptions.Mode                  := fmAll;
  FFDGetLocationByIP.FetchOptions.RowsetSize            := 1;    
  FFDGetLocationByIP.FetchOptions.LiveWindowFastFirst   := True;
  FFDGetLocationByIP.CachedUpdates                      := True; 
  FFDGetLocationByIP.Connection                         := FConnection;    
  
  Connection.Params.Values['Synchronous']               := 'OFF'; 
  Connection.Params.Values['Cache']                     := 'True'; 
  Connection.Params.Values['JournalMode']               := 'MEMORY';
  Connection.Params.Values['PageSize']                  := '20480';

end;

procedure TWpcapGEOLITE.LoadGeoLiteCSVAsync(const aFileNameASNv4,aFileNameASNv6,aFileLocationV4,aFileLocationV6,aFileOutput:String);
var LConnectionParams : TFDConnectionDefParams;
    LThreadImport     : TImportThreadGeoLite;
begin
  if aFileOutput.Trim.IsEmpty then
      raise Exception.CreateFmt('Invalid database name %S',[aFileOutput]);  
  if FileExists(aFileOutput) then
    if not DeleteFile(aFileOutput) then
      raise Exception.CreateFmt('Unable delete old database file %S',[aFileOutput]);

  FImportAborted := False;
  ForceDirectories(ExtractFilePath(aFileOutput));         
  CreateDatabase(aFileOutput); 
  Connection.Close; 
  LConnectionParams := FConnection.Params;

  LThreadImport                    := TImportThreadGeoLite.Create(aFileNameASNv4, aFileNameASNv6, aFileLocationV4, aFileLocationV6, aFileOutput,LConnectionParams);
  LThreadImport.OnProgressImport   := DoOnProgressImport;
  LThreadImport.OnImportCompleate  := OnImportCompleate; 
  LThreadImport.FreeOnTerminate    := True;
  LThreadImport.Start;
end;

destructor TWpcapGEOLITE.Destroy;
begin
  FreeAndNil(FFDGetASNByIP);
  FreeAndNil(FFDGetLocationByIP);
  inherited;
end;

{TImportThreadGeoLite}

constructor TImportThreadGeoLite.Create(const FileNameASNv4, FileNameASNv6, FileLocationV4, FileLocationV6, FileOutput: string;AConnectionParams:TFDConnectionDefParams);
begin
  inherited Create(True);
  FConnection               := TFDConnection.Create(nil);
  FConnection.Params.Assign(AConnectionParams);   
  FFileNameASNv4                   := FileNameASNv4;
  FFileNameASNv6                   := FileNameASNv6;
  FFileLocationV4                  := FileLocationV4;
  FFileLocationV6                  := FileLocationV6;
  FFileOutput                      := FileOutput;
  FFDInsertQuery                   := TFDQuery.Create(nil);
  FFDInsertQuery.Connection        := FConnection;
  FFDInsertQuery.CachedUpdates     := True;   
  FFormatSettings                  := TFormatSettings.Create;
  FFormatSettings.DecimalSeparator := '.';
  
end;

procedure TImportThreadGeoLite.Execute;
begin
  LoadGeoLiteCSV(FFileNameASNv4,FFileNameASNv6,FFileLocationV4,FFileLocationV6,FFileOutput)
end;  

procedure TImportThreadGeoLite.LoadGeoLiteCSV(const aFileNameASNv4,aFileNameASNv6,aFileLocationV4,aFileLocationV6,aFileOutput:String);
var LStringListImport: TStringList;
    LRow          : string;
    LCount        : Integer;
    LMaxRow       : Integer;

    Procedure SyncDoOnProgressImport(aKink : TGeoLiteDBType;aProgress:Integer;aMax:Integer);
    var LPercProg : integer;
    begin
      LPercProg := Trunc( (aProgress * 100) / aMax);

      if (LPercProg Mod 5 = 0) and (FLastPercProg <> LPercProg) then                
      begin
        FLastPercProg := LPercProg;
        TThread.Synchronize(nil,
          procedure
          begin
            if Assigned(FOnProgressImport) then          
              FOnProgressImport(aKink,aProgress,aMax,FImportAborted);
          end);
      end;
    end;
begin
  LStringListImport := TStringList.Create;
  Try
    try
      FConnection.Open;    
      FConnection.StartTransaction;
      Try
        Try
          if FileExists(aFileNameASNv4) then
          begin
            FFDInsertQuery.SQL.Text := 'INSERT INTO ASN (IP_START,IP_END,ASN_NUMBER,ORGANIZATION,IS_IPV6) VALUES (:pIPStart,:pIPEnd,:pASN,:pOrganizzation,0)';

            LStringListImport.LoadFromFile(aFileNameASNv4);
            LCount   := 0;
            LMaxRow  := LStringListImport.Count;
            SyncDoOnProgressImport(gbtASNv4,LCount,LMaxRow);
            for LRow in LStringListImport do
            begin
              Inc(LCount);
              if LCount = 1 then Continue;//Header
              if FImportAborted then Exit;

              ParseASNBlocksRow(LRow);
              SyncDoOnProgressImport(gbtASNv4,LCount,LMaxRow);
            end;      
          end;

          if FileExists(aFileNameASNv6) then
          begin
            FFDInsertQuery.SQL.Text := 'INSERT INTO ASN (IP_START,IP_END,ASN_NUMBER,ORGANIZATION,IS_IPV6) VALUES (:pIPStart,:pIPEnd,:pASN,:pOrganizzation,1)';
            LStringListImport.LoadFromFile(aFileNameASNv6);
            LCount   := 0;
            LMaxRow  := LStringListImport.Count;  
              
            SyncDoOnProgressImport(gbtASNv6,LCount,LMaxRow);            
            for LRow in LStringListImport do
            begin
              Inc(LCount);
              if LCount = 1 then Continue;//Header
              if FImportAborted then Exit;
              SyncDoOnProgressImport(gbtASNv6,LCount,LMaxRow);            
              ParseASNBlocksRowIPv6(LRow);
            end;    
          end;

          if FileExists(aFileLocationV4) then
          begin
            FFDInsertQuery.SQL.Text := 'INSERT INTO Location (IS_IPV6,IP_START,IP_END,GEONAME_ID,REGISTERED_COUNTRY_GEONAME_ID,REPRESENTED_COUNTRY_GEONAME_ID,IS_ANONYMOUS_PROXY,IS_SATELLITE_PROVIDER,POSTAL_CODE,LATITUDE,LONGITUDE,ACCURACY_RADIUS) ' + sLineBreak+
                                       'VALUES (0,:pIPStart,:pIPEnd,:pGeoNameID,:pRegCountryGeoNameID,:pRepCountryGeoNameID,:pIsAnonymousProxy,:pIsSatelliteProvider,:pPostalCode,:pLatitude,:pLongitude,:pAccuracyRadius)';          
            LStringListImport.LoadFromFile(aFileLocationV4);
            LCount   := 0;
            LMaxRow  := LStringListImport.Count;    
            SyncDoOnProgressImport(gbtLocationv4,LCount,LMaxRow);              
            for LRow in LStringListImport do
            begin
              Inc(LCount);
              if LCount = 1 then Continue;//Header
              if FImportAborted then Exit;
               SyncDoOnProgressImport(gbtLocationv4,LCount,LMaxRow);                        
               ParseLocationBlocksRow(LRow);
            end; 
          end;    

          if FileExists(aFileLocationV6) then
          begin
            FFDInsertQuery.SQL.Text := 'INSERT INTO Location (IS_IPV6,IP_START,IP_END,GEONAME_ID,REGISTERED_COUNTRY_GEONAME_ID,REPRESENTED_COUNTRY_GEONAME_ID,IS_ANONYMOUS_PROXY,IS_SATELLITE_PROVIDER,POSTAL_CODE,LATITUDE,LONGITUDE,ACCURACY_RADIUS) ' + sLineBreak+
                             'VALUES (1,:pIPStart,:pIPEnd,:pGeoNameID,:pRegCountryGeoNameID,:pRepCountryGeoNameID,:pIsAnonymousProxy,:pIsSatelliteProvider,:pPostalCode,:pLatitude,:pLongitude,:pAccuracyRadius)';          

            LStringListImport.LoadFromFile(aFileLocationV6);
            LCount   := 0;
            LMaxRow  := LStringListImport.Count; 
            SyncDoOnProgressImport(gbtLocationv4,LCount,LMaxRow);
            for LRow in LStringListImport do
            begin
              Inc(LCount);
              if LCount = 1 then Continue;//Header
              if FImportAborted then Exit;
               SyncDoOnProgressImport(gbtLocationv6,LCount,LMaxRow);                                    
               ParseLocationBlocksRowIPv6(LRow);
            end;         
          end;
        Except on E: Exception do
          begin
            FImportAborted := True;
            if FConnection.InTransaction then
              FConnection.Rollback;
            raise Exception.CreateFmt('Error Import database %s',[e.Message]);
          end;
        End;
      finally
        if not FImportAborted then
          FConnection.Commit
        else if FConnection.InTransaction then
          FConnection.Rollback    
      end;
    finally
      FreeAndNIl(LStringListImport);
    end;
  finally
    LStringListImport.Free;

    TThread.Synchronize(nil,
      procedure
      begin
        if Assigned(OnImportCompleate) then
          OnImportCompleate(FImportAborted);
      end);     
  end; 
end;

procedure TImportThreadGeoLite.ParseLocationBlocksRowIpv6(const aRow: string);
var LFields              : TArray<string>;
    LNetwork             : string;
    LGeoNameID           : Integer;
    LRegCountryGeoNameID : Integer;
    LRepCountryGeoNameID : Integer;
    LIsAnonymousProxy    : Integer;
    LIsSatelliteProvider : Integer;
    LPostalCode          : string;
    LLatitude            : Double;
    LLongitude           : Double;
    LAccuracyRadius      : Integer;
    LIpRange             : TArray<UInt64>;
begin
  LFields := aRow.Split([',']);

  if Length(LFields) < 10 then
    raise Exception.Create('Invalid row format');

  LNetwork             := LFields[0].Trim;
  LGeoNameID           := StrToIntDef(LFields[1].Trim,0);
  LRegCountryGeoNameID := StrToIntDef(LFields[2].Trim,0);
  LRepCountryGeoNameID := StrToIntDef(LFields[3].Trim,0);
  LIsAnonymousProxy    := StrToIntDef(LFields[4].Trim,0);
  LIsSatelliteProvider := StrToIntDef(LFields[5].Trim,0);
  LPostalCode          := LFields[6].Trim;
  LLatitude            := StrToFloatDef(LFields[7].Trim,0,FFormatSettings);
  LLongitude           := StrToFloatDef(LFields[8].Trim,0,FFormatSettings);
  LAccuracyRadius      := StrToIntDef(LFields[9].Trim,0);
  LIpRange             := GetSubnetBoundsIpv6(LNetwork);

  if not FFDInsertQuery.Prepared then
  begin
    FFDInsertQuery.ParamByName('pGeoNameID').DataType           := ftInteger;
    FFDInsertQuery.ParamByName('pRegCountryGeoNameID').DataType := ftInteger;
    FFDInsertQuery.ParamByName('pRepCountryGeoNameID').DataType := ftInteger;
    FFDInsertQuery.ParamByName('pIsAnonymousProxy').DataType    := ftInteger;
    FFDInsertQuery.ParamByName('pIsSatelliteProvider').DataType := ftInteger;
    FFDInsertQuery.ParamByName('pPostalCode').DataType          := ftString;
    FFDInsertQuery.ParamByName('pLatitude').DataType            := ftFloat;
    FFDInsertQuery.ParamByName('pLongitude').DataType           := ftFloat;
    FFDInsertQuery.ParamByName('pAccuracyRadius').DataType      := ftInteger;
    FFDInsertQuery.ParamByName('pIPStart').DataType             := ftLargeint;
    FFDInsertQuery.ParamByName('pIPEnd').DataType               := ftLargeint;
    FFDInsertQuery.Prepare;
  end;

  Try
    FFDInsertQuery.ParamByName('pGeoNameID').AsInteger           := LGeoNameID;
    FFDInsertQuery.ParamByName('pRegCountryGeoNameID').AsInteger := LRegCountryGeoNameID;
    FFDInsertQuery.ParamByName('pRepCountryGeoNameID').AsInteger := LRepCountryGeoNameID;
    FFDInsertQuery.ParamByName('pIsAnonymousProxy').AsInteger    := LIsAnonymousProxy;
    FFDInsertQuery.ParamByName('pIsSatelliteProvider').AsInteger := LIsSatelliteProvider;
    FFDInsertQuery.ParamByName('pPostalCode').AsString           := LPostalCode;
    FFDInsertQuery.ParamByName('pLatitude').AsFloat              := LLatitude;
    FFDInsertQuery.ParamByName('pLongitude').AsFloat             := LLongitude;
    FFDInsertQuery.ParamByName('pAccuracyRadius').AsInteger      := LAccuracyRadius;
    FFDInsertQuery.ParamByName('pIPStart').AsLargeInt            := LIpRange[0];
    FFDInsertQuery.ParamByName('pIPEnd').AsLargeInt              := LIpRange[1];
    FFDInsertQuery.ExecSQL;
  finally
    SetLength(LIpRange, 0);
  end;
end;


procedure TImportThreadGeoLite.ParseLocationBlocksRow(const aRow: string);
var LFields              : TArray<string>;
    LNetwork             : string;
    LGeoNameID           : Integer;
    LRegCountryGeoNameID : Integer;
    LRepCountryGeoNameID : Integer;
    LIsAnonymousProxy    : Integer;
    LIsSatelliteProvider : Integer;
    LPostalCode          : string;
    LLatitude            : Double;
    LLongitude           : Double;
    LAccuracyRadius      : Integer;
    LIpRange             : TArray<UInt32>;
begin
  LFields := aRow.Split([',']);

  if Length(LFields) < 10 then
    raise Exception.Create('Invalid row format');

  LNetwork             := LFields[0].Trim;
  LGeoNameID           := StrToIntDef(LFields[1].Trim,0);
  LRegCountryGeoNameID := StrToIntDef(LFields[2].Trim,0);
  LRepCountryGeoNameID := StrToIntDef(LFields[3].Trim,0);
  LIsAnonymousProxy    := StrToIntDef(LFields[4].Trim,0);
  LIsSatelliteProvider := StrToIntDef(LFields[5].Trim,0);
  LPostalCode          := LFields[6].Trim;
  LLatitude            := StrToFloatDef(LFields[7].Trim,0,FFormatSettings);
  LLongitude           := StrToFloatDef(LFields[8].Trim,0,FFormatSettings);
  LAccuracyRadius      := StrToIntDef(LFields[9].Trim,0);
  LIpRange             := GetSubnetBounds(LNetwork);

  if not FFDInsertQuery.Prepared then
  begin
    FFDInsertQuery.ParamByName('pGeoNameID').DataType           := ftInteger;
    FFDInsertQuery.ParamByName('pRegCountryGeoNameID').DataType := ftInteger;
    FFDInsertQuery.ParamByName('pRepCountryGeoNameID').DataType := ftInteger;
    FFDInsertQuery.ParamByName('pIsAnonymousProxy').DataType    := ftInteger;
    FFDInsertQuery.ParamByName('pIsSatelliteProvider').DataType := ftInteger;
    FFDInsertQuery.ParamByName('pPostalCode').DataType          := ftString;
    FFDInsertQuery.ParamByName('pLatitude').DataType            := ftFloat;
    FFDInsertQuery.ParamByName('pLongitude').DataType           := ftFloat;
    FFDInsertQuery.ParamByName('pAccuracyRadius').DataType      := ftInteger;
    FFDInsertQuery.ParamByName('pIPStart').DataType             := ftInteger;
    FFDInsertQuery.ParamByName('pIPEnd').DataType               := ftInteger;
    FFDInsertQuery.Prepare;
  end;

  Try
    FFDInsertQuery.ParamByName('pGeoNameID').AsInteger           := LGeoNameID;
    FFDInsertQuery.ParamByName('pRegCountryGeoNameID').AsInteger := LRegCountryGeoNameID;
    FFDInsertQuery.ParamByName('pRepCountryGeoNameID').AsInteger := LRepCountryGeoNameID;
    FFDInsertQuery.ParamByName('pIsAnonymousProxy').AsInteger    := LIsAnonymousProxy;
    FFDInsertQuery.ParamByName('pIsSatelliteProvider').AsInteger := LIsSatelliteProvider;
    FFDInsertQuery.ParamByName('pPostalCode').AsString           := LPostalCode;
    FFDInsertQuery.ParamByName('pLatitude').AsFloat              := LLatitude;
    FFDInsertQuery.ParamByName('pLongitude').AsFloat             := LLongitude;
    FFDInsertQuery.ParamByName('pAccuracyRadius').AsInteger      := LAccuracyRadius;
    FFDInsertQuery.ParamByName('pIPStart').AsInteger             := LIpRange[0];
    FFDInsertQuery.ParamByName('pIPEnd').AsInteger               := LIpRange[1];
    FFDInsertQuery.ExecSQL;
  finally
    SetLength(LIpRange, 0);
  end;
end;

function TImportThreadGeoLite.GetSubnetBounds(const AIPAddress: string): TArray<UInt32>;
var LIPAddress         : UInt32; 
    LSubnetMask        : UInt32; 
    LNetworkAddress    : UInt32; 
    LBroadcastAddress  : UInt32; 
    LFirstIPAddress    : UInt32; 
    LLastIPAddress     : UInt32;
    LCIDR              : Integer;
begin
  // Parse IP address and CIDR subnet
  LIPAddress := IPv4ToUInt32(AIPAddress.Split(['/'])[0]);
  LCIDR      := StrToInt(AIPAddress.Split(['/'])[1]);

  // Calculate subnet mask and network/broadcast addresses
  LSubnetMask       := CIDRToSubnetMask(LCIDR);
  LNetworkAddress   := LIPAddress and LSubnetMask;
  LBroadcastAddress := LNetworkAddress or (not LSubnetMask);

  // Calculate first and last IP addresses
  LFirstIPAddress   := LNetworkAddress + 1;
  LLastIPAddress    := LBroadcastAddress - 1;

  SetLength(Result, 2);
  Result[0] := LFirstIPAddress;
  Result[1] := LLastIPAddress;
end;

function TImportThreadGeoLite.CIDRToSubnetMask(const ACIDR: Integer): UInt32;
begin
  Result := not ((1 shl (32 - ACIDR)) - 1);
end;


function TImportThreadGeoLite.GetSubnetBoundsIPv6(const AIPAddress: string): TArray<UInt64>;
var 
  LParts     : TArray<string>;
  LAddress   : TIdIPv6Address;
  LCIDR      : Integer;
  LFirstPart : UInt64;
  LSecondPart: UInt64;
  I          : Integer;
begin
  LParts := AIPAddress.Split(['/']);
  if Length(LParts) <> 2 then
    raise Exception.Create('Invalid IPv6 address with CIDR format');
  if not IsValidIP(LParts[0]) then
    raise Exception.Create('Invalid IPv6 address');

  // Convert IP address from string to TIdIPv6Address
  IPv6ToIdIPv6Address(LParts[0], LAddress);
  LCIDR := StrToInt(LParts[1]);

  // Calculate the IP start and IP end
  LFirstPart  := 0;
  LSecondPart := 0;
  for I := 0 to 7 do
  begin
    if I < 4 then
      LFirstPart  := (LFirstPart shl 16) or Swap(LAddress[I])
    else
      LSecondPart := (LSecondPart shl 16) or Swap(LAddress[I]);
  end;

  Result    := [LFirstPart, LSecondPart];
  Result[0] := Result[0] shl (128 - LCIDR);
  Result[1] := Result[1] or ((UInt64(1) shl (128 - LCIDR)) - 1);
end;



procedure TImportThreadGeoLite.ParseASNBlocksRowIPv6(const aRow: string);
var LFields        : TArray<string>;
    LNetwork       : string;
    LASNumber      : String;
    LASOrganization: string;
    LIpRange       : TArray<UInt64>;
begin                        
  LFields := aRow.Split([',']);
  if Length(LFields) < 3 then
    raise Exception.Create('Invalid row format');

  LNetwork        := LFields[0].Trim;
  LASNumber       := LFields[1].Trim;
  LASOrganization := LFields[2].Trim;
  LIpRange        := GetSubnetBoundsIPv6(LNetwork);
  
  if not FFDInsertQuery.Prepared then
  begin
    FFDInsertQuery.ParamByName('pASN').DataType           := ftString;
    FFDInsertQuery.ParamByName('pOrganizzation').DataType := ftString;
    FFDInsertQuery.ParamByName('pIPStart').DataType       := ftLargeint;
    FFDInsertQuery.ParamByName('pIPEnd').DataType         := ftLargeint;
    FFDInsertQuery.Prepare
  end;
  
  Try  
    FFDInsertQuery.ParamByName('pASN').AsString           := LASNumber;
    FFDInsertQuery.ParamByName('pOrganizzation').AsString := LASOrganization;
    FFDInsertQuery.ParamByName('pIPStart').AsLargeInt     := LIpRange[0];  
    FFDInsertQuery.ParamByName('pIPEnd').AsLargeInt       := LIpRange[1];
    FFDInsertQuery.ExecSQL; 
  finally
    SetLength(LIpRange,0);
  end;
end;


procedure TImportThreadGeoLite.ParseASNBlocksRow(const aRow: string);
var LFields        : TArray<string>;
    LNetwork       : string;
    LASNumber      : String;
    LASOrganization: string;
    LIpRange       : TArray<UInt32>;
begin                        
  LFields := aRow.Split([',']);
  if Length(LFields) < 3 then
    raise Exception.Create('Invalid row format');

  LNetwork        := LFields[0].Trim;
  LASNumber       := LFields[1].Trim;
  LASOrganization := LFields[2].Trim;
  LIpRange        := GetSubnetBounds(LNetwork);
  
  if not FFDInsertQuery.Prepared then
  begin
    FFDInsertQuery.ParamByName('pASN').DataType           := ftString;
    FFDInsertQuery.ParamByName('pOrganizzation').DataType := ftString;
    FFDInsertQuery.ParamByName('pIPStart').DataType       := ftInteger;
    FFDInsertQuery.ParamByName('pIPEnd').DataType         := ftInteger;
    FFDInsertQuery.Prepare
  end;
  
  Try  
    FFDInsertQuery.ParamByName('pASN').AsString           := LASNumber;
    FFDInsertQuery.ParamByName('pOrganizzation').AsString := LASOrganization;
    FFDInsertQuery.ParamByName('pIPStart').AsInteger      := LIpRange[0];  
    FFDInsertQuery.ParamByName('pIPEnd').AsInteger        := LIpRange[1];
    FFDInsertQuery.ExecSQL; 
  finally
    SetLength(LIpRange,0);
  end;
end;

destructor TImportThreadGeoLite.Destroy;
begin
  FreeAndNil(FConnection);
  FreeAndNil(FFDInsertQuery);
  
  inherited;
end;


end.
