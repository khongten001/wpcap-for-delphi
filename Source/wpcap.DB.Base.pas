
unit wpcap.DB.Base;
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

interface                        

uses
  FireDAC.Stan.ExprFuncs, FireDAC.Phys.SQLiteWrapper.Stat,
  FireDAC.Phys.SQLiteDef, Winapi.Windows, FireDAC.Stan.Intf, FireDAC.Stan.Option,
  System.Classes, FireDAC.Stan.Error, FireDAC.UI.Intf, FireDAC.Phys.Intf,
  FireDAC.Stan.Def, FireDAC.Stan.Pool, FireDAC.Stan.Async, FireDAC.Phys,
  FireDAC.VCLUI.Wait, FireDAC.Stan.Param, FireDAC.DatS, FireDAC.DApt.Intf,
  FireDAC.DApt, FireDAC.Comp.Script, FireDAC.Comp.Client, Data.DB,
  FireDAC.Comp.DataSet, FireDAC.Phys.SQLite, System.SysUtils;

Type
  TWPcapDBBase = Class(TObject)
  strict private
    CONST METADATA_VERSION_LABEL = 'Version';
  private
    procedure DoOnErrorCreateDatabase(ASender, AInitiator: TObject;var AException: Exception);

    ///<summary>
    ///   Insert metadata import datetime
    ///</summary>
    procedure InsertDate;
    
    ///<summary>
    ///   Insert filename PCAP
    ///</summary>
    procedure InsertFilename(const aFilename:String); 
    
    ///<summary>
    ///   Insert metadata version
    ///</summary>
    procedure InsertVersion;
  protected
    var FConnection       : TFDConnection; 
    var FFDQueryTmp       : TFdQuery; 
    var FFDQueryGrid      : TFdQuery;
    var FFDGetDataByID    : TFdQuery;  
    var FFilenameDB       : String;
    function GetMetadataCOLUMN_NAME_NAME: String;
    function GetMetadataCOLUMN_NAME_VALUE: String;     
    function GetMetadataTableName:String;
    ///<summary>
    /// Creates a new FireDAC database connection object.
    ///</summary>
    ///<remarks>
    /// This procedure creates a new FireDAC database connection object, which is used to connect to a database. 
    /// The created object is stored in the private field FConnection of the class, and is not connected to any database by default. 
    /// The connection object is automatically freed when the containing object is destroyed.
    ///</remarks>
    procedure InitConnection;virtual;  
    
    ///<summary>
    ///Returns the name of the Firedac driver ID.
    ///</summary>
    /// <returns>A string containing the name of the Firedac driver ID.</returns>
    function GetDriverIDName: string; virtual;
    
    /// <summary>
    /// Sets the username and password for the database connection.
    /// </summary>
    /// <param name="aUsername">The username to set.</param>
    /// <param name="aPassword">The password to set.</param>
    /// <remarks>
    /// This metho should be called before the Connect method to set the credentials.
    /// </remarks>
    procedure SetCredentialConnection(const aUsername,aPassword:String); virtual;    

    /// <summary>
    /// Sets the TNS connection string for the current database connection.
    /// </summary>
    /// <param name="aTNS">The TNS connection string to set.</param>
    /// <remarks>
    /// This procedure sets the TNS connection string for the current database connection. The TNS connection
    /// string is used to connect to an Oracle database. The TNS connection string should be in the format
    /// '(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=hostname)(PORT=port)))(CONNECT_DATA=(SERVICE_NAME=servicename)))'.
    /// </remarks>   
    procedure SetTNSConnection(const aTNS:String); virtual; 
    
    ///<summary>
    /// Returns an string representing the SQL script for creating the database schema.
    ///</summary>
    ///<returns>An string representing the SQL script for creating the database schema.</returns>
    function GetSQLScriptDatabaseSchema: string; virtual;
    
    /// <summary>
    ///   Creates the Firedac driver link for the database component, if not already created
    /// </summary>
    /// <remarks>
    ///   This procedure creates a new instance of the Firedac driver link if it does not already exist, then sets its
    ///   VendorLib and DriverID properties based on the current system configuration, and finally assigns the created
    ///   driver link to the database component's DriverLink property.
    /// </remarks>
    /// <seealso cref="TDatabase" />
    /// <seealso cref="TFDPhysFBDriverLink" />
    /// <seealso cref="TFDPhysIBDriverLink" />
    /// <seealso cref="TFDPhysMSSQLDriverLink" />
    /// <seealso cref="TFDPhysMySQLDriverLink" />
    /// <seealso cref="TFDPhysODBCDriverLink" />
    /// <seealso cref="TFDPhysPgDriverLink" />
    /// <seealso cref="TFDPhysSQLiteDriverLink" />
    procedure CreateFDDriverLink; virtual;
    
    ///<summary>
    ///   Destroys the Firedac driver link.
    ///</summary>
    ///<remarks>
    ///   This method will destroy the Firedac driver link, which can be created by calling the CreateFDDriverLink method.
    ///</remarks>
    procedure DestroyFDDriverLink; virtual;   

    ///<summary>
    ///   Return version of database schema
    ///</summary>
    function GetVersion: String; virtual;

    ///<summary>
    ///   Insert metadata name and value
    ///</summary>
    procedure InsertMetadata(const aName: String; aValue: String);virtual;    
   public
    constructor Create;reintroduce;      
    destructor Destroy;override;   
    
    
    ///<summary>
    /// Opens a connection to a SQLite database file.
    ///</summary>
    ///<param name="aFilename">
    /// The filename of the database file to open.
    ///</param>
    ///<returns>
    /// A boolean value indicating whether the connection was successfully opened.
    ///</returns>
    ///<remarks>
    ///</remarks>
    ///<exception cref="EDatabaseError">
    /// An EDatabaseError exception is raised if there are any errors during connection.
    ///</exception>    
    function OpenDatabase(const aFilename:String):Boolean;overload;virtual;
    function OpenDatabase(const aFilename,aUserName,aPassword,aTNS:String):Boolean;overload;virtual;
    
    procedure CreateDatabase(const aFilename:String);overload;    
    procedure CreateDatabase(const aFilename,aUserName,aPassword,aTNS: String);overload;

    ///<summary>
    /// Rolls back any pending transactions and closes the connection to the SQLite database.
    ///</summary>
    ///<param name="aDelete">
    /// A boolean value indicating whether to delete the database file
    ///</param>
    ///<remarks>
    /// This function performs a rollback of any pending transactions on the SQLite database, and then closes the connection. 
    /// If the aDelete parameter is true,  database file is deleted. 
    /// If there are any errors during the rollback or deletion, it raises an EDatabaseError exception. 
    /// After the connection is closed, all components connected to the database will be disconnected.
    ///</remarks>
    ///<exception cref="EDatabaseError">
    /// An EDatabaseError exception is raised if there are any errors during the rollback or deletion.
    ///</exception>
    procedure RollbackAndClose(aDelete:Boolean);

    ///<summary>
    /// Commits pending transactions and closes the connection to the SQLite database.
    ///</summary>
    ///<remarks>
    /// This function performs a commit of any pending transactions on the SQLite database, and then closes the connection. 
    /// If there are any errors during the commit, it raises an EDatabaseError exception. After the connection is closed, 
    /// all components connected to the database will be disconnected.
    ///</remarks>
    ///<exception cref="EDatabaseError">
    /// An EDatabaseError exception is raised if there are any errors during the commit.
    ///</exception>    
    procedure CommitAndClose;  
    function IsVersion(const aVersion:Byte):Boolean;
    
    property Connection  : TFDConnection read FConnection  write FConnection;  

    /// <summary>
    ///   Gets or sets the FireDAC query object used to populate a grid.
    /// </summary>
    /// <remarks>
    ///   This query object is used to populate a grid with data retrieved from a database.
    /// </remarks>    
    property FDQueryGrid : TFDQuery      read FFDQueryGrid write FFDQueryGrid;     
  End;

implementation
  
{ TWPcapDBBase }

constructor TWPcapDBBase.Create;
begin
  InitConnection;
end;

destructor TWPcapDBBase.Destroy;
begin
  FConnection.Connected := False;
  FreeAndNil(FFDQueryTmp);
  FreeAndNil(FFDGetDataByID);
  FreeAndNil(FFDQueryGrid);    
  FreeAndNil(FConnection); 
  DestroyFDDriverLink; 
  inherited;
end;

procedure TWPcapDBBase.InitConnection;

begin
  FConnection                           := TFDConnection.Create( nil );
  FConnection.Params.Values['DriverID'] := GetDriverIDName;
  
  FFDQueryTmp                           := TFDQuery.Create(nil);
  FFDQueryTmp.Connection                := FConnection;

  FFDQueryGrid                          := TFDQuery.Create(nil);
  FFDQueryGrid.Connection               := FConnection;
                                           
  FFDGetDataByID                        := TFDQuery.Create(nil);
  FFDGetDataByID.Connection             := FConnection;
end;

function TWPcapDBBase.OpenDatabase(const aFilename: String): Boolean;
begin
   Result := OpenDatabase(aFilename,String.Empty,String.Empty,String.Empty);
end;

function TWPcapDBBase.OpenDatabase(const aFilename,aUserName,aPassword,aTNS: String): Boolean;
begin
  Result      := FConnection.Connected;
  FFilenameDB := aFilename;
  if not Result then
    FConnection.Params.Values['Database'] := aFilename
  else
  begin
    if FConnection.Params.Values['Database'] <> aFilename then
    begin
      FConnection.Connected                 := False;
      FConnection.Params.Values['Database'] := aFilename
    end;
  end;
  SetCredentialConnection(aUserName,aPassword);
  SetTNSConnection(aTNS);  
  FConnection.Connected := True;  
  Result                := FConnection.Connected;
end;

procedure TWPcapDBBase.DoOnErrorCreateDatabase(ASender, AInitiator: TObject;var AException: Exception);
begin
  raise Exception.CreateFmt('Unable create database %s',[AException.Message]);
end;

procedure TWPcapDBBase.CreateDatabase(const aFilename, aUserName,aPassword,aTNS: String);
var LTable   : TFdScript;
begin
  if not OpenDatabase(aFilename,aUserName,aPassword,aTNS) then 
    raise Exception.CreateFmt('Unable connect to database %s',[aFilename]);

  {Create schema}      
  LTable := TFdScript.Create( nil );                                
  Try
    LTable.Connection                 := FConnection;
    LTable.OnError                    := DoOnErrorCreateDatabase;
    LTable.ScriptOptions.BreakOnError := True;
    LTable.SQLScripts.Add.SQL.Add(GetSQLScriptDatabaseSchema);
    LTable.ValidateAll;
    LTable.ExecuteAll;
  Finally
    FreeAndNil(LTable);
  End;  

  InsertVersion;
  InsertDate;
  InsertFilename(aFilename);
end;

procedure TWPcapDBBase.CreateDatabase(const aFilename: String);
begin
   CreateDatabase(aFilename,String.Empty,String.Empty,String.Empty)
end;


procedure TWPcapDBBase.CommitAndClose;
begin
  FConnection.Commit;
  FConnection.Connected := False;
end;

procedure TWPcapDBBase.RollbackAndClose(aDelete:Boolean);
begin
  if FConnection.InTransaction then
    FConnection.Rollback;
  FConnection.Connected := False;
  if FileExists(FFilenameDB) then
    DeleteFile(FFilenameDB);
end;


procedure TWPcapDBBase.InsertDate;
begin
  InsertMetadata('Import date:',DateTimeToStr(now));
end;

procedure TWPcapDBBase.InsertFilename(const aFilename: String);
begin
  InsertMetadata('Filename',aFilename);
end;

procedure TWPcapDBBase.InsertVersion;
begin
  InsertMetadata(METADATA_VERSION_LABEL,GetVersion);
end;

function TWPcapDBBase.GetVersion: String;
begin
   Result := '2';
end;

function TWPcapDBBase.GetMetadataTableName: String;
begin
  Result := 'METADATA';
end;

function TWPcapDBBase.GetMetadataCOLUMN_NAME_NAME: String;
begin
  Result := 'NAME';
end;

function TWPcapDBBase.GetMetadataCOLUMN_NAME_VALUE: String;
begin
  Result := 'VALUE';
end;

function TWPcapDBBase.IsVersion(const aVersion: Byte): Boolean;
var LFDGetVersion : TFDQuery;
begin
  Result        := False;
  LFDGetVersion := TFDQuery.Create(nil);
  Try
    LFDGetVersion.Connection                    := FConnection;  
    LFDGetVersion.SQL.Text                      := Format('SELECT %S FROM %s WHERE %s = :pName',[GetMetadataCOLUMN_NAME_VALUE,GetMetadataTableName,GetMetadataCOLUMN_NAME_NAME]);  
    LFDGetVersion.ParamByName('pName').AsString := METADATA_VERSION_LABEL; 
    LFDGetVersion.Open();

    if not LFDGetVersion.IsEmpty then
    begin
      Result := LFDGetVersion.FieldByName(GetMetadataCOLUMN_NAME_VALUE).AsInteger = aVersion;
    end;
  Finally
    FreeAndNil(LFDGetVersion);
  End;
end;

Procedure TWPcapDBBase.InsertMetadata(const aName:String;aValue:String);
begin
   raise Exception.Create('TWPcapDBBase.InsertMetadata - Non implemented in base class - please override this method');
end;

function TWPcapDBBase.GetSQLScriptDatabaseSchema: String;
begin
   raise Exception.Create('TWPcapDBBase.GetSQLScriptDatabaseSchema- Non implemented in base class - please override this method');
end;

function TWPcapDBBase.GetDriverIDName: String;
begin
   raise Exception.Create('TWPcapDBBase.GetDriverIDName- Non implemented in base class - please override this method');
end;

procedure TWPcapDBBase.CreateFDDriverLink;
begin
   raise Exception.Create('TWPcapDBBase.CreateFDDriverLink- Non implemented in base class - please override this method');
end;

procedure TWPcapDBBase.DestroyFDDriverLink;
begin
   raise Exception.Create('TWPcapDBBase.DestroyFDDriverLink- Non implemented in base class - please override this method');
end;

procedure TWPcapDBBase.SetCredentialConnection(const aUsername, aPassword: String);
begin
  raise Exception.Create('TWPcapDBBase.SetCredentialConnection- Non implemented in base class - please override this method');
end;

procedure TWPcapDBBase.SetTNSConnection(const aTNS: String);
begin
  raise Exception.Create('TWPcapDBBase.SetTNSConnection- Non implemented in base class - please override this method');
end;


end.
