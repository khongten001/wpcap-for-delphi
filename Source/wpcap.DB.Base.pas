unit wpcap.DB.Base;

interface

uses
  FireDAC.Stan.ExprFuncs, FireDAC.Phys.SQLiteWrapper.Stat,wpcap.StrUtils,
  FireDAC.Phys.SQLiteDef, FireDAC.Stan.Intf, FireDAC.Stan.Option, System.Classes,
  FireDAC.Stan.Error, FireDAC.UI.Intf, FireDAC.Phys.Intf, FireDAC.Stan.Def,
  FireDAC.Stan.Pool, FireDAC.Stan.Async, FireDAC.Phys, FireDAC.VCLUI.Wait,wpcap.Level.IP,
  FireDAC.Stan.Param, FireDAC.DatS, FireDAC.DApt.Intf, FireDAC.DApt,wpcap.Types,
  FireDAC.Comp.Script, FireDAC.Comp.Client, Data.DB, FireDAC.Comp.DataSet,wpcap.Level.Eth,
  FireDAC.Phys.SQLite,System.SysUtils,wpcap.Packet,Math,System.Generics.Collections;

Type
  TWPcapDBBase = Class(TObject)
  strict private
    var FConnection       : TFDConnection; 
    var FFDQueryTmp       : TFdQuery; 
    var FFDQueryGrid      : TFdQuery; 
    var FFDGetPacketData  : TFdQuery;  
    var FFilenameDB       : String;
  private
    procedure DoOnErrorCreateDatabase(ASender, AInitiator: TObject;
      var AException: Exception);
  protected
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
    function OpenDatabase(const aFilename:String):Boolean;overload;
    function OpenDatabase(const aFilename,aUserName,aPassword,aTNS:String):Boolean;overload;virtual;
    
    procedure CreateDatabase(const aFilename:String);overload;    
    procedure CreateDatabase(const aFilename,aUserName,aPassword,aTNS: String);overload;
    ///<summary>
    /// Inserts a network packet into the database.
    ///</summary>
    ///<param name="aInternalPacket">
    /// A pointer to internal packet structure.
    ///</param>
    ///<remarks>
    /// This function inserts a network packet into the database. 
    /// The packet data is provided as a pointer and its length is specified.
    /// The date and time the packet was captured is also specified, 
    /// as well as various protocol information such as the Ethernet type, MAC addresses, link-layer and IP protocol, and source and destination IP and port information. 
    /// The function raises an EDatabaseError exception if an error occurs while inserting the packet.
    ///</remarks>
    ///<exception cref="EDatabaseError">
    /// An EDatabaseError exception is raised if an error occurs while inserting the packet.
    ///</exception>
    procedure InsertPacket(const aInternalPacket : PTInternalPacket);
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

    /// <summary>
    /// Retrieves the packet data from the database at the specified packet number.
    /// </summary>
    /// <param name="aNPacket">The packet number to retrieve the data for.</param>
    /// <param name="aPacketSize">The size of the packet data.</param>
    /// <returns>A pointer to the packet data in memory.</returns>    
    function GetPacketDataFromDatabase(aNPacket: Integer;var aPacketSize:Integer): PByte;
    
    /// <summary>
    /// Returns a list of string containing the hexadecimal dump of a packet data with
    /// line by line formatting.
    /// </summary>
    /// <param name="aNPacket">The number of packet to display (starting from 0)</param>
    /// <returns>A list of string containing the hexadecimal dump of the packet data</returns>
    function GetListHexPacket(aNPacket: Integer;var aListDetail:TList<THeaderString>): TArray<String>;        
   
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
  FreeAndNil(FFDGetPacketData);
  FreeAndNil(FFDQueryGrid);    
  FreeAndNil(FConnection); 
  DestroyFDDriverLink; 
  inherited;
end;

procedure TWPcapDBBase.InitConnection;
CONST SQL_INSERT = 'INSERT INTO PACKETS (PACKET_LEN, PACKET_DATE, ETH_TYPE, ETH_ACRONYM, MAC_SRC, MAC_DST, IPPROTO, PROTOCOL, IP_SRC, IP_DST, PORT_SRC, PORT_DST, PACKET_DATA,PROTO_DETECT,IANA_PROTO,IS_IPV6) '+slineBreak+
                    'VALUES(:pLen,:pDate,:pEthType,:pEthAcr,:pMacSrc,:pMacDst,:pIpProto,:pProto,:pIpSrc,:pIpDst,:pPortSrc,:pPortDst,:pPacket,:pProtoDetect,:pProtoIANA,:pIsIPV6)';
begin
  FConnection                           := TFDConnection.Create( nil );
  FConnection.Params.Values['DriverID'] := GetDriverIDName;
  
  FFDQueryTmp                           := TFDQuery.Create(nil);
  FFDQueryTmp.Connection                := FConnection;
  FFDQueryTmp.SQL.Text                  := SQL_INSERT;   

  FFDQueryGrid                          := TFDQuery.Create(nil);
  FFDQueryGrid.Connection               := FConnection;
  FFDQueryGrid.SQL.Text                 := 'SELECT * FROM VST_PACKETS ORDER BY NPACKET ';
                                           
  FFDGetPacketData                      := TFDQuery.Create(nil);
  FFDGetPacketData.Connection           := FConnection;
  FFDGetPacketData.SQL.Text             := 'SELECT PACKET_DATA FROM PACKETS WHERE NPACKET = :pNPACKET ';                                              
end;

function TWPcapDBBase.OpenDatabase(const aFilename: String): Boolean;
begin
   OpenDatabase(aFilename,String.Empty,String.Empty,String.Empty);
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
    I        : Integer;
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
end;

procedure TWPcapDBBase.CreateDatabase(const aFilename: String);
begin
   CreateDatabase(aFilename,String.Empty,String.Empty,String.Empty)
end;

procedure TWPcapDBBase.InsertPacket(const aInternalPacket : PTInternalPacket);
var LMemoryStream : TMemoryStream;
begin   
  FFDQueryTmp.ParamByName('pLen').AsInteger         := aInternalPacket.PacketSize;
  FFDQueryTmp.ParamByName('pDate').AsString         := DateTimeToStr(aInternalPacket.PacketDate);
  FFDQueryTmp.ParamByName('pEthType').AsInteger     := aInternalPacket.Eth.EtherType;
  FFDQueryTmp.ParamByName('pEthAcr').AsString       := aInternalPacket.Eth.Acronym.Trim;
  FFDQueryTmp.ParamByName('pMacSrc').AsString       := aInternalPacket.Eth.SrcAddr;
  FFDQueryTmp.ParamByName('pMacDst').AsString       := aInternalPacket.Eth.DestAddr;
  FFDQueryTmp.ParamByName('pIpProto').AsInteger     := aInternalPacket.IP.IpProto;
  FFDQueryTmp.ParamByName('pPortSrc').AsInteger     := aInternalPacket.IP.PortSrc;  
  FFDQueryTmp.ParamByName('pPortDst').AsInteger     := aInternalPacket.IP.PortDst;  
  FFDQueryTmp.ParamByName('pIsIPV6').AsInteger      := ifthen(aInternalPacket.IP.IsIPv6,1,0);  
  FFDQueryTmp.ParamByName('pProtoDetect').AsInteger := aInternalPacket.IP.DetectedIPProto;    
  FFDQueryTmp.ParamByName('pProtoIANA').AsString    := aInternalPacket.IP.IANAProtoStr;  
  FFDQueryTmp.ParamByName('pPacket').DataType       := ftBlob;
    
  FFDQueryTmp.ParamByName('pProto').DataType        := ftString;
  FFDQueryTmp.ParamByName('pIpSrc').DataType        := ftString;
  FFDQueryTmp.ParamByName('pIpDst').DataType        := ftString;  

  if aInternalPacket.IP.IpProtoAcronym.Trim.IsEmpty then
    FFDQueryTmp.ParamByName('pProto').Clear
  else
    FFDQueryTmp.ParamByName('pProto').AsString := aInternalPacket.IP.IpProtoAcronym;
    
  if aInternalPacket.IP.Src.Trim.IsEmpty then
    FFDQueryTmp.ParamByName('pIpSrc').Clear
  else
    FFDQueryTmp.ParamByName('pIpSrc').AsString := aInternalPacket.IP.Src;  

  if aInternalPacket.IP.Dst.Trim.IsEmpty then
    FFDQueryTmp.ParamByName('pIpDst').Clear
  else
    FFDQueryTmp.ParamByName('pIpDst').AsString := aInternalPacket.IP.Dst;
    
  LMemoryStream := TMemoryStream.Create; 
  Try
    LMemoryStream.WriteBuffer(aInternalPacket.PacketData^,aInternalPacket.PacketSize);

    FFDQueryTmp.ParamByName('pPacket').LoadFromStream(LMemoryStream,ftBlob);
    FFDQueryTmp.ExecSQL;
  Finally
    FreeAndNil(LMemoryStream);
  End;  
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

Function TWPcapDBBase.GetPacketDataFromDatabase(aNPacket:Integer;var aPacketSize:Integer):PByte;
var LStream    : TMemoryStream;
begin
  Result      := nil;
  aPacketSize := 0;
  FFDGetPacketData.Close;
  FFDGetPacketData.ParamByName('pNPACKET').AsInteger :=aNPacket; 
  FFDGetPacketData.Open;

  if not FFDGetPacketData.IsEmpty then
  begin
    LStream := TMemoryStream.Create;
    try  
      TBlobField(FFDGetPacketData.Fields[0]).SaveToStream(LStream);
      aPacketSize := LStream.Size;
      GetMem(Result, aPacketSize);
      LStream.Seek(0, soBeginning);
      LStream.ReadBuffer(Result^, aPacketSize);
    finally
      LStream.Free;
    end;    
  end;
  FFDGetPacketData.Close;  
end;

Function TWPcapDBBase.GetListHexPacket(aNPacket:Integer;var aListDetail:TList<THeaderString>):TArray<String>;
var LPacket     : PByte;
    LPacketSize : Integer;
begin
  SetLength(Result,0);

  LPacket := GetPacketDataFromDatabase(aNPacket,LPacketSize);
  if Assigned(LPacket) then
  begin
    Result      := DisplayHexData(LPacket,LPacketSize);
    aListDetail := TWpcapEthHeader.HeaderToString(LPacket,LPacketSize);
    if TWpcapIPHeader.HeaderToString(LPacket,LPacketSize,aListDetail) then
    begin
      //Todo UDP e TCP
    end;
  end;
end;


end.
