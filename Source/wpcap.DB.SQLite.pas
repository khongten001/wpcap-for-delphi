unit wpcap.DB.SQLite;

interface

uses
  FireDAC.Stan.ExprFuncs, FireDAC.Phys.SQLiteWrapper.Stat,
  FireDAC.Phys.SQLiteDef, FireDAC.Stan.Intf, FireDAC.Stan.Option, System.Classes,
  FireDAC.Stan.Error, FireDAC.UI.Intf, FireDAC.Phys.Intf, FireDAC.Stan.Def,
  FireDAC.Stan.Pool, FireDAC.Stan.Async, FireDAC.Phys, FireDAC.VCLUI.Wait,
  FireDAC.Stan.Param, FireDAC.DatS, FireDAC.DApt.Intf, FireDAC.DApt,
  FireDAC.Comp.Script, FireDAC.Comp.Client, Data.DB, FireDAC.Comp.DataSet,
  FireDAC.Phys.SQLite,System.SysUtils;
  
type
  TDBSqLite = Class(TObject)
  Strict private
    var FDriverLink : TFDPhysSQLiteDriverLink;
    var FConnection : TFDConnection;      
    var FQueryTmp   : TFdQuery; 
    var FFilenameDB : String;    
  private
    ///<summary>
    /// Creates a new FireDAC database connection object.
    ///</summary>
    ///<remarks>
    /// This procedure creates a new FireDAC database connection object, which is used to connect to a database. 
    /// The created object is stored in the private field FConnection of the class, and is not connected to any database by default. 
    /// The connection object is automatically freed when the containing object is destroyed.
    ///</remarks>
    procedure InitConnection;
  public
    constructor Create;reintroduce;
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
    function OpenDatabase(const aFilename:String):Boolean;
    
    procedure CreateDatabase(const aFilename:String);
    ///<summary>
    /// Inserts a network packet into the database.
    ///</summary>
    ///<param name="aPktData">
    /// A pointer to the packet data.
    ///</param>
    ///<param name="aPktLen">
    /// The length of the packet data.
    ///</param>
    ///<param name="aPktDate">
    /// The date and time the packet was captured.
    ///</param>
    ///<param name="aEthType">
    /// The Ethernet type of the packet.
    ///</param>
    ///<param name="atEthAcronym">
    /// The acronym for the Ethernet type of the packet.
    ///</param>
    ///<param name="aMacSrc">
    /// The source MAC address of the packet.
    ///</param>
    ///<param name="aMacDst">
    /// The destination MAC address of the packet.
    ///</param>
    ///<param name="LaPProto">
    /// The protocol of the packet at the link layer.
    ///</param>
    ///<param name="aIPProtoMapping">
    /// The mapping of the IP protocol of the packet.
    ///</param>
    ///<param name="aIpSrc">
    /// The source IP address of the packet.
    ///</param>
    ///<param name="aIpDst">
    /// The destination IP address of the packet.
    ///</param>
    ///<param name="aPortSrc">
    /// The source port of the packet.
    ///</param>
    ///<param name="aPortDst">
    /// The destination port of the packet.
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
    procedure InsertPacket(const aPktData: PByte; aPktLen: LongWord; aPktDate: TDateTime; aEthType: Word;
      const atEthAcronym, aMacSrc, aMacDst: String; LaPProto: Word;
      const aIPProtoMapping, aIpSrc, aIpDst: String; aPortSrc, aPortDst: Word);

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
  End;

implementation

{ TDBSqLite }


procedure TDBSqLite.CommitAndClose;

begin
  FConnection.Commit;
  FConnection.Connected := False;
end;

procedure TDBSqLite.RollbackAndClose(aDelete:Boolean);
begin
  if FConnection.InTransaction then
    FConnection.Rollback;
  FConnection.Connected := False;
  if FileExists(FFilenameDB) then
    DeleteFile(FFilenameDB);  
end;

procedure TDBSqLite.CreateDatabase(const aFilename: String);
{$REGION 'SQL Scrit'}
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
{$ENDREGION}
var LTable : TFdScript;

  Procedure AddScriptSQL(const aSQL : String);
  begin
     LTable.SQLScripts.Add.SQL.Add(aSQL)
  end;
  
begin

  if not OpenDatabase(aFilename) then 
    raise Exception.CreateFmt('Unable connect to database %s',[aFilename]);

  {Create schema}      
  LTable := TFdScript.Create( nil );                                
  Try
    LTable.Connection := FConnection;
    AddScriptSQL(SQL_TABLE);
    AddScriptSQL(SQL_INDEX);
    LTable.ValidateAll;
    LTable.ExecuteAll;
  Finally
    FreeAndNil(LTable);
  End;  
end;

procedure TDBSqLite.InitConnection;
CONST SQL_INSERT = 'INSERT INTO PACKETS (PACKET_LEN, PACKET_DATE, ETH_TYPE, ETH_ACRONYM, MAC_SRC, MAC_DST, IPPROTO, PROTOCOL, IP_SRC, IP_DST, PORT_SRC, PORT_DST, PACKET_DATA) '+slineBreak+
                    'VALUES(:pLen,:pDate,:pEthType,:pEthAcr,:pMacSrc,:pMacDst,:pIpProto,:pProto,:pIpSrc,:pIpDst,:pPortSrc,:pPortDst,:pPacket)';
begin
  FDriverLink                           := TFDPhysSQLiteDriverLink.Create( nil );
  FConnection                           := TFDConnection.Create( nil );  
  FConnection.Params.Values['DriverID'] := 'SQLite';  
  FQueryTmp                             := TFDQuery.Create(nil);
  FQueryTmp.Connection                  := FConnection;
  FQueryTmp.SQL.Text                    := SQL_INSERT;
end;

constructor TDBSqLite.Create;
begin
  InitConnection;
end;

function TDBSqLite.OpenDatabase(const aFilename: String): Boolean;
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
  FConnection.Connected := True;  
  Result                := FConnection.Connected
end;

procedure TDBSqLite.InsertPacket(const aPktData: PByte; aPktLen: LongWord;
  aPktDate: TDateTime; aEthType: Word; const atEthAcronym, aMacSrc,
  aMacDst: String; LaPProto: Word; const aIPProtoMapping, aIpSrc,
  aIpDst: String; aPortSrc, aPortDst: Word);
  var LMemoryStream : TMemoryStream;
begin   
  FQueryTmp.ParamByName('pLen').AsInteger     := aPktLen;
  FQueryTmp.ParamByName('pDate').AsString     := DateTimeToStr(aPktDate);
  FQueryTmp.ParamByName('pEthType').AsInteger := aEthType;
  FQueryTmp.ParamByName('pEthAcr').AsString   := atEthAcronym;
  FQueryTmp.ParamByName('pMacSrc').AsString   := aMacSrc;
  FQueryTmp.ParamByName('pMacDst').AsString   := aMacDst;
  FQueryTmp.ParamByName('pIpProto').AsInteger := LaPProto;
  FQueryTmp.ParamByName('pProto').AsString    := aIPProtoMapping;
  FQueryTmp.ParamByName('pIpSrc').AsString    := aIpSrc;  
  FQueryTmp.ParamByName('pIpDst').AsString    := aIpDst;
  FQueryTmp.ParamByName('pPortSrc').AsInteger := aPortSrc;  
  FQueryTmp.ParamByName('pPortDst').AsInteger := aPortDst;  
  FQueryTmp.ParamByName('pPacket').DataType   := ftOraBlob;
  LMemoryStream := TMemoryStream.Create; 
  Try
    LMemoryStream.Write(aPktData,aPktLen);
    FQueryTmp.ParamByName('pPacket').LoadFromStream(LMemoryStream,ftOraBlob);
    FQueryTmp.ExecSQL;
  Finally
    FreeAndNil(LMemoryStream);
  End;  
end;

end.
