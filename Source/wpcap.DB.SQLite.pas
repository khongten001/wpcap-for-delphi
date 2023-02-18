unit wpcap.DB.SQLite;

interface

uses
  wpcap.DB.Base, System.Classes, FireDAC.Phys, FireDAC.Phys.SQLite,
  System.SysUtils;

type
  /// <summary>
  /// The TWPcapDBSqLite class extends the TWPcapDBBase class and implements a database
  /// connection to SQLite. It provides methods to open and close the connection,
  /// and to execute SQL queries and commands. This class is used to write and read
  /// data from SQLite database files that store packets captured using
  /// the WinPcap library.
  /// </summary>
  TWPcapDBSqLite = Class(TWPcapDBBase)
  Strict private
    var FDriverLink : TFDPhysSQLiteDriverLink;    
  protected
    procedure CreateFDDriverLink;override;
    function GetDriverIDName:String;override;
    function GetSQLScriptDatabaseSchema:String;override;  
    procedure DestroyFDDriverLink;override;  
    procedure SetCredentialConnection(const aUsername,aPassword:String); override;    
    procedure SetTNSConnection(const aTNS:String); override;       
  End;

implementation

{ TDBSqLite }
procedure TWPcapDBSqLite.CreateFDDriverLink;
begin
  FDriverLink := TFDPhysSQLiteDriverLink.Create( nil );
end;

function TWPcapDBSqLite.GetDriverIDName: String;
begin
  Result := 'SQLite';
end;

function TWPcapDBSqLite.GetSQLScriptDatabaseSchema: String;
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
                      '  PROTO_DETECT INTEGER,                                        '+sLineBreak+                                            
                      '  PACKET_DATA BLOB                                             '+sLineBreak+
                      ');                                                             ';
                      
           SQL_INDEX = 'CREATE UNIQUE INDEX PACKETS_NPACKET_IDX ON PACKETS (NPACKET);  ';

           SQL_VIEW  = 'CREATE VIEW VST_PACKETS AS SELECT NPACKET, PACKET_LEN, PACKET_DATE, ETH_TYPE, ETH_ACRONYM,MAC_SRC, MAC_DST,' +sLineBreak+
                      ' PROTO_DETECT,IPPROTO, IFNULL(PROTOCOL,ETH_ACRONYM) AS PROTOCOL, IFNULL(IP_SRC,MAC_SRC) AS IP_SRC, IFNULL(IP_DST,MAC_DST) AS IP_DST, PORT_SRC,PORT_DST FROM PACKETS;';
{$ENDREGION}
begin

  Result := SQL_TABLE +sLineBreak+
            SQL_INDEX +sLineBreak+
            SQL_VIEW;
end;

procedure TWPcapDBSqLite.DestroyFDDriverLink;
begin
  FreeAndNIl(FDriverLink);
end;

procedure TWPcapDBSqLite.SetCredentialConnection(const aUsername,
  aPassword: String);
begin
  //
end;

procedure TWPcapDBSqLite.SetTNSConnection(const aTNS: String);
begin
  //

end;

end.
