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

    procedure InsertVersion;virtual;     
  
    procedure CreateFDDriverLink;override;
    procedure InsertMetadata(const aName: String; aValue: String);override;       
    function GetDriverIDName:String;override;
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

procedure TWPcapDBSqLite.DestroyFDDriverLink;
begin
  FreeAndNIl(FDriverLink);
end;

procedure TWPcapDBSqLite.SetCredentialConnection(const aUsername,aPassword: String);
begin
  //
end;

procedure TWPcapDBSqLite.SetTNSConnection(const aTNS: String);
begin
  //

end;

procedure TWPcapDBSqLite.InsertVersion;
begin

end;

procedure TWPcapDBSqLite.InsertMetadata(const aName: String; aValue: String);
begin
  
end;

end.
